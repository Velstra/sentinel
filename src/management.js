// Shared management lifecycle. Credentials and configuration drafts never enter
// URLs or persistent storage. Confirmation is an explicit operator action.
let pendingBatch = null, completedTransaction = null;
let pendingTransaction = null, confirmationDeadline = 0, managementTimer = null;
let telemetryAbort = null, liveFrame = null, liveStatus = "Connecting to telemetry…";
let flowPage = 0, frozenEvents = null, lastEventSequence = 0;
let tomlBaseline = "", tomlRevision = "", tomlBusy = false;

function setTransaction(pending) {
  pendingTransaction = pending || null;
  confirmationDeadline = pending ? performance.now() + Number(pending.remaining_seconds || 0) * 1000 : 0;
  drawConfirmation();
}
function drawConfirmation() {
  const pending = pendingTransaction;
  $("confirmation").classList.toggle("hidden", !pending);
  $("toml-apply").disabled = permission === "read-only" || !!target || tomlBusy || !!pending;
  if (!pending) return;
  const seconds = Math.max(0, Math.ceil((confirmationDeadline - performance.now()) / 1000));
  const message = pending.reverting ? "Rollback requested. The independent recovery service is restoring the previous working configuration." : !pending.ready ? "Applying configuration in the independent worker. The confirmation window starts when reconciliation completes." : seconds
    ? "Verify management access and forwarding, then keep this revision. Without confirmation the previous working configuration returns automatically."
    : "The confirmation window expired. Reconnecting to check recovery…";
  if ($("confirmation-message").textContent !== message) $("confirmation-message").textContent = message;
  $("confirmation-countdown").textContent = pending.ready ? seconds + " seconds until automatic rollback" : "Preparing the confirmation window…";
  $("confirm-change").disabled = permission === "read-only" || !!target || $("confirm-change").classList.contains("busy") || !pending.ready || seconds === 0;
  $("revert-change").disabled = permission === "read-only" || !!target || $("revert-change").classList.contains("busy");
}
function rememberPendingBatch(pending, changes) {
  if (pending) pendingBatch = { id: pending.id, changes: changes.map(s => ({ label: s.label, cmds: [...s.cmds] })) };
}
function completeTransaction(id, outcome) {
  if (completedTransaction === id) return;
  completedTransaction = id;
  const confirmed = outcome === "confirmed";
  const message = confirmed ? "Configuration confirmed and saved." : outcome === "apply-failed"
    ? "Application failed. The previous working configuration was restored; review the retained changes before retrying."
    : "Previous working configuration restored. Your proposed changes remain available for review.";
  if (pendingBatch?.id === id) {
    if (!confirmed) for (const change of pendingBatch.changes) {
      if (!staged.some(s => s.label === change.label)) stage(change.label, change.cmds);
    }
    pendingBatch = null;
  }
  if (confirmed && !dirty.has("toml-editor")) clearToml();
  else if (tomlRevision && $("toml-candidate").value !== tomlBaseline) {
    dirty.add("toml-editor");
    $("toml-feedback").textContent = message + " Reload the current baseline before applying again.";
  }
  if ($("result").dataset.transaction === id) {
    $("resulttitle").textContent = confirmed ? "Confirmed" : "Configuration restored";
    $("resultout").textContent = message;
  }
  banner(message, "note");
}
async function refreshTransaction() {
  if (!token) return;
  try {
    const previous = pendingTransaction;
    const status = await (await api("/api/v1/config/transaction")).json();
    const current = status.pending;
    setTransaction(current);
    const finished = previous?.id || pendingBatch?.id;
    if (!current && finished && status.last_result?.id === finished) completeTransaction(finished, status.last_result.outcome);
    if (previous && (!current || (!previous.ready && current.ready)) && !dirty.size && !staged.length && !tomlBusy) await refresh();
  }
  catch (e) { if (pendingTransaction) $("confirmation-message").textContent = "The appliance is unreachable. Recovery runs independently; reconnect before the deadline to confirm."; }
}
async function finishTransaction(action) {
  if (!pendingTransaction || $("confirm-change").classList.contains("busy") || $("revert-change").classList.contains("busy")) return;
  const id = pendingTransaction.id;
  const done = busy(["confirm-change", "revert-change"], action === "confirm" ? "Confirming…" : "Reverting…");
  try {
    const response = await api("/api/v1/config/" + action, { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ id }) }, 120);
    const result = await response.json();
    if (result.reverting) {
      await refreshTransaction();
      banner("Rollback requested. Recovery continues independently of this connection.", "note");
      return;
    }
    setTransaction(null);
    completeTransaction(id, action === "confirm" ? "confirmed" : "reverted");
    await refresh();
  } catch (e) { banner(String(e.message || e), "err"); await refreshTransaction(); }
  finally { done(); drawConfirmation(); }
}
$("confirm-change").onclick = () => finishTransaction("confirm");
$("revert-change").onclick = () => finishTransaction("revert");

function startManagement() {
  stopManagement();
  refreshTransaction();
  let tick = 0;
  managementTimer = setInterval(() => { drawConfirmation(); if (++tick % 5 === 0) refreshTransaction(); renderLive(); }, 1000);
  telemetryAbort = new AbortController();
  consumeTelemetry(telemetryAbort.signal);
}
function stopManagement() {
  if (managementTimer) clearInterval(managementTimer);
  managementTimer = null;
  if (telemetryAbort) telemetryAbort.abort();
  telemetryAbort = null; liveFrame = null; frozenEvents = null;
  setTransaction(null); pendingBatch = null; completedTransaction = null;
  for (const id of ["live-interfaces", "live-flows", "live-rule-counters", "live-talkers", "live-routing", "live-vpn", "live-ha", "live-connections", "telemetry-freshness"]) $(id).textContent = "";
  $("flow-search").value = ""; $("flow-action").value = ""; $("flow-pause").checked = false;
  flowPage = 0; lastEventSequence = 0;
  clearToml();
}
async function consumeTelemetry(signal) {
  let delay = 1000;
  while (!signal.aborted && token) {
    try {
      const response = await fetch("/api/v1/telemetry", { headers: { Authorization: "Bearer " + token }, signal, cache: "no-store" });
      if (response.status === 401) { signOut("That token was not accepted."); return; }
      if (!response.ok || !response.body) throw new Error("Telemetry HTTP " + response.status);
      const reader = response.body.getReader(), decoder = new TextDecoder();
      let buffer = "";
      try {
        while (!signal.aborted) {
          const { value, done } = await reader.read();
          if (done) throw new Error("Telemetry connection closed");
          buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
          if (buffer.length > 4 * 1024 * 1024) throw new Error("Telemetry frame exceeds the bounded receive window");
          let boundary;
          while ((boundary = buffer.indexOf("\n\n")) >= 0) {
            const frame = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2);
            const data = frame.split("\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart()).join("\n");
            if (!data) continue;
            const next = JSON.parse(data);
            if (next.collecting) continue;
            if (next.sequence < lastEventSequence) { flowPage = 0; frozenEvents = null; }
            lastEventSequence = next.sequence; liveFrame = next; delay = 1000;
            liveStatus = "Live telemetry connected.";
            $("telemetry-freshness").textContent = "Sampled " + new Date(next.sampled_at * 1000).toLocaleTimeString();
            renderLive();
          }
        }
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    } catch (e) {
      if (signal.aborted) return;
      liveStatus = "Telemetry disconnected; displayed values are stale. Reconnecting…";
      renderLive();
      await new Promise((resolve) => {
        const timer = setTimeout(finish, delay);
        function finish() { clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); }
        signal.addEventListener("abort", finish, { once: true });
      });
      delay = Math.min(15000, delay * 2);
    }
  }
}
function tableRows(id, headers, rows) {
  const table = $(id); table.textContent = "";
  table.append(el("tr", {}, headers.map((text) => el("th", { text }))));
  for (const row of rows) table.append(el("tr", {}, row.map((text) => el("td", { text: String(text ?? "—") }))));
}
function renderLive() {
  $("telemetry-status").textContent = target ? "Live telemetry belongs to this appliance. Select the local member to inspect it." : liveStatus;
  if (target) return;
  if (!liveFrame) { $("flow-state").textContent = liveStatus; return; }
  const f = liveFrame, errors = f.errors || {};
  if (view === "dashboard") {
    tableRows("live-interfaces", ["Interface", "Health", "RX bytes/s", "TX bytes/s", "RX pps", "TX pps"],
      (f.interfaces || []).map((i) => [i.name, i.state, ...["rx_bytes_per_second", "tx_bytes_per_second", "rx_pps", "tx_pps"].map((key) => i.rates ? Math.round(i.rates[key]).toLocaleString() : "sampling…")]));
    const ha = f.ha;
    $("live-ha").textContent = ha ? (ha.role === "standalone" ? "Witness-authorized HA is not configured. VRRP status is available on the HA page." : ha.role) + (ha.cluster ? " • " + ha.cluster + " • node " + ha.node + " • term " + ha.term : "") +
      (ha.role === "Backup" ? (ha.sync_age_ms == null ? " • awaiting a complete replica baseline" : " • last authenticated replica update " + ha.sync_age_ms + " ms ago") : ha.role === "Master" ? " • forwarding authority; remote apply latency is not measured by VCS2" : "") : (errors.ha || "HA state unavailable");
    $("live-connections").textContent = f.conntrack?.total == null ? errors.conntrack || "Connection state unavailable" : f.conntrack.total + " active firewall states";
    $("live-talkers").textContent = f.top_talkers || errors.top_talkers || "No NAT talkers reported.";
    $("live-routing").textContent = "BGP\n" + (f.routing?.bgp || errors.bgp || "Unavailable") + "\nOSPF\n" + (f.routing?.ospf || errors.ospf || "Unavailable");
    $("live-vpn").textContent = f.wireguard || errors.wireguard || "No configured WireGuard peers.";
  }
  if (view === "rules") renderFlows();
}
function renderFlows() {
  const events = frozenEvents || liveFrame?.events || [];
  const query = $("flow-search").value.trim().toLowerCase(), action = $("flow-action").value;
  $("flow-clear").classList.toggle("hidden", !query);
  const rows = events.filter((event) => (!action || event.action === action) && (!query || [event.src, event.dst, event.rule, event.rule_id, event.interface_name, event.interface, event.protocol, event.src_port, event.dst_port].join(" ").toLowerCase().includes(query))).slice().reverse();
  flowPage = Math.max(0, Math.min(flowPage, Math.ceil(rows.length / 50) - 1));
  const start = flowPage * 50, shown = rows.slice(start, start + 50);
  tableRows("live-flows", ["Event", "Action", "Rule / ID", "Source", "Destination", "Protocol", "Interface"], shown.map((e) => [e.id, e.action, (e.rule || "default policy") + " / " + e.rule_id, (e.src.includes(":") ? "[" + e.src + "]" : e.src) + ":" + e.src_port, (e.dst.includes(":") ? "[" + e.dst + "]" : e.dst) + ":" + e.dst_port, ({1:"ICMP",6:"TCP",17:"UDP",58:"ICMPv6"})[e.protocol] || e.protocol, e.interface_name || e.interface]));
  $("flow-state").textContent = target ? "Select this appliance to inspect local packet events." : liveFrame?.errors?.events || ((frozenEvents ? "Display paused. " : liveStatus + ". ") + (rows.length ? "Latest 512 retained events; older IDs have left the history window." : query || action ? "No events match these filters." : "No packet events received."));
  $("flow-range").textContent = rows.length ? (start + 1) + "–" + (start + shown.length) + " of " + rows.length : "0 events";
  $("flow-prev").disabled = start === 0; $("flow-next").disabled = start + 50 >= rows.length;
  $("live-rule-counters").textContent = liveFrame?.rule_counters ? JSON.stringify(liveFrame.rule_counters, null, 2) : liveFrame?.errors?.rule_counters || "Counters unavailable";
}
$("flow-search").oninput = (event) => { if (!event.isComposing) { flowPage = 0; renderFlows(); } };
$("flow-search").oncompositionend = () => { flowPage = 0; renderFlows(); };
$("flow-action").onchange = () => { flowPage = 0; renderFlows(); };
$("flow-clear").onclick = () => { $("flow-search").value = ""; flowPage = 0; renderFlows(); $("flow-search").focus(); };
$("flow-pause").onchange = () => { frozenEvents = $("flow-pause").checked ? [...(liveFrame?.events || [])] : null; renderFlows(); };
$("flow-prev").onclick = () => { flowPage--; renderFlows(); };
$("flow-next").onclick = () => { flowPage++; renderFlows(); };

function clearToml() {
  tomlBaseline = ""; tomlRevision = "";
  $("toml-baseline").textContent = ""; $("toml-candidate").value = ""; $("toml-diff").textContent = "";
  $("toml-feedback").textContent = "No changes."; $("toml-candidate").removeAttribute("aria-invalid");
  $("toml-editor").classList.add("hidden"); $("toml-hide").classList.add("hidden");
  $("toml-load").classList.remove("hidden"); dirty.delete("toml-editor");
}
async function loadToml(preserveDraft = false) {
  if (tomlBusy || target || permission === "read-only") return;
  tomlBusy = true;
  const done = busy(["toml-load", "toml-reload", "toml-validate", "toml-apply"], "Loading…");
  try {
    const document = await (await api("/api/v1/config/document")).json();
    tomlBaseline = document.toml; tomlRevision = document.revision;
    $("toml-baseline").textContent = tomlBaseline;
    if (!preserveDraft) $("toml-candidate").value = tomlBaseline;
    if ($("toml-candidate").value !== tomlBaseline) dirty.add("toml-editor"); else dirty.delete("toml-editor");
    $("toml-editor").classList.remove("hidden"); $("toml-hide").classList.remove("hidden"); $("toml-load").classList.add("hidden");
    $("toml-feedback").textContent = preserveDraft ? "Current baseline reloaded. Your draft is preserved; review the side-by-side changes before applying." : "No changes. Secrets are visible only in this tab.";
  } catch (e) { banner(String(e.message || e), "err"); }
  finally { tomlBusy = false; done(); }
}
$("toml-load").onclick = () => loadToml();
$("toml-reload").onclick = () => loadToml(true);
$("toml-hide").onclick = () => { if (dirty.has("toml-editor")) { banner("The TOML draft has unsaved changes. Apply it or restore the current document before hiding it.", "note"); return; } clearToml(); };
$("toml-candidate").oninput = () => {
  const changed = $("toml-candidate").value !== tomlBaseline;
  if (changed) dirty.add("toml-editor"); else dirty.delete("toml-editor");
  $("toml-feedback").textContent = changed ? "Draft changed. Validate against the appliance schema before applying." : "No changes.";
  $("toml-candidate").removeAttribute("aria-invalid"); $("toml-diff").textContent = "";
};
async function submitToml(validateOnly) {
  if (tomlBusy || !tomlRevision || target || permission === "read-only") return;
  if (staged.length) { banner("Apply or discard the staged form changes before submitting a complete TOML revision.", "note"); return; }
  tomlBusy = true;
  $("toml-candidate").readOnly = true;
  const done = busy(["toml-validate", "toml-apply"], validateOnly ? "Validating…" : "Applying…");
  try {
    const response = await api("/api/v1/config/document", { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ toml: $("toml-candidate").value, expected_revision: tomlRevision, validate_only: validateOnly }) }, 120);
    const result = await response.json();
    $("toml-candidate").removeAttribute("aria-invalid");
    $("toml-diff").textContent = result.diff || "No changes.";
    $("toml-feedback").textContent = validateOnly ? "Valid configuration. Nothing applied." : result.pending?.ready ? "Applied provisionally. Verify connectivity and use Keep change before the rollback deadline." : "Application accepted. The independent worker is reconciling; confirmation becomes available when it completes.";
    if (result.pending) setTransaction(result.pending);
    if (!validateOnly) { dirty.delete("toml-editor"); await refresh(); }
  } catch (e) {
    if (e.status === 400) $("toml-candidate").setAttribute("aria-invalid", "true");
    else $("toml-candidate").removeAttribute("aria-invalid");
    $("toml-feedback").textContent = String(e.message || e) + (!validateOnly && !e.status ? " The operation may have started. Reconnect and inspect the pending revision before retrying." : ""); $("toml-candidate").focus();
    await refreshTransaction();
  } finally { tomlBusy = false; $("toml-candidate").readOnly = false; done(); drawConfirmation(); }
}
$("toml-validate").onclick = () => submitToml(true);
$("toml-apply").onclick = () => submitToml(false);
