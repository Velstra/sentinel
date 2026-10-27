// The existing authentication/navigation and CLI forms share one React-managed
// telemetry, document and safe-apply lifecycle. No credentials cross a URL or
// persistent storage boundary. This adapter contains no rendering logic.
const management = window.SentinelReact.mount({
  api: (...args) => api(...args),
  credential: () => token,
  // Only a confirmed read-write account writes; "unknown" offers nothing.
  canWrite: () => permission === "read-write",
  remote: () => !!target,
  refresh: () => refresh(),
  navigate: destination => goto(destination),
  signOut: message => signOut(message),
  notice: message => banner(message, "note"),
  staged: () => staged,
  restore: change => stage(change.label, change.cmds),
  dirty: changed => changed ? dirty.add("toml-editor") : dirty.delete("toml-editor"),
  completed: (id, outcome, message) => {
    if ($("result").dataset.transaction === id) {
      $("resulttitle").textContent = outcome === "confirmed" ? "Confirmed" : "Configuration restored";
      $("resultout").textContent = message;
    }
  },
});
function startManagement() { management.start(); }
function stopManagement() { management.stop(); }
function setTransaction(pending) { management.setPending(pending); }
function refreshTransaction() { return management.refreshTransaction(); }
function rememberPendingBatch(pending, changes) { management.rememberBatch(pending, changes); }
function renderLive() { management.contextChanged(); }
