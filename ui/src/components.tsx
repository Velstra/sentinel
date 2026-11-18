import {
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import type { ReactNode, Ref } from "react";
import { diffLines } from "diff";
import { endpoint, protocolName, selectEvents } from "./model";
import type { PacketEvent } from "./model";
import type { Management } from "./controller";

export function useManagement(manager: Management) {
  return useSyncExternalStore(manager.subscribe, manager.getSnapshot);
}
export function Panel({
  title,
  children,
  focusRef,
}: {
  title: string;
  children: ReactNode;
  focusRef?: Ref<HTMLElement>;
}) {
  return (
    <section
      className="card management-panel"
      aria-label={title}
      ref={focusRef}
      tabIndex={focusRef ? -1 : undefined}
    >
      <header className="panel-heading">
        <h3>{title}</h3>
      </header>
      {children}
    </section>
  );
}
/** One shared observation surface; the overview uses its compact variant. */
export function ReactSystemHealth({
  manager,
  compact = false,
}: {
  manager: Management;
  compact?: boolean;
}) {
  const state = useManagement(manager);
  const health = state.health;
  const stale =
    !!health &&
    (state.now - state.healthReceivedAt > 30000 || !!state.healthError);
  const status = !health || stale ? "unknown" : health.status;
  const summary =
    state.healthError ||
    (health
      ? stale
        ? "Observations are stale. Retry before relying on these values."
        : ""
      : state.healthBusy
        ? "Checking system health…"
        : "System health has not been checked yet.");
  const Frame = compact ? HealthBar : HealthPanel;
  return (
    <Frame>
      <div className="telemetry-meta system-health-state" aria-live="polite">
        <span
          className={
            "pill " +
            (status === "warning" ? "warn" : status === "ok" ? "ok" : "rest")
          }
        >
          {status === "warning"
            ? "Needs attention"
            : status === "ok"
              ? "Healthy"
              : "Unknown"}
          {stale ? " · stale" : ""}
        </span>
        {/* A healthy, current reading needs no sentence beside its badge. */}
        <p role="status">{summary}</p>
      </div>
      {
        <>
          {health && !compact && (
            <dl className="system-health-summary">
              <div>
                <dt>Appliance clock (UTC)</dt>
                <dd>
                  <code>{health.clock.utc}</code>
                </dd>
              </div>
              <div>
                <dt>Clock synchronisation</dt>
                <dd>
                  {health.clock.synchronised === true
                    ? "Synchronised"
                    : health.clock.synchronised === false
                      ? "Not synchronised"
                      : "Unknown"}
                </dd>
              </div>
              <div>
                <dt>Custom NTP upstreams</dt>
                <dd>
                  {health.clock.ntp_servers === null
                    ? "Unknown"
                    : health.clock.ntp_servers.length
                      ? health.clock.ntp_servers.join(", ")
                      : "None configured; image defaults apply"}
                </dd>
              </div>
              <div>
                <dt>NTP service</dt>
                <dd>
                  <code>{health.clock.service?.unit || "chronyd.service"}</code>{" "}
                  · {health.clock.service?.active_state || "Unknown"}
                </dd>
              </div>
              <div>
                <dt>Default route</dt>
                <dd>
                  {health.network.default_route === true
                    ? "Present (IPv4 or IPv6)"
                    : health.network.default_route === false
                      ? "No IPv4 or IPv6 default route"
                      : "Unknown"}
                </dd>
              </div>
              <div>
                <dt>TPM setup</dt>
                <dd>
                  {health.tpm.status === "not-present"
                    ? "No TPM detected"
                    : health.tpm.status === "warning"
                      ? "Failed / needs attention"
                      : health.tpm.status === "ok"
                        ? "Completed"
                        : "Unverified"}
                  {health.tpm.setup?.exit_status != null && (
                    <> · exit status {health.tpm.setup.exit_status}</>
                  )}
                </dd>
              </div>
            </dl>
          )}
          {!!health?.issues.length && (
            <ul className="system-health-issues">
              {(compact ? health.issues.slice(0, 3) : health.issues).map(
                (issue) => (
                  <li key={issue.code}>
                    <strong>{issue.message}</strong>
                    {!compact && <p>{issue.action}</p>}
                  </li>
                ),
              )}
            </ul>
          )}
          {compact && !!health && health.issues.length > 3 && (
            <p className="lede">
              {health.issues.length - 3} additional health notice(s). Open
              system health for all details.
            </p>
          )}
          {health && !compact && (
            <div>
              <h4>Failed system services</h4>
              {!health.systemd.available ||
              health.systemd.failed_units === null ? (
                <p>
                  Service status is unknown; the appliance could not enumerate
                  failed units.
                </p>
              ) : health.systemd.failed_units.length ? (
                <>
                  <ul className="system-health-units">
                    {health.systemd.failed_units.slice(0, 20).map((unit) => (
                      <li key={unit.unit}>
                        <code>{unit.unit}</code> ·{" "}
                        {unit.active_state || "Unknown"} /{" "}
                        {unit.sub_state || "Unknown"}
                      </li>
                    ))}
                  </ul>
                  {health.systemd.failed_units.length > 20 && (
                    <p>
                      Showing the first 20 of{" "}
                      {health.systemd.failed_units.length} failed units. Inspect
                      the complete list with <code>systemctl --failed</code>.
                    </p>
                  )}
                </>
              ) : (
                <p>No failed system services observed.</p>
              )}
              {health.tpm.present &&
                health.tpm.status !== "ok" &&
                !health.issues.some((issue) =>
                  issue.code.startsWith("tpm-"),
                ) && <p>{health.tpm.advice}</p>}
            </div>
          )}
          <div className="row system-health-actions">
            <button
              type="button"
              className="btn"
              disabled={state.healthBusy}
              aria-busy={state.healthBusy}
              onClick={() => void manager.refreshHealth()}
            >
              Retry health check
            </button>
            {compact && (
              <button
                type="button"
                className="btn"
                onClick={() => manager.navigate("system")}
              >
                Open system health
              </button>
            )}
            <button
              type="button"
              className="btn"
              disabled={state.remote}
              title={
                state.remote
                  ? "Select the local member to configure NTP"
                  : undefined
              }
              onClick={() => manager.navigate("services:resolution")}
            >
              Configure NTP
            </button>
          </div>
          {state.remote && (
            <p className="lede">
              Select the local member to configure NTP. Peer diagnostics are
              read-only.
            </p>
          )}
        </>
      }
    </Frame>
  );
}
function HealthPanel({ children }: { children: ReactNode }) {
  return <Panel title="System health">{children}</Panel>;
}
/** The dashboard's health line: the same observations and actions as the
 * panel on the System page, as one row rather than a card with a heading. */
function HealthBar({ children }: { children: ReactNode }) {
  return (
    <section className="health-bar" aria-label="System health">
      {children}
    </section>
  );
}
export function Table({
  id,
  headers,
  rows,
  empty,
}: {
  id: string;
  headers: string[];
  rows: ReactNode[][];
  empty: string;
}) {
  return (
    <div className="tblwrap">
      <table id={id}>
        <thead>
          <tr>
            {headers.map((h) => (
              <th scope="col" key={h}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((row, i) => (
              <tr key={i}>
                {row.map((cell, j) => (
                  <td key={j}>{cell ?? "—"}</td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={headers.length} className="empty">
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
export const number = (n: number | null | undefined) =>
  n == null ? "—" : Math.round(n).toLocaleString("en-US");
/** A byte rate as the bit rate an operator compares with a line speed:
 * decimal units, as link speeds and provider contracts are quoted. */
export function rate(n: number | null | undefined) {
  if (n == null) return "Sampling…";
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  let bits = n * 8,
    i = 0;
  while (bits >= 1000 && i < 3) {
    bits /= 1000;
    i++;
  }
  return `${bits.toLocaleString("en-US", { maximumFractionDigits: bits >= 100 || i === 0 ? 0 : 1 })} ${units[i]}`;
}
export function Health({
  state,
  held,
  label,
}: {
  state: string | null;
  held?: boolean;
  /** The word to show when it is not the state itself (a protocol's own). */
  label?: string;
}) {
  return (
    <span
      className={
        "health " +
        (state === "up"
          ? "health-up"
          : state === "down" || held
            ? "health-down"
            : "health-unknown")
      }
    >
      {label || state || "Unknown"}
    </span>
  );
}
export function Source({
  value,
  error,
  empty,
}: {
  value?: string | null;
  error?: string;
  empty: string;
}) {
  // One line at rest. A source that did not answer is not a healthy zero, and
  // it is not a paragraph either: the reason is one click away.
  if (error)
    return (
      <details className="source-notice">
        <summary>Status unavailable</summary>
        <pre className="out react-source source-error">{error}</pre>
      </details>
    );
  if (!value) return <p className="source-empty">{empty}</p>;
  return <pre className="out react-source">{value}</pre>;
}
export function Glyph({
  kind,
}: {
  kind:
    | "network"
    | "shield"
    | "pair"
    | "key"
    | "arrow"
    | "settings"
    | "block"
    | "chip"
    | "memory";
}) {
  const paths = {
    network: "M12 3v6M5 15v6M19 15v6M5 15h14M12 9v6M8 3h8v6H8z",
    shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M8 12l3 3 5-6",
    pair: "M3 5h7v14H3zM14 5h7v14h-7zM10 12h4",
    key: "M14 10a5 5 0 1 0-5 5l3-3h3v-3h3v-3",
    arrow: "M5 12h14M13 6l6 6-6 6",
    settings: "M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6",
    block: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM5.6 5.6l12.8 12.8",
    chip: "M7 7h10v10H7zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4",
    memory:
      "M3 8h18v8H3zM7 16v3M11 16v3M15 16v3M19 16v3M7 11v2M11 11v2M15 11v2",
  };
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[kind]} />
    </svg>
  );
}
export function Flows({ manager }: { manager: Management }) {
  const state = useManagement(manager),
    [query, setQuery] = useState(""),
    [action, setAction] = useState(""),
    [page, setPage] = useState(0);
  const [paused, setPaused] = useState<{
      member: string;
      events: PacketEvent[];
    } | null>(null),
    search = useRef<HTMLInputElement>(null);
  const frozen = paused?.member === state.member ? paused.events : null;
  const setFrozen = (events: PacketEvent[] | null) =>
    setPaused(events ? { member: state.member, events } : null);
  const events = frozen || state.frame?.events || [];
  const selected = useMemo(
    () => selectEvents(events, query, action, page),
    [events, query, action, page],
  );
  const streamSequence = useRef(0);
  useEffect(() => {
    setPaused(null);
    setQuery("");
    setAction("");
    setPage(0);
  }, [state.member]);
  useEffect(() => {
    if (state.frame && state.frame.sequence < streamSequence.current) {
      setFrozen(null);
      setPage(0);
    }
    streamSequence.current = state.frame?.sequence || 0;
  }, [state.frame]);
  // Session teardown clears sensitive filters and paused history.
  useEffect(() => {
    if (!state.frame && !state.connected) {
      setFrozen(null);
      setQuery("");
      setAction("");
      setPage(0);
    }
  }, [state.frame, state.connected, state.member]);
  const status =
    state.frame?.errors.events ||
    (frozen
      ? "Display paused. Live collection continues."
      : !state.frame
        ? state.status
        : !selected.total
          ? query || action
            ? "No events match these filters."
            : "No packet events received. Enable Log on a firewall rule to collect matches."
          : state.status);
  return (
    <section className="card management-panel" data-react-view="flows">
      <header className="panel-heading">
        <h3>Live flow and rule inspector</h3>
        <span className="panel-tag">{events.length} retained</span>
      </header>
      <p className="lede">
        Allowed and dropped packets from rules with Log enabled. The latest 512
        events are retained; this is a diagnostic stream.
      </p>
      <div
        className="flow-presets"
        role="group"
        aria-label="Quick event filters"
      >
        {[
          { value: "", label: "All packets", count: events.length },
          {
            value: "accept",
            label: "Allowed",
            count: events.filter((e) => e.action === "accept").length,
          },
          {
            value: "blocked",
            label: "Blocked",
            count: events.filter(
              (e) => e.action === "drop" || e.action === "reject",
            ).length,
          },
        ].map((filter) => (
          <button
            className={action === filter.value ? "selected" : ""}
            key={filter.value}
            aria-pressed={action === filter.value}
            onClick={() => {
              setAction(filter.value);
              setPage(0);
            }}
          >
            {filter.label}
            <span>{filter.count}</span>
          </button>
        ))}
      </div>
      <div className="toolbar flow-toolbar">
        <label className="field" htmlFor="flow-search">
          <span>Filter events</span>
          <input
            ref={search}
            id="flow-search"
            type="search"
            placeholder="IP address, rule name, port or protocol"
            autoComplete="off"
            value={query}
            onInput={(e) => {
              setQuery(e.currentTarget.value);
              setPage(0);
            }}
          />
        </label>
        <button
          className={"btn" + (!query ? " hidden" : "")}
          id="flow-clear"
          aria-label="Clear event filter"
          onClick={() => {
            setQuery("");
            setPage(0);
            search.current?.focus();
          }}
        >
          Clear
        </button>
        <label className="field" htmlFor="flow-action">
          <span>Action</span>
          <select
            id="flow-action"
            value={action}
            onChange={(e) => {
              setAction(e.target.value);
              setPage(0);
            }}
          >
            <option value="">All actions</option>
            <option value="accept">Accept</option>
            <option value="blocked">Blocked (drop or reject)</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </label>
        <label className="check">
          <input
            id="flow-pause"
            type="checkbox"
            checked={frozen !== null}
            disabled={!state.frame}
            onChange={(e) => {
              setFrozen(
                e.target.checked ? [...(state.frame?.events || [])] : null,
              );
              setPage(0);
            }}
          />
          <span>Pause display</span>
        </label>
      </div>
      <div className="flow-feedback">
        <p id="flow-state" role="status" className="stream-status">
          {state.frame?.errors.events
            ? "Packet logging is currently unavailable."
            : status}
        </p>
        {!!state.frame?.events_lost && (
          <p id="flow-lost" role="note" className="stream-status">
            {state.frame.events_lost.toLocaleString()}{" "}
            {state.frame.events_lost === 1 ? "event" : "events"} lost: the
            packet log filled faster than this view read it. Rule counters stay
            exact.
          </p>
        )}
        {state.frame?.errors.events && (
          <details className="inline-diagnostic">
            <summary>Connection details</summary>
            <pre className="out react-source">{state.frame.errors.events}</pre>
          </details>
        )}
      </div>
      <div className="flow-table">
        <Table
          id="live-flows"
          headers={[
            "Event",
            "Action",
            "Rule / ID",
            "Source",
            "Destination",
            "Protocol",
            "Interface",
          ]}
          rows={selected.rows.map((e) => [
            e.id,
            <span
              className={
                "health " +
                (e.action === "accept" ? "health-up" : "health-drop")
              }
            >
              {e.action}
            </span>,
            <span className="rule-identity">
              <strong>{e.rule || "default policy"}</strong>
              <small>Rule {e.rule_id}</small>
            </span>,
            <code>{endpoint(e.src, e.src_port)}</code>,
            <code>{endpoint(e.dst, e.dst_port)}</code>,
            <span className="protocol-tag">{protocolName(e.protocol)}</span>,
            e.interface_name || e.interface,
          ])}
          empty={
            query || action
              ? "No events match these filters."
              : "No packet events received."
          }
        />
      </div>
      <div className="row flow-pagination">
        <button
          className="btn"
          id="flow-prev"
          disabled={selected.start === 0}
          onClick={() => setPage(selected.page - 1)}
        >
          Previous
        </button>
        <span id="flow-range">
          {selected.total
            ? `${selected.start + 1}–${selected.start + selected.rows.length} of ${selected.total}`
            : "0 events"}
        </span>
        <button
          className="btn"
          id="flow-next"
          disabled={selected.start + 50 >= selected.total}
          onClick={() => setPage(selected.page + 1)}
        >
          Next
        </button>
      </div>
      <details>
        <summary>Exact per-rule packet counters</summary>
        <pre className="out react-source" id="live-rule-counters">
          {state.frame?.rule_counters
            ? JSON.stringify(state.frame.rule_counters, null, 2)
            : state.frame?.errors.rule_counters || "Counters unavailable."}
        </pre>
      </details>
    </section>
  );
}
export function VisualDiff({
  before,
  after,
}: {
  before: string;
  after: string;
}) {
  const changes = useMemo(
    () => diffLines(before, after, { timeout: 40, maxEditLength: 10000 }),
    [before, after],
  );
  if (!changes)
    return (
      <p>
        Large revision: use the current and proposed document panes to review
        the complete change.
      </p>
    );
  let left = 0,
    right = 0;
  const old: ReactNode[] = [],
    next: ReactNode[] = [];
  for (const [i, part] of changes.entries()) {
    if (!part.added) {
      const start = left + 1;
      left += part.count || 0;
      old.push(
        <span
          key={i}
          className={part.removed ? "diff-removed" : ""}
          data-line={start}
        >
          {part.value}
        </span>,
      );
    }
    if (!part.removed) {
      const start = right + 1;
      right += part.count || 0;
      next.push(
        <span
          key={i}
          className={part.added ? "diff-added" : ""}
          data-line={start}
        >
          {part.value}
        </span>,
      );
    }
  }
  return (
    <div
      className="config-columns visual-diff"
      aria-label="Side-by-side configuration diff"
    >
      <div>
        <h4>Current · removed lines marked −</h4>
        <pre className="out config-source">{old}</pre>
      </div>
      <div>
        <h4>Proposed · added lines marked +</h4>
        <pre className="out config-source">{next}</pre>
      </div>
    </div>
  );
}
export function ConfigEditor({ manager }: { manager: Management }) {
  const state = useManagement(manager),
    e = state.editor,
    editable = state.writable && !state.remote,
    input = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    if (e.invalid) input.current?.focus();
  }, [e.invalid]);
  const [showDiff, setShowDiff] = useState(false);
  if (state.remote)
    return (
      <section
        className="card management-panel"
        data-react-view="configuration"
      >
        <h3>Declarative configuration</h3>
        <p role="status">
          Select the local member to edit its configuration. Your local draft is
          retained in this tab.
        </p>
      </section>
    );
  return (
    <section className="card management-panel" data-react-view="configuration">
      <header className="panel-heading">
        <h3>Declarative configuration</h3>
        <span className="panel-tag">
          {!e.visible
            ? "Secrets hidden"
            : e.candidate !== e.baseline
              ? "Draft edited"
              : "Current revision"}
        </span>
      </header>
      <p className="lede">
        Review the current configuration alongside your proposed changes.
        Validate before applying, then confirm when access and forwarding work.
      </p>
      <ol className="editor-guide" aria-label="Configuration workflow">
        <li>
          <strong>Edit</strong>
          <span>Prepare a private draft</span>
        </li>
        <li>
          <strong>Validate</strong>
          <span>Check syntax and settings</span>
        </li>
        <li>
          <strong>Apply</strong>
          <span>Try the new configuration</span>
        </li>
        <li>
          <strong>Confirm</strong>
          <span>Keep it before the timer expires</span>
        </li>
      </ol>
      {!e.visible && (
        <div className="editor-privacy">
          <Glyph kind="key" />
          <div>
            <strong>Your configuration stays private</strong>
            <p>
              appliance.toml contains secrets. Reveal it only when needed.
              Drafts stay in this tab and are cleared when you sign out.
            </p>
          </div>
        </div>
      )}
      {!editable && (
        <p role="status">
          {state.remote
            ? "Select the local member to edit its configuration."
            : "Full configuration documents require write access."}
        </p>
      )}
      <div className="toolbar">
        <button
          className={"btn" + (e.visible ? " hidden" : "")}
          id="toml-load"
          disabled={!editable || e.busy}
          aria-busy={e.busy}
          onClick={() => void manager.loadEditor()}
        >
          Show configuration
        </button>
        <button
          className={"btn" + (!e.visible ? " hidden" : "")}
          id="toml-hide"
          disabled={e.busy}
          onClick={manager.hideEditor}
        >
          Hide configuration
        </button>
      </div>
      <div id="toml-editor" className={e.visible ? "" : "hidden"}>
        <div className="config-columns">
          <div className="code-pane">
            <h4>
              Current appliance.toml<span className="code-meta">Read only</span>
            </h4>
            <pre className="out config-source" id="toml-baseline">
              {e.baseline}
            </pre>
          </div>
          <label className="field code-pane" htmlFor="toml-candidate">
            <span>
              <span id="toml-candidate-label">Proposed appliance.toml</span>
              <span className="code-meta" aria-hidden="true">
                Editable draft
              </span>
            </span>
            <textarea
              ref={input}
              id="toml-candidate"
              aria-labelledby="toml-candidate-label"
              className="resize-none"
              rows={20}
              spellCheck={false}
              autoComplete="off"
              readOnly={e.busy || !editable}
              value={e.candidate}
              aria-invalid={e.invalid || undefined}
              aria-describedby="toml-feedback"
              onInput={(event) =>
                manager.changeCandidate(event.currentTarget.value)
              }
            />
          </label>
        </div>
        <div className="row editor-actions">
          <button
            className="btn"
            id="toml-reload"
            disabled={!editable || e.busy}
            onClick={() => void manager.loadEditor(true)}
          >
            Reload current baseline
          </button>
          <button
            className="btn"
            id="toml-validate"
            disabled={!editable || e.busy || !!state.pending || e.uncertain}
            aria-busy={e.busy}
            onClick={() => void manager.submitEditor(true)}
          >
            Validate
          </button>
          <button
            className="btn primary"
            id="toml-apply"
            disabled={!editable || e.busy || !!state.pending || e.uncertain}
            aria-busy={e.busy}
            onClick={() => void manager.submitEditor(false)}
          >
            Apply with confirmation
          </button>
        </div>
        <p id="toml-feedback" role="status">
          {e.busy ? "Working… " : ""}
          {e.feedback}
        </p>
        {!!e.warnings.length && (
          <div
            id="toml-warnings"
            role="status"
            aria-live="polite"
            aria-labelledby="toml-warnings-title"
          >
            <span id="toml-warnings-title" className="pill warn">
              Configuration advisories
            </span>
            <ul className="system-health-issues">
              {e.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        )}
        <details
          open={showDiff}
          onToggle={(event) => setShowDiff(event.currentTarget.open)}
        >
          <summary>Side-by-side visual diff</summary>
          {showDiff && <VisualDiff before={e.baseline} after={e.candidate} />}
        </details>
        <details>
          <summary>Validated configuration diff</summary>
          <pre id="toml-diff" className="out react-source">
            {e.diff ||
              "Validate the proposed document to generate its canonical diff."}
          </pre>
        </details>
      </div>
      {!e.visible && e.feedback !== "No changes." && (
        <p role="status">{e.feedback}</p>
      )}
    </section>
  );
}
export function Confirmation({ manager }: { manager: Management }) {
  const state = useManagement(manager),
    pending = state.pending;
  const seconds = Math.max(0, Math.ceil((state.deadline - state.now) / 1000));
  const message =
    state.transactionError ||
    (state.remote
      ? "Select the local member to confirm or revert its pending configuration."
      : !state.writable
        ? "A write-capable account must confirm or revert this configuration."
        : "") ||
    (!pending
      ? ""
      : pending.recovery_failed
        ? "Automatic recovery failed after " +
          (pending.recovery_attempts ?? 0) +
          " attempts. The saved configuration is restored, but the live network may not match it. Inspect the appliance, then accept the current network to allow changes again, or reboot to apply the saved configuration."
        : pending.reverting
          ? (pending.recovery_attempts
              ? "Restoring the previous working configuration failed " +
                pending.recovery_attempts +
                " time(s); retrying with backoff. "
              : "") +
            "Rollback requested. The independent recovery service is restoring the previous working configuration."
          : !pending.ready
            ? "Applying configuration in the independent worker. The confirmation window starts when reconciliation completes."
            : seconds
              ? "Verify management access and forwarding, then keep this revision. Without confirmation the previous working configuration returns automatically."
              : "The confirmation window expired. Reconnecting to check recovery…");
  return (
    <section
      id="confirmation"
      className={"card staged" + (!pending ? " hidden" : "")}
      aria-label="Confirm network configuration"
    >
      <span className="stagedtext">
        <strong>Confirm network configuration</strong>
        <span id="confirmation-message" role="status">
          {message}
        </span>
        <span id="confirmation-countdown" role="timer" aria-live="off">
          {pending?.recovery_failed
            ? "Automatic recovery stopped"
            : pending?.ready
              ? seconds + " seconds until automatic rollback"
              : "Preparing the confirmation window…"}
        </span>
      </span>
      {pending?.recovery_failed && (
        <button
          className="btn primary"
          id="accept-current"
          disabled={!state.writable || state.remote || state.confirming}
          aria-busy={state.confirming}
          onClick={() => void manager.finishTransaction("recovery/accept")}
        >
          Accept current network
        </button>
      )}
      <button
        className="btn primary"
        id="confirm-change"
        disabled={
          !state.writable ||
          state.remote ||
          state.confirming ||
          !pending?.ready ||
          !!pending.reverting ||
          !!pending.recovery_failed ||
          !seconds
        }
        aria-busy={state.confirming}
        onClick={() => void manager.finishTransaction("confirm")}
      >
        Keep change
      </button>
      <button
        className="btn"
        id="revert-change"
        disabled={
          !state.writable ||
          state.remote ||
          state.confirming ||
          !pending ||
          pending.reverting ||
          pending.recovery_failed
        }
        aria-busy={state.confirming}
        onClick={() => void manager.finishTransaction("revert")}
      >
        Revert now
      </button>
    </section>
  );
}
