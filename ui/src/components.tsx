import {
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import type { ReactNode } from "react";
import { diffLines } from "diff";
import { endpoint, haRole, protocolName, selectEvents } from "./model";
import type { Link, PacketEvent } from "./model";
import type { Management } from "./controller";

function useManagement(manager: Management) {
  return useSyncExternalStore(manager.subscribe, manager.getSnapshot);
}
function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="card management-panel">
      <header className="panel-heading">
        <h3>{title}</h3>
      </header>
      {children}
    </section>
  );
}
function Table({
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
const number = (n: number | null | undefined) =>
  n == null ? "—" : Math.round(n).toLocaleString("en-US");
function rate(n: number | null | undefined) {
  if (n == null) return "Sampling…";
  const units = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
  let i = 0;
  while (n >= 1024 && i < 3) {
    n /= 1024;
    i++;
  }
  return `${n.toLocaleString("en-US", { maximumFractionDigits: 1 })} ${units[i]}`;
}
function Health({ state, held }: { state: string | null; held?: boolean }) {
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
      {state || "Unknown"}
    </span>
  );
}
function Source({
  value,
  error,
  empty,
}: {
  value?: string | null;
  error?: string;
  empty: string;
}) {
  if (error)
    return (
      <div className="source-notice">
        <p>Status unavailable</p>
        <span>This source did not return a measurement.</span>
        <details>
          <summary>Technical details</summary>
          <pre className="out react-source source-error">{error}</pre>
        </details>
      </div>
    );
  if (!value) return <p className="source-empty">{empty}</p>;
  return <pre className="out react-source">{value}</pre>;
}
function Glyph({
  kind,
}: {
  kind: "network" | "shield" | "pair" | "key" | "arrow" | "settings";
}) {
  const paths = {
    network: "M12 3v6M5 15v6M19 15v6M5 15h14M12 9v6M8 3h8v6H8z",
    shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M8 12l3 3 5-6",
    pair: "M3 5h7v14H3zM14 5h7v14h-7zM10 12h4",
    key: "M14 10a5 5 0 1 0-5 5l3-3h3v-3h3v-3",
    arrow: "M5 12h14M13 6l6 6-6 6",
    settings: "M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6",
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
function Overview({ manager }: { manager: Management }) {
  const state = useManagement(manager),
    f = state.remote ? null : state.frame;
  const links = (f?.interfaces || []).filter((link) => link.name !== "lo");
  const peers = (f?.wireguard || "")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((row) => row.trim().split(/\s+/));
  const knownPeers =
    !!f?.wireguard &&
    !f.errors.wireguard &&
    peers.every((row) => row.length === 3 && /^\d+$/.test(row[2]));
  const cards = [
    {
      label: "Interfaces up",
      value: links.length
        ? `${links.filter((link) => link.state === "up").length} / ${links.length}`
        : "—",
      detail: "Physical and virtual links",
      icon: "network",
      destination: "interfaces",
    },
    {
      label: "Active connections",
      value: number(f?.conntrack?.total),
      detail: "Stateful firewall sessions",
      icon: "shield",
      destination: "rules",
    },
    {
      label: "High availability",
      value: haRole(f?.ha),
      detail:
        f?.ha?.role === "Backup"
          ? "Standby replica"
          : f?.ha?.role === "Master"
            ? "Forwarding authority"
            : "Appliance role",
      icon: "pair",
      destination: "ha",
    },
    {
      label: "WireGuard peers",
      value: knownPeers ? number(peers.length) : "—",
      detail: knownPeers
        ? "Peers reporting handshake data"
        : "No peer measurements",
      icon: "key",
      destination: "wireguard",
    },
  ] as const;
  return (
    <>
      {state.frame && !state.connected && !state.remote && (
        <p className="overview-stale" role="status">
          Last known measurements · telemetry connection interrupted.
        </p>
      )}
      <section className="overview-summary" aria-label="Appliance summary">
        {cards.map((card) => (
          <button
            key={card.label}
            className="overview-metric"
            onClick={() => manager.navigate(card.destination)}
            aria-label={`Open ${card.destination}`}
          >
            <span className="metric-top">
              <span>{card.label}</span>
              <Glyph kind={card.icon} />
            </span>
            <strong>{card.value}</strong>
            <span className="metric-bottom">
              {card.detail}
              <Glyph kind="arrow" />
            </span>
          </button>
        ))}
      </section>
      <nav className="dashboard-shortcuts" aria-label="Common tasks">
        <span>Quick access</span>
        <button onClick={() => manager.navigate("flows")}>
          <Glyph kind="network" />
          Live packets
        </button>
        <button onClick={() => manager.navigate("rules")}>
          <Glyph kind="shield" />
          Firewall rules
        </button>
        <button onClick={() => manager.navigate("config")}>
          <Glyph kind="settings" />
          Review configuration
          <Glyph kind="arrow" />
        </button>
      </nav>
    </>
  );
}
function Throughput({
  links,
  sequence,
  remote,
}: {
  links: Link[];
  sequence: number;
  remote: boolean;
}) {
  const [history, setHistory] = useState<number[]>([]);
  const measured = links.length > 0 && links.every((link) => link.rates);
  const receive = measured
    ? links.reduce((sum, link) => sum + link.rates!.rx_bytes_per_second, 0)
    : null;
  const transmit = measured
    ? links.reduce((sum, link) => sum + link.rates!.tx_bytes_per_second, 0)
    : null;
  const sample =
    receive !== null && transmit !== null ? receive + transmit : null;
  useEffect(() => {
    if (!sequence || remote) setHistory([]);
    else if (sample !== null) setHistory((old) => [...old, sample].slice(-40));
  }, [sequence, remote, sample]);
  const max = Math.max(...history, 1);
  const points = history
    .map(
      (n, i) =>
        `${(i * 400) / Math.max(1, history.length - 1)},${60 - (n / max) * 52}`,
    )
    .join(" ");
  return (
    <div className="throughput-strip">
      <div className="traffic-readout">
        <span className="metric-label">Aggregate RX + TX</span>
        <strong>{remote ? "Unavailable" : rate(sample)}</strong>
        <div className="traffic-directions">
          <div>
            <span className="metric-label">↓ Receive</span>
            <span>{remote ? "—" : rate(receive)}</span>
          </div>
          <div>
            <span className="metric-label">↑ Transmit</span>
            <span>{remote ? "—" : rate(transmit)}</span>
          </div>
        </div>
      </div>
      <div className="traffic-chart">
        <div className="chart-caption">
          <span>Measured traffic</span>
          <span>
            {history.length > 1 && !remote && sample !== null
              ? `Peak ${rate(Math.max(...history))}`
              : "Collecting samples"}
          </span>
        </div>
        {history.length > 1 && !remote && sample !== null ? (
          <svg
            role="img"
            aria-label="Last 40 received throughput samples; aggregate RX plus TX"
            viewBox="0 0 400 64"
            preserveAspectRatio="none"
          >
            <path className="chart-grid" d="M0 8H400 M0 34H400 M0 60H400" />
            <polygon points={`0,64 ${points} 400,64`} />
            <polyline fill="none" points={points} />
          </svg>
        ) : (
          <div className="chart-waiting">
            {remote
              ? "Measurements are unavailable in a peer view."
              : "The chart appears after two measured samples."}
          </div>
        )}
        <div className="chart-caption">
          <span>Recent samples</span>
          <span>Now</span>
        </div>
      </div>
    </div>
  );
}

function WireGuard({
  value,
  error,
  sampledAt,
}: {
  value?: string | null;
  error?: string;
  sampledAt: number;
}) {
  const peers = (value || "")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => line.trim().split(/\s+/));
  if (
    error ||
    !peers.length ||
    peers.some((row) => row.length !== 3 || !/^\d+$/.test(row[2]))
  )
    return (
      <Source
        value={value}
        error={error}
        empty="No configured WireGuard peers."
      />
    );
  return (
    <Table
      id="live-vpn-peers"
      headers={["Interface", "Peer public key", "Latest handshake"]}
      rows={peers.map(([link, key, when]) => [
        link,
        <code>{key}</code>,
        Number(when) === 0
          ? "No handshake"
          : Number(when) > sampledAt
            ? "Clock ahead of appliance"
            : `${number(sampledAt - Number(when))} seconds ago`,
      ])}
      empty="No configured WireGuard peers."
    />
  );
}
export function Dashboard({ manager }: { manager: Management }) {
  const state = useManagement(manager),
    f = state.remote ? null : state.frame,
    errors = f?.errors || {},
    ha = f?.ha;
  const status = state.remote
    ? "Live telemetry belongs to this appliance. Select the local member to inspect it."
    : state.status;
  return (
    <div data-react-view="dashboard">
      <Overview manager={manager} />
      <div className="dashboard-primary">
        <Panel title="Live interface throughput">
          <div className="telemetry-meta">
            <p
              id="telemetry-status"
              role="status"
              className={
                "stream-status" +
                (state.connected && !state.remote ? " stream-connected" : "")
              }
            >
              {status}
            </p>
            <p id="telemetry-freshness" className="lede">
              {f
                ? "Sampled " +
                  new Date(f.sampled_at * 1000).toLocaleTimeString("en-US")
                : "Waiting for the first sample."}
            </p>
          </div>
          <Throughput
            links={f?.interfaces || []}
            sequence={f?.sequence || 0}
            remote={state.remote}
          />
          {errors.interfaces && <p role="status">{errors.interfaces}</p>}
          <Table
            id="live-interfaces"
            headers={[
              "Interface",
              "Health",
              "Receive",
              "Transmit",
              "RX pps",
              "TX pps",
            ]}
            rows={(f?.interfaces || []).map((i) => [
              <code>{i.name}</code>,
              <Health state={i.state} held={i.held} />,
              rate(i.rates?.rx_bytes_per_second),
              rate(i.rates?.tx_bytes_per_second),
              number(i.rates?.rx_pps),
              number(i.rates?.tx_pps),
            ])}
            empty="No interface measurements available."
          />
        </Panel>
        <div className="dashgrid">
          <Panel title="HA authority and replication">
            <div id="live-ha">
              {ha ? (
                <>
                  <strong className="ha-role">
                    <span className="metric-label">Current role</span>
                    {haRole(ha)}
                  </strong>
                  {ha.cluster && (
                    <p>
                      {ha.cluster} · node {ha.node} · term {ha.term}
                    </p>
                  )}
                  <p>
                    {ha.role === "Backup"
                      ? ha.sync_age_ms == null
                        ? "Awaiting a complete replica baseline."
                        : `Last authenticated replica update ${number(ha.sync_age_ms)} ms ago.`
                      : ha.role === "Master"
                        ? "Forwarding authority. Remote apply latency is not measured by VCS2."
                        : ha.role === "standalone"
                          ? "Witness-authorized HA is not configured. VRRP status is available on the HA page."
                          : "Forwarding authority is determined by the HA state machine."}
                  </p>
                </>
              ) : (
                <Source error={errors.ha} empty="HA state unavailable." />
              )}
            </div>
          </Panel>
          <Panel title="Connection tracking">
            <div id="live-connections">
              {f?.conntrack?.total == null ? (
                <Source
                  error={errors.conntrack}
                  empty="Connection state unavailable."
                />
              ) : (
                <p>{number(f.conntrack.total) + " active firewall states"}</p>
              )}
            </div>
            <Source
              value={f?.top_talkers}
              error={errors.top_talkers}
              empty="No NAT talkers reported."
            />
          </Panel>
        </div>
      </div>
      <div className="dashgrid">
        <Panel title="BGP and OSPF neighbors">
          <div id="live-routing">
            <h4>BGP sessions</h4>
            <Source
              value={f?.routing?.bgp}
              error={errors.bgp}
              empty="No BGP neighbor status available."
            />
            <h4>OSPF neighbors</h4>
            <Source
              value={f?.routing?.ospf}
              error={errors.ospf}
              empty="No OSPF neighbor status available."
            />
          </div>
        </Panel>
        <Panel title="WireGuard sessions">
          <p className="lede">
            Latest peer handshakes, as reported by WireGuard.
          </p>
          <div id="live-vpn">
            <WireGuard
              value={f?.wireguard}
              error={errors.wireguard}
              sampledAt={f?.sampled_at || 0}
            />
          </div>
        </Panel>
      </div>
      <Panel title="Routing table">
        <Source
          value={f?.routing?.routes}
          error={errors.routes}
          empty="No route table available."
        />
      </Panel>
    </div>
  );
}
export function Flows({ manager }: { manager: Management }) {
  const state = useManagement(manager),
    [query, setQuery] = useState(""),
    [action, setAction] = useState(""),
    [page, setPage] = useState(0);
  const [frozen, setFrozen] = useState<PacketEvent[] | null>(null),
    search = useRef<HTMLInputElement>(null);
  const events = state.remote ? [] : frozen || state.frame?.events || [];
  const selected = useMemo(
    () => selectEvents(events, query, action, page),
    [events, query, action, page],
  );
  const streamSequence = useRef(0);
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
  }, [state.frame, state.connected]);
  const status = state.remote
    ? "Select this appliance to inspect local packet events."
    : state.frame?.errors.events ||
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
            disabled={state.remote}
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
          {state.frame?.errors.events && !state.remote
            ? "Packet logging is currently unavailable."
            : status}
        </p>
        {!state.remote && !!state.frame?.events_lost && (
          <p id="flow-lost" role="note" className="stream-status">
            {state.frame.events_lost.toLocaleString()}{" "}
            {state.frame.events_lost === 1 ? "event" : "events"} lost: the
            packet log filled faster than this view read it. Rule counters stay
            exact.
          </p>
        )}
        {state.frame?.errors.events && !state.remote && (
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
          {state.remote
            ? "Select the local member."
            : state.frame?.rule_counters
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
