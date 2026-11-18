// The appliance dashboard: what the box is doing right now, in one screen.
//
// Read top to bottom the way an operator asks: does anything need me, how busy
// is it, what is it carrying, what is it refusing, and are its neighbours
// there. Every figure is a measurement from the telemetry stream, the health
// endpoint or the appliance's own stored history; a source that did not answer
// is shown as unavailable, never as zero.
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { endpoint, haRole, protocolName } from "./model";
import type {
  Link,
  PacketEvent,
  RuleCounter,
  State,
  SystemHealth,
  Telemetry,
  Vitals,
} from "./model";
import type { Management } from "./controller";
import {
  Glyph,
  Health,
  Panel,
  ReactSystemHealth,
  Source,
  Table,
  number,
  rate,
  useManagement,
} from "./components";

/** How many live samples the chart keeps: a few minutes at the stream's pace. */
const HISTORY = 60;
type Destination = Parameters<Management["navigate"]>[0];
type LinkMeta = Record<string, { zone?: string; description?: string }>;

const bytes = (n: number | null | undefined) => {
  if (n == null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toLocaleString("en-US", { maximumFractionDigits: n >= 100 || i === 0 ? 0 : 1 })} ${units[i]}`;
};
const percent = (n: number | null | undefined) =>
  n == null ? "—" : `${Math.round(n)} %`;
/** Uptime as its two largest units: "12 d 4 h", "3 h 07 min", "42 s". */
export function uptime(seconds: number | null | undefined) {
  if (seconds == null) return "—";
  const d = Math.floor(seconds / 86400),
    h = Math.floor((seconds % 86400) / 3600),
    m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d} d ${h} h`;
  if (h) return `${h} h ${String(m).padStart(2, "0")} min`;
  if (m) return `${m} min`;
  return `${Math.floor(seconds)} s`;
}
const used = (total: number, available: number) =>
  total > 0 ? ((total - available) / total) * 100 : null;
const isBlocked = (event: PacketEvent) =>
  event.action === "drop" || event.action === "reject";

/** A level, 0–100. The figure beside it is the value; the bar is its shape,
 * and it only changes colour where an operator should look. */
function Meter({
  value,
  label,
  plain,
}: {
  value: number | null;
  label: string;
  /** A share of something, not a level of something: no thresholds. */
  plain?: boolean;
}) {
  const level =
    plain || value == null
      ? ""
      : value >= 90
        ? " high"
        : value >= 75
          ? " raised"
          : "";
  return (
    <span
      className={"meter" + level}
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value == null ? undefined : Math.round(value)}
      aria-valuetext={
        value == null ? "unknown" : `${Math.round(value)} percent`
      }
    >
      <span style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%` }} />
    </span>
  );
}

interface Sample {
  rx: number;
  tx: number;
}
/** Measured history for the current member, in total and per link. A member
 * change, a collector restart or an unmeasured sample starts it again: a line
 * drawn across a gap would be a measurement nobody took. */
function useHistory(links: Link[], sequence: number, scope: string) {
  const [history, setHistory] = useState<Sample[]>([]);
  const [perLink, setPerLink] = useState<Record<string, number[]>>({});
  const previous = useRef(0);
  const charted = scope ? links.filter((link) => link.name === scope) : links;
  const measured = charted.length > 0 && charted.every((link) => link.rates);
  const rx = measured
    ? charted.reduce((sum, link) => sum + link.rates!.rx_bytes_per_second, 0)
    : null;
  const tx = measured
    ? charted.reduce((sum, link) => sum + link.rates!.tx_bytes_per_second, 0)
    : null;
  // Another link is another measurement: its line starts where it starts.
  useEffect(() => setHistory([]), [scope]);
  useEffect(() => {
    const sample = rx !== null && tx !== null ? { rx, tx } : null;
    const restart = !sequence || sequence < previous.current;
    if (restart) {
      setHistory(sample && sequence ? [sample] : []);
      setPerLink({});
    } else if (sequence !== previous.current) {
      if (sample) setHistory((old) => [...old, sample].slice(-HISTORY));
      setPerLink((old) => {
        const next: Record<string, number[]> = {};
        for (const link of links)
          if (link.rates)
            next[link.name] = [
              ...(old[link.name] || []),
              link.rates.rx_bytes_per_second + link.rates.tx_bytes_per_second,
            ].slice(-30);
        return next;
      });
    }
    previous.current = sequence;
    // Keyed on the sample: `links` is a new array on every frame.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sequence, rx, tx]);
  return { history, perLink, rx, tx };
}

/** Rule counters as rows; anything else is not counters. */
function ruleRows(frame: Telemetry | null): RuleCounter[] | null {
  const rows = frame?.rule_counters?.rules;
  return Array.isArray(rows) &&
    rows.every(
      (row) =>
        row &&
        Number.isFinite(row.accepted) &&
        Number.isFinite(row.dropped) &&
        Number.isFinite(row.packets),
    )
    ? rows
    : null;
}
/** Packets the firewall decided over the last minute, from its own counters:
 * every rule and every default action, logged or not. Counters only ever
 * rise, so a lower total is a restarted data plane and starts the count again
 * rather than producing a negative one. */
function useDecisions(frame: Telemetry | null) {
  const [window, setWindow] = useState<
    { at: number; refused: number; allowed: number }[]
  >([]);
  const last = useRef<{
    sequence: number;
    refused: number;
    allowed: number;
  } | null>(null);
  const rows = ruleRows(frame);
  const sequence = frame?.sequence || 0,
    at = frame?.sampled_at || 0;
  const refused = rows ? rows.reduce((sum, row) => sum + row.dropped, 0) : null;
  const allowed = rows
    ? rows.reduce((sum, row) => sum + row.accepted, 0)
    : null;
  useEffect(() => {
    if (refused === null || allowed === null || !sequence) {
      last.current = null;
      setWindow([]);
      return;
    }
    const before = last.current;
    last.current = { sequence, refused, allowed };
    if (!before) return;
    if (
      sequence < before.sequence ||
      refused < before.refused ||
      allowed < before.allowed
    ) {
      setWindow([]);
      return;
    }
    if (sequence === before.sequence) return;
    setWindow((old) =>
      [
        ...old,
        {
          at,
          refused: refused - before.refused,
          allowed: allowed - before.allowed,
        },
      ].filter((row) => at - row.at < 60),
    );
  }, [sequence, refused, allowed, at]);
  return {
    measured: window.length > 0,
    refused: window.reduce((sum, row) => sum + row.refused, 0),
    allowed: window.reduce((sum, row) => sum + row.allowed, 0),
  };
}

const RANGES = [
  { key: "live", label: "Live", points: 0 },
  { key: "hour", label: "1 h", points: 60 },
  { key: "day", label: "24 h", points: 1440 },
] as const;
type Range = (typeof RANGES)[number]["key"];
/** The appliance's own recorded history for the chart: one stored series per
 * link and direction, summed per minute. Local only — a peer's history is on
 * the peer — and re-read once a minute, which is how often it grows. */
function useStored(
  manager: Management,
  range: Range,
  member: string,
  scope: string,
) {
  const [stored, setStored] = useState<{
    samples: Sample[];
    error: string;
    busy: boolean;
  }>({ samples: [], error: "", busy: false });
  useEffect(() => {
    const points = RANGES.find((r) => r.key === range)!.points;
    if (!points) {
      setStored({ samples: [], error: "", busy: false });
      return;
    }
    let current = true;
    const read = async () => {
      setStored((old) => ({ ...old, busy: true }));
      try {
        const index = (await manager.metrics("")) as { series?: unknown };
        const names = (Array.isArray(index.series) ? index.series : []).filter(
          (name): name is string =>
            typeof name === "string" &&
            /^iface\..+\.(rx|tx)$/.test(name) &&
            !name.startsWith("iface.lo.") &&
            (!scope || name.startsWith("iface." + scope + ".")),
        );
        const buckets = new Map<number, Sample>();
        await Promise.all(
          names.map(async (name) => {
            const answer = (await manager.metrics(
              "/minute/" + encodeURIComponent(name),
            )) as { points?: { at: number; value: number }[] };
            const side = name.endsWith(".rx") ? "rx" : "tx";
            for (const point of answer.points || []) {
              if (!Number.isFinite(point.at) || !Number.isFinite(point.value))
                continue;
              const minute = Math.round(point.at / 60);
              const bucket = buckets.get(minute) || { rx: 0, tx: 0 };
              bucket[side] += point.value;
              buckets.set(minute, bucket);
            }
          }),
        );
        const samples = [...buckets]
          .sort((a, b) => a[0] - b[0])
          .slice(-points)
          .map(([, sample]) => sample);
        if (current) setStored({ samples, error: "", busy: false });
      } catch (error) {
        if (current)
          setStored({
            samples: [],
            error: error instanceof Error ? error.message : String(error),
            busy: false,
          });
      }
    };
    void read();
    const timer = setInterval(() => void read(), 60000);
    return () => {
      current = false;
      clearInterval(timer);
    };
  }, [manager, range, member, scope]);
  return stored;
}

function Tile({
  label,
  value,
  detail,
  icon,
  destination,
  manager,
  children,
}: {
  label: string;
  value: ReactNode;
  detail: ReactNode;
  icon: Parameters<typeof Glyph>[0]["kind"];
  destination: Destination;
  manager: Management;
  children?: ReactNode;
}) {
  return (
    <button
      className="overview-metric"
      onClick={() => manager.navigate(destination)}
      aria-label={`Open ${destination}`}
    >
      <span className="metric-top">
        <span>{label}</span>
        <Glyph kind={icon} />
      </span>
      <strong>{value}</strong>
      {children}
      <span className="metric-bottom">{detail}</span>
    </button>
  );
}

function Chart({ history, label }: { history: Sample[]; label: string }) {
  const peak = Math.max(...history.map((s) => Math.max(s.rx, s.tx)), 1);
  const line = (pick: (s: Sample) => number) =>
    history
      .map(
        (s, i) =>
          `${(i * 400) / Math.max(1, history.length - 1)},${76 - (pick(s) / peak) * 68}`,
      )
      .join(" ");
  const rx = line((s) => s.rx),
    tx = line((s) => s.tx);
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox="0 0 400 80"
      preserveAspectRatio="none"
    >
      <path className="chart-grid" d="M0 8H400 M0 42H400 M0 76H400" />
      <polygon className="chart-rx" points={`0,80 ${rx} 400,80`} />
      <polyline className="chart-rx" fill="none" points={rx} />
      <polyline className="chart-tx" fill="none" points={tx} />
    </svg>
  );
}
/** A link's last samples as one small line: its shape, not its scale. */
function Spark({ values }: { values?: number[] }) {
  if (!values || values.length < 2) return <span className="spark" />;
  const peak = Math.max(...values, 1);
  const points = values
    .map((n, i) => `${(i * 60) / (values.length - 1)},${15 - (n / peak) * 13}`)
    .join(" ");
  return (
    <svg className="spark" viewBox="0 0 60 16" aria-hidden="true">
      <polyline fill="none" points={points} />
    </svg>
  );
}

/** A link as the configuration knows it: "uplink · wan", then its kernel name. */
function LinkName({ name, meta }: { name: string; meta: LinkMeta }) {
  const known = meta[name];
  const title = [known?.description, known?.zone].filter(Boolean).join(" · ");
  return title ? (
    <span className="link-name">
      <span>{title}</span>
      <code>{name}</code>
    </span>
  ) : (
    <code>{name}</code>
  );
}

function Traffic({
  manager,
  remote,
  member,
  links,
  meta,
  history,
  perLink,
  rx,
  tx,
  error,
  scope,
  onScope,
}: {
  manager: Management;
  remote: boolean;
  member: string;
  links: Link[];
  meta: LinkMeta;
  history: Sample[];
  perLink: Record<string, number[]>;
  rx: number | null;
  tx: number | null;
  error?: string;
  /** The one link the chart follows, or "" for the sum of all of them. */
  scope: string;
  onScope: (name: string) => void;
}) {
  const [range, setRange] = useState<Range>("live");
  // A peer's history is on the peer: the choice falls back to what it has.
  const shown: Range = remote ? "live" : range;
  const stored = useStored(manager, shown, member, scope);
  const live = shown === "live";
  const samples = live ? history : stored.samples;
  const charted = samples.length > 1 && (!live || rx !== null);
  const peak = charted ? Math.max(...samples.map((s) => s.rx + s.tx)) : null;
  return (
    <Panel title="Traffic">
      <div className="throughput-strip">
        <div className="traffic-readout">
          <div className="traffic-directions">
            <div>
              <span className="metric-label">
                <i className="swatch rx" /> Receive
              </span>
              <strong>{rate(rx)}</strong>
            </div>
            <div>
              <span className="metric-label">
                <i className="swatch tx" /> Transmit
              </span>
              <strong>{rate(tx)}</strong>
            </div>
          </div>
          <span className="chart-caption">
            {peak !== null
              ? `Peak ${rate(peak)}`
              : live
                ? "Collecting samples"
                : stored.busy
                  ? "Reading history…"
                  : stored.error || "No history recorded yet"}
          </span>
        </div>
        <div className="traffic-chart">
          <div className="range" role="group" aria-label="Chart period">
            {/* Forwarded traffic is counted on the way in and on the way
                out, so the sum of all links is twice what crossed the
                appliance: one link is the honest view of one line. */}
            <select
              id="traffic-scope"
              aria-label="Interface shown in the chart"
              value={scope}
              onChange={(event) => onScope(event.target.value)}
            >
              <option value="">All interfaces (sum)</option>
              {links.map((link) => (
                <option key={link.name} value={link.name}>
                  {[meta[link.name]?.description, meta[link.name]?.zone]
                    .filter(Boolean)
                    .join(" · ") || link.name}
                </option>
              ))}
            </select>
            {RANGES.map((option) => (
              <button
                key={option.key}
                type="button"
                className={option.key === shown ? "selected" : ""}
                aria-pressed={option.key === shown}
                disabled={remote && option.key !== "live"}
                title={
                  remote && option.key !== "live"
                    ? "History is stored on each member; select this appliance"
                    : undefined
                }
                onClick={() => setRange(option.key)}
              >
                {option.label}
              </button>
            ))}
          </div>
          {charted ? (
            <Chart
              history={samples}
              label={
                live
                  ? `Last ${samples.length} throughput samples; receive and transmit`
                  : `Recorded throughput, ${samples.length} one-minute averages; receive and transmit`
              }
            />
          ) : (
            <div className="chart-waiting">
              {live
                ? "The chart appears after two measured samples."
                : stored.busy
                  ? "Reading recorded history…"
                  : "No recorded history for this period."}
            </div>
          )}
        </div>
      </div>
      {error && <p role="status">{error}</p>}
      <Table
        id="live-interfaces"
        headers={[
          "Interface",
          "State",
          "Receive",
          "Transmit",
          "Packets/s",
          "Trend",
        ]}
        rows={links.map((link) => [
          <LinkName name={link.name} meta={meta} />,
          <Health state={link.state} held={link.held} />,
          rate(link.rates?.rx_bytes_per_second),
          rate(link.rates?.tx_bytes_per_second),
          link.rates
            ? `${number(link.rates.rx_pps)} / ${number(link.rates.tx_pps)}`
            : "—",
          <Spark values={perLink[link.name]} />,
        ])}
        empty="No interface measurements available."
      />
    </Panel>
  );
}

function Firewall({
  frame,
  errors,
}: {
  frame: Telemetry | null;
  errors: Record<string, string>;
}) {
  const rows = ruleRows(frame);
  // Rules an operator wrote, busiest first; what no rule decided — each
  // zone's default action and established traffic — is one line under them.
  const named = rows
    ? rows
        .filter((row) => row.rule && row.packets > 0)
        .sort((a, b) => b.packets - a.packets)
        .slice(0, 6)
    : [];
  const defaults = (rows || []).filter((row) => !row.rule);
  const rest: RuleCounter | null = defaults.length
    ? {
        rule: null,
        policy: defaults.length,
        accepted: defaults.reduce((sum, row) => sum + row.accepted, 0),
        dropped: defaults.reduce((sum, row) => sum + row.dropped, 0),
        packets: defaults.reduce((sum, row) => sum + row.packets, 0),
        bytes: defaults.reduce((sum, row) => sum + row.bytes, 0),
      }
    : null;
  const busiest = rest ? [...named, rest] : named;
  const recent = (frame?.events || []).filter(isBlocked).slice(-5).reverse();
  return (
    <Panel title="Firewall">
      <div id="live-connections" className="dash-facts">
        {frame?.conntrack?.total == null ? (
          <Source
            error={errors.conntrack}
            empty="Connection state unavailable."
          />
        ) : (
          <p>{number(frame.conntrack.total) + " active firewall states"}</p>
        )}
      </div>
      <h4>Busiest rules</h4>
      {rows ? (
        <Table
          id="live-rules"
          headers={["Rule", "Allowed", "Refused", "Volume"]}
          rows={busiest.map((row) => [
            row.rule ? (
              <code>{row.rule}</code>
            ) : (
              <span className="muted">
                default actions and established traffic
              </span>
            ),
            number(row.accepted),
            row.dropped ? (
              <span className="refused">{number(row.dropped)}</span>
            ) : (
              "0"
            ),
            bytes(row.bytes),
          ])}
          empty="No packets counted yet."
        />
      ) : (
        <Source
          error={errors.rule_counters}
          empty="Rule counters unavailable."
        />
      )}
      <h4>Latest refusals</h4>
      {errors.events ? (
        <Source error={errors.events} empty="" />
      ) : (
        <Table
          id="live-refusals"
          headers={["From", "To", "Protocol", "Rule"]}
          rows={recent.map((event) => [
            <code>{event.src}</code>,
            <code>{endpoint(event.dst, event.dst_port)}</code>,
            protocolName(event.protocol),
            event.rule || "default policy",
          ])}
          empty="Nothing refused by a logging rule yet."
        />
      )}
    </Panel>
  );
}

/** The agent's table of busiest hosts, which it prints as text: a header, a
 * rule of dashes, then `host bytes packets connections`. A line that is not
 * four columns means the format moved, and the text is shown as it came. */
function talkers(value?: string | null) {
  const rows = (value || "")
    .split("\n")
    .map((row) => row.trim())
    .filter((row) => row && !/^-+(\s+-+)*$/.test(row) && !/^host\b/i.test(row))
    .map((row) => row.split(/\s+/));
  return rows.length && rows.every((row) => row.length === 4) ? rows : null;
}
function Hosts({
  frame,
  errors,
}: {
  frame: Telemetry | null;
  errors: Record<string, string>;
}) {
  const busiest = talkers(frame?.top_talkers);
  const sources = new Map<string, number>();
  for (const event of (frame?.events || []).filter(isBlocked))
    sources.set(event.src, (sources.get(event.src) || 0) + 1);
  const refused = [...sources].sort((a, b) => b[1] - a[1]).slice(0, 5);
  return (
    <Panel title="Hosts">
      <h4>Busiest through NAT</h4>
      {busiest ? (
        <Table
          id="live-talkers"
          headers={["Host", "Volume", "Packets", "Connections"]}
          rows={busiest
            .slice(0, 6)
            .map(([host, volume, packets, connections]) => [
              <code>{host}</code>,
              volume,
              number(Number(packets)),
              number(Number(connections)),
            ])}
          empty="No NAT talkers reported."
        />
      ) : (
        <Source
          value={frame?.top_talkers}
          error={errors.top_talkers}
          empty="No NAT talkers reported."
        />
      )}
      <h4>Refused most often</h4>
      {refused.length ? (
        <ol className="dash-rank">
          {refused.map(([source, count]) => (
            <li key={source}>
              <code>{source}</code>
              <Meter
                plain
                label={`${source} share of refused packets`}
                value={(count / refused[0][1]) * 100}
              />
              <span>{number(count)}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="source-empty">No refused packets logged.</p>
      )}
    </Panel>
  );
}

/** `198.51.100.1 AS 65010 Established hold 180 "isp"`, one neighbour a line.
 * Anything else is shown as the daemon wrote it. */
export function bgpNeighbours(value?: string | null) {
  const rows = (value || "")
    .split("\n")
    .map((row) => row.trim())
    .filter(Boolean)
    .map((row) => /^(\S+)\s+AS\s+(\d+)\s+(\S+)\s*(.*)$/.exec(row));
  if (!rows.length || rows.some((row) => !row)) return null;
  return rows.map((row) => ({
    address: row![1],
    as: row![2],
    state: row![3],
    note: (/"([^"]*)"/.exec(row![4]) || [])[1] || "",
  }));
}
function Routing({
  frame,
  errors,
}: {
  frame: Telemetry | null;
  errors: Record<string, string>;
}) {
  const neighbours = bgpNeighbours(frame?.routing?.bgp);
  const ospf = frame?.routing?.ospf?.trim() || "";
  const routes = (frame?.routing?.routes || "")
    .split("\n")
    .map((row) => row.trimEnd())
    .filter(Boolean);
  const sources = new Map<string, number>();
  for (const row of routes) {
    const source = (/\bproto\s+(\S+)/.exec(row) || [])[1] || "other";
    sources.set(source, (sources.get(source) || 0) + 1);
  }
  return (
    <Panel title="Routing">
      <div id="live-routing">
        <h4>BGP sessions</h4>
        {neighbours ? (
          <Table
            id="live-bgp"
            headers={["Neighbour", "AS", "State", "Description"]}
            rows={neighbours.map((n) => [
              <code>{n.address}</code>,
              n.as,
              <Health
                state={n.state === "Established" ? "up" : "down"}
                label={n.state}
              />,
              n.note || "—",
            ])}
            empty="No BGP neighbours."
          />
        ) : (
          <Source
            value={frame?.routing?.bgp}
            error={errors.bgp}
            empty="No BGP neighbor status available."
          />
        )}
        <h4>OSPF neighbors</h4>
        {/not enabled/i.test(ospf) && !errors.ospf ? (
          <p className="source-empty">Not enabled.</p>
        ) : (
          <Source
            value={frame?.routing?.ospf}
            error={errors.ospf}
            empty="No OSPF neighbor status available."
          />
        )}
        <h4>
          Routes
          {routes.length > 0 && (
            <span className="count">
              {" "}
              · {number(routes.length)} learned
              {[...sources].length
                ? " (" +
                  [...sources]
                    .map(([source, count]) => `${count} ${source}`)
                    .join(", ") +
                  ")"
                : ""}
            </span>
          )}
        </h4>
        {errors.routes || !routes.length ? (
          <Source
            value={frame?.routing?.routes}
            error={errors.routes}
            empty="No route table available."
          />
        ) : (
          <>
            <pre className="out react-source">
              {routes.slice(0, ROUTES_SHOWN).join("\n")}
            </pre>
            {routes.length > ROUTES_SHOWN && (
              <details className="dash-routes">
                <summary>All {number(routes.length)} lines</summary>
                <pre className="out react-source">{routes.join("\n")}</pre>
              </details>
            )}
          </>
        )}
      </div>
    </Panel>
  );
}
/** The routing table, most of which nobody reads on a dashboard: the first
 * lines stand in for it and the rest is one click away. */
const ROUTES_SHOWN = 6;

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
        <code title={key}>
          {key.length > 16 ? key.slice(0, 8) + "…" + key.slice(-4) : key}
        </code>,
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

/** What the health endpoint observed, as three short answers. Unknown stays
 * unknown: a check that could not be made is not a check that passed. */
function Checks({ health }: { health: SystemHealth | null }) {
  if (!health) return null;
  const answer = (value: boolean | null, yes: string, no: string) =>
    value === null ? "Unknown" : value ? yes : no;
  const failed = health.systemd.failed_units;
  return (
    <ul className="dash-checks">
      <li>
        <span>Clock</span>
        <span>
          {answer(
            health.clock.synchronised,
            "Synchronised",
            "Not synchronised",
          )}
        </span>
      </li>
      <li>
        <span>Default route</span>
        <span>
          {answer(health.network.default_route, "Present", "Missing")}
        </span>
      </li>
      <li>
        <span>Failed services</span>
        <span>
          {!health.systemd.available || failed === null
            ? "Unknown"
            : failed.length
              ? `${failed.length} failed`
              : "None"}
        </span>
      </li>
    </ul>
  );
}
const DISKS: Record<string, string> = {
  data: "Data disk",
  runtime: "Runtime (RAM)",
  root: "System disk",
};
function System({
  vitals,
  health,
}: {
  vitals?: Vitals | null;
  health: SystemHealth | null;
}) {
  if (!vitals)
    return (
      <Panel title="System">
        <p className="source-empty">
          This member does not report system vitals.
        </p>
        <Checks health={health} />
      </Panel>
    );
  const memory = vitals.memory
    ? used(vitals.memory.total_bytes, vitals.memory.available_bytes)
    : null;
  return (
    <Panel title="System">
      <dl className="dash-vitals">
        <div>
          <dt>Uptime</dt>
          <dd>{uptime(vitals.uptime_seconds)}</dd>
        </div>
        <div>
          <dt>Load{vitals.cpus ? ` · ${vitals.cpus} CPUs` : ""}</dt>
          <dd>
            {vitals.load
              ? vitals.load.map((n) => n.toFixed(2)).join(" · ")
              : "—"}
          </dd>
        </div>
      </dl>
      <ul className="dash-gauges">
        <li>
          <span>Processor</span>
          <Meter label="Processor use" value={vitals.cpu_percent} />
          <span>{percent(vitals.cpu_percent)}</span>
        </li>
        <li>
          <span>Memory</span>
          <Meter label="Memory use" value={memory} />
          <span>
            {vitals.memory
              ? `${bytes(vitals.memory.total_bytes - vitals.memory.available_bytes)} of ${bytes(vitals.memory.total_bytes)}`
              : "—"}
          </span>
        </li>
        {vitals.filesystems.map((fs) => (
          <li key={fs.name}>
            <span title={fs.path}>{DISKS[fs.name] || fs.name}</span>
            <Meter
              label={`${fs.name} filesystem use`}
              value={used(fs.total_bytes, fs.available_bytes)}
            />
            <span>
              {bytes(fs.total_bytes - fs.available_bytes)} of{" "}
              {bytes(fs.total_bytes)}
            </span>
          </li>
        ))}
      </ul>
      <Checks health={health} />
    </Panel>
  );
}

export interface Notice {
  key: string;
  text: string;
  destination: Destination;
}
/** What needs an operator, derived from the measurements on this page — the
 * health line above it carries what the health endpoint found. Only things
 * somebody can act on, each with the page where they act; a quiet appliance
 * produces an empty list, and the list is then not drawn at all. */
export function attention(state: State, meta: LinkMeta): Notice[] {
  const frame = state.frame;
  if (!frame) return [];
  const out: Notice[] = [];
  const errors = frame.errors || {};
  // Every question the data plane answers went unanswered: it is not running.
  if (errors.conntrack && errors.ha && errors.rule_counters)
    out.push({
      key: "agent",
      text: "The firewall data plane is not answering.",
      destination: "system",
    });
  for (const link of frame.interfaces) {
    const known = meta[link.name];
    // An unconfigured port that is down is a spare port, not a fault.
    if (!known || (!known.zone && !known.description)) continue;
    if (link.state !== "down" && !link.held) continue;
    const name = known.description || known.zone || link.name;
    out.push({
      key: "link-" + link.name,
      text: link.held
        ? `${name} (${link.name}) is held down until the data plane takes it.`
        : `${name} (${link.name}) is down.`,
      destination: "interfaces",
    });
  }
  for (const neighbour of bgpNeighbours(frame.routing?.bgp) || [])
    if (neighbour.state !== "Established")
      out.push({
        key: "bgp-" + neighbour.address,
        text: `BGP neighbour ${neighbour.note || neighbour.address} is ${neighbour.state}.`,
        destination: "routing:bgp",
      });
  if (frame.ha && frame.ha.role !== "Master" && frame.ha.not_ready)
    out.push({
      key: "ha",
      text: `The standby could not take over: ${frame.ha.not_ready}.`,
      destination: "ha",
    });
  const vitals = frame.system;
  if (vitals?.memory) {
    const level = used(
      vitals.memory.total_bytes,
      vitals.memory.available_bytes,
    );
    if (level !== null && level >= 90)
      out.push({
        key: "memory",
        text: `Memory is ${Math.round(level)} % used.`,
        destination: "system",
      });
  }
  for (const fs of vitals?.filesystems || []) {
    const level = used(fs.total_bytes, fs.available_bytes);
    if (level !== null && level >= 90)
      out.push({
        key: "disk-" + fs.name,
        text: `${DISKS[fs.name] || fs.name} is ${Math.round(level)} % full.`,
        destination: "system",
      });
  }
  return out;
}
function Attention({
  notices,
  manager,
}: {
  notices: Notice[];
  manager: Management;
}) {
  if (!notices.length) return null;
  return (
    <section className="dash-attention" aria-label="Needs attention">
      <h3>
        Needs attention <span className="count">{notices.length}</span>
      </h3>
      <ul>
        {notices.map((notice) => (
          <li key={notice.key}>
            <span>{notice.text}</span>
            <button
              type="button"
              className="btn"
              onClick={() => manager.navigate(notice.destination)}
            >
              Open
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function Dashboard({ manager }: { manager: Management }) {
  const state = useManagement(manager),
    f = state.frame,
    errors = f?.errors || {},
    ha = f?.ha;
  const meta = manager.links();
  const links = (f?.interfaces || []).filter((link) => link.name !== "lo");
  const [chosen, setScope] = useState("");
  // A link that has gone cannot be followed; the chart returns to the sum.
  const scope = links.some((link) => link.name === chosen) ? chosen : "";
  const { history, perLink, rx, tx } = useHistory(
    links,
    f?.sequence || 0,
    scope,
  );
  const everyLink = links.length > 0 && links.every((link) => link.rates);
  const total = everyLink
    ? links.reduce(
        (sum, link) =>
          sum +
          link.rates!.rx_bytes_per_second +
          link.rates!.tx_bytes_per_second,
        0,
      )
    : null;
  const decisions = useDecisions(f);
  const vitals = f?.system;
  const memory = vitals?.memory
    ? used(vitals.memory.total_bytes, vitals.memory.available_bytes)
    : null;
  const up = links.filter((link) => link.state === "up").length;
  // Standalone is said by the tile; the panel is for a pair, or for a failure.
  const paired = !!ha && ha.role !== "standalone";
  return (
    <div data-react-view="dashboard">
      <div className="dash-status">
        <ReactSystemHealth manager={manager} compact />
        <div className="telemetry-meta">
          <p
            id="telemetry-status"
            role="status"
            className={
              "stream-status" + (state.connected ? " stream-connected" : "")
            }
          >
            {state.status}
          </p>
          <p id="telemetry-freshness">
            {f
              ? "Sampled " +
                new Date(f.sampled_at * 1000).toLocaleTimeString("en-US")
              : "Waiting for the first sample."}
          </p>
        </div>
      </div>
      {f && !state.connected && (
        <p className="overview-stale" role="status">
          Last known measurements · telemetry connection interrupted.
        </p>
      )}
      <Attention notices={attention(state, meta)} manager={manager} />
      <section className="overview-summary" aria-label="Appliance summary">
        <Tile
          manager={manager}
          label="Traffic"
          icon="network"
          destination="interfaces"
          value={rate(total)}
          detail={
            links.length
              ? `${up} of ${links.length} interfaces up`
              : "No interface measurements"
          }
        />
        <Tile
          manager={manager}
          label="Connections"
          icon="shield"
          destination="rules"
          value={number(f?.conntrack?.total)}
          detail="Tracked firewall states"
        />
        <Tile
          manager={manager}
          label="Refused"
          icon="block"
          destination="flows"
          value={decisions.measured ? number(decisions.refused) : "—"}
          detail={
            decisions.measured
              ? `Packets in the last minute · ${number(decisions.allowed)} allowed`
              : "Packets in the last minute"
          }
        />
        <Tile
          manager={manager}
          label="Processor"
          icon="chip"
          destination="system"
          value={percent(vitals?.cpu_percent)}
          detail={
            vitals?.load
              ? `Load ${vitals.load[0].toFixed(2)}${vitals.cpus ? ` · ${vitals.cpus} CPUs` : ""}`
              : "No measurement"
          }
        >
          <Meter label="Processor use" value={vitals?.cpu_percent ?? null} />
        </Tile>
        <Tile
          manager={manager}
          label="Memory"
          icon="memory"
          destination="system"
          value={percent(memory)}
          detail={
            vitals?.memory
              ? `${bytes(vitals.memory.total_bytes - vitals.memory.available_bytes)} of ${bytes(vitals.memory.total_bytes)}`
              : "No measurement"
          }
        >
          <Meter label="Memory use" value={memory} />
        </Tile>
        <Tile
          manager={manager}
          label="High availability"
          icon="pair"
          destination="ha"
          value={haRole(ha)}
          detail={
            ha?.role === "Backup"
              ? "Standby replica"
              : ha?.role === "Master"
                ? "Forwarding authority"
                : vitals?.uptime_seconds != null
                  ? `Up ${uptime(vitals.uptime_seconds)}`
                  : "Appliance role"
          }
        />
      </section>
      <div className="dash-grid">
        <div className="dash-wide">
          <Traffic
            manager={manager}
            remote={state.remote}
            member={state.member}
            links={links}
            meta={meta}
            history={history}
            perLink={perLink}
            rx={rx}
            tx={tx}
            error={errors.interfaces}
            scope={scope}
            onScope={setScope}
          />
        </div>
        <System
          vitals={vitals}
          health={
            // Stale observations are not answers; the health line says so.
            state.health &&
            !state.healthError &&
            state.now - state.healthReceivedAt <= 30000
              ? state.health
              : null
          }
        />
        <div className="dash-half">
          <Firewall frame={f} errors={errors} />
        </div>
        <div className="dash-half">
          <Hosts frame={f} errors={errors} />
        </div>
        <div className="dash-half">
          <Routing frame={f} errors={errors} />
        </div>
        <div className="dash-half">
          <Panel title="VPN">
            <div id="live-vpn">
              <WireGuard
                value={f?.wireguard}
                error={errors.wireguard}
                sampledAt={f?.sampled_at || 0}
              />
            </div>
          </Panel>
          {(paired || !ha) && (
            <Panel title="High availability">
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
                          : "Forwarding authority is determined by the HA state machine."}
                    </p>
                  </>
                ) : (
                  <Source error={errors.ha} empty="HA state unavailable." />
                )}
              </div>
            </Panel>
          )}
        </div>
      </div>
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
    </div>
  );
}
