export interface PacketEvent {
  id: number;
  action: string;
  rule?: string;
  rule_id: number;
  src: string;
  dst: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  interface: number;
  interface_name?: string;
}
export interface Link {
  name: string;
  state: string | null;
  /** A zoned link held down until the data plane has hooked it. Its `state`
   * then says so; dark is the fail-closed state, not a cabling fault. */
  held?: boolean;
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rates: null | {
    rx_bytes_per_second: number;
    tx_bytes_per_second: number;
    rx_pps: number;
    tx_pps: number;
  };
}
export interface Telemetry {
  sequence: number;
  sampled_at: number;
  interfaces: Link[];
  events: PacketEvent[];
  oldest_event_id?: number;
  next_event_id?: number;
  /** Events this view will never show: evicted or dropped before it read them. */
  events_lost?: number;
  conntrack?: { total: number | null; states?: unknown[] };
  top_talkers?: string | null;
  rule_counters?: unknown;
  ha?: {
    role: string;
    cluster?: string;
    node?: string;
    term?: number;
    sync_age_ms?: number | null;
    ready?: boolean;
    not_ready?: string | null;
  } | null;
  routing?: {
    bgp?: string;
    ospf?: string;
    routes?: string;
    /** The table is sent once per change; keep the copy already received. */
    routes_unchanged?: boolean;
  };
  wireguard?: string | null;
  errors: Record<string, string>;
}
export interface Pending {
  id: string;
  remaining_seconds: number;
  ready: boolean;
  reverting?: boolean;
  recovery_attempts?: number;
  /** Recovery gave up; only an explicit accept (or a reboot) ends it. */
  recovery_failed?: boolean;
}
export interface StagedChange {
  label: string;
  cmds: string[];
}
export interface Host {
  api(
    path: string,
    options?: RequestInit,
    patience?: number,
  ): Promise<Response>;
  credential(): string;
  canWrite(): boolean;
  remote(): boolean;
  refresh(): Promise<unknown>;
  navigate(
    destination:
      "interfaces" | "rules" | "ha" | "wireguard" | "config" | "flows",
  ): void;
  signOut(message: string): void;
  notice(message: string): void;
  staged(): StagedChange[];
  restore(change: StagedChange): void;
  dirty(changed: boolean): void;
  completed(id: string, outcome: string, message: string): void;
}
export interface Editor {
  baseline: string;
  candidate: string;
  revision: string;
  visible: boolean;
  busy: boolean;
  feedback: string;
  invalid: boolean;
  diff: string;
  uncertain: boolean;
}
export interface State {
  frame: Telemetry | null;
  status: string;
  connected: boolean;
  receivedAt: number;
  pending: Pending | null;
  deadline: number;
  now: number;
  confirming: boolean;
  transactionError: string;
  editor: Editor;
  writable: boolean;
  remote: boolean;
}
export const emptyEditor = (): Editor => ({
  baseline: "",
  candidate: "",
  revision: "",
  visible: false,
  busy: false,
  feedback: "No changes.",
  invalid: false,
  diff: "",
  uncertain: false,
});
export const initialState = (): State => ({
  frame: null,
  status: "Connecting to telemetry…",
  connected: false,
  receivedAt: 0,
  pending: null,
  deadline: 0,
  now: performance.now(),
  confirming: false,
  transactionError: "",
  editor: emptyEditor(),
  writable: false,
  remote: false,
});
export function endpoint(address: string, port: number) {
  return `${address.includes(":") ? "[" + address + "]" : address}:${port}`;
}
export function protocolName(id: number) {
  return (
    (
      { 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6" } as Record<number, string>
    )[id] || String(id)
  );
}
export function selectEvents(
  events: PacketEvent[],
  query: string,
  action: string,
  page: number,
) {
  const search = query.trim().toLowerCase();
  const filtered = events
    .filter(
      (e) =>
        (!action ||
          (action === "blocked"
            ? e.action === "drop" || e.action === "reject"
            : e.action === action)) &&
        (!search ||
          [
            e.src,
            e.dst,
            endpoint(e.src, e.src_port),
            endpoint(e.dst, e.dst_port),
            protocolName(e.protocol),
            e.rule || "default policy",
            e.src_port,
            e.dst_port,
            e.rule,
            e.rule_id,
            e.interface,
            e.interface_name,
            e.protocol,
          ]
            .join(" ")
            .toLowerCase()
            .includes(search)),
    )
    .slice()
    .reverse();
  const current = Math.max(
    0,
    Math.min(page, Math.ceil(filtered.length / 50) - 1),
  );
  return {
    rows: filtered.slice(current * 50, current * 50 + 50),
    total: filtered.length,
    page: current,
    start: current * 50,
  };
}
// A streaming parser must handle CR/LF and UTF-8 split across arbitrary reads.
// Keepalives don't contain data and never become fabricated telemetry samples.
export async function* sseFrames(
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
): AsyncGenerator<unknown> {
  const reader = body.getReader(),
    decoder = new TextDecoder();
  let buffer = "";
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    while (!signal.aborted) {
      const { value, done } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      if (buffer.length > 4 * 1024 * 1024)
        throw Error("Telemetry frame exceeds the bounded receive window");
      let match: RegExpExecArray | null;
      while ((match = /\r?\n\r?\n/.exec(buffer))) {
        const block = buffer.slice(0, match.index);
        buffer = buffer.slice(match.index + match[0].length);
        const data = block
          .split(/\r?\n/)
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).replace(/^ /, ""))
          .join("\n");
        if (data) yield JSON.parse(data);
      }
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
export function isTelemetry(value: unknown): value is Telemetry {
  if (!value || typeof value !== "object") return false;
  const f = value as Partial<Telemetry>;
  return (
    typeof f.sequence === "number" &&
    Number.isFinite(f.sampled_at) &&
    Array.isArray(f.interfaces) &&
    Array.isArray(f.events) &&
    !!f.errors
  );
}

/** The member's role, and for a member that is not forwarding, why the
 * witness would refuse it authority. A bare "Backup" reads as "covered". */
export function haRole(ha: Telemetry["ha"]): string {
  if (!ha) return "—";
  if (ha.role === "standalone") return "Standalone";
  return ha.role !== "Master" && ha.not_ready
    ? `${ha.role} (not ready: ${ha.not_ready})`
    : ha.role;
}
