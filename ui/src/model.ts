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
export interface SystemUnit {
  unit: string;
  load_state: string | null;
  active_state: string | null;
  sub_state: string | null;
  result: string | null;
  exit_status: number | null;
  condition_result: boolean | null;
}
export interface SystemHealth {
  status: "ok" | "warning" | "unknown";
  clock: {
    unix_seconds: number;
    utc: string;
    synchronised: boolean | null;
    ntp_configured: boolean | null;
    ntp_servers: string[] | null;
    service: SystemUnit | null;
  };
  systemd: {
    available: boolean;
    failed_units: SystemUnit[] | null;
    error: string | null;
  };
  network: { default_route: boolean | null };
  tpm: {
    present: boolean;
    devices: string[];
    setup: SystemUnit | null;
    status: "ok" | "warning" | "not-present" | "unknown";
    advice: string;
  };
  issues: {
    code: string;
    severity: "warning" | "unknown";
    message: string;
    action: string;
  }[];
}

/** This boundary never interprets malformed or missing observations as healthy. */
export function isSystemHealth(value: unknown): value is SystemHealth {
  const record = (v: unknown): v is Record<string, unknown> =>
    typeof v === "object" && v !== null && !Array.isArray(v);
  const text = (v: unknown) => typeof v === "string";
  const nullableText = (v: unknown) => v === null || text(v);
  const nullableBool = (v: unknown) => v === null || typeof v === "boolean";
  const strings = (v: unknown) => Array.isArray(v) && v.every(text);
  const unit = (v: unknown) =>
    v === null ||
    (record(v) &&
      text(v.unit) &&
      [v.load_state, v.active_state, v.sub_state, v.result].every(
        nullableText,
      ) &&
      (v.exit_status === null || Number.isInteger(v.exit_status)) &&
      nullableBool(v.condition_result));
  if (!record(value)) return false;
  const { clock, systemd, network, tpm, issues } = value;
  return (
    ["ok", "warning", "unknown"].includes(String(value.status)) &&
    record(clock) &&
    typeof clock.unix_seconds === "number" &&
    Number.isFinite(clock.unix_seconds) &&
    text(clock.utc) &&
    nullableBool(clock.synchronised) &&
    nullableBool(clock.ntp_configured) &&
    (clock.ntp_servers === null || strings(clock.ntp_servers)) &&
    unit(clock.service) &&
    record(systemd) &&
    typeof systemd.available === "boolean" &&
    (systemd.failed_units === null ||
      (Array.isArray(systemd.failed_units) &&
        systemd.failed_units.every((v) => v !== null && unit(v)))) &&
    nullableText(systemd.error) &&
    record(network) &&
    nullableBool(network.default_route) &&
    record(tpm) &&
    typeof tpm.present === "boolean" &&
    strings(tpm.devices) &&
    unit(tpm.setup) &&
    ["ok", "warning", "not-present", "unknown"].includes(String(tpm.status)) &&
    text(tpm.advice) &&
    Array.isArray(issues) &&
    issues.every(
      (v) =>
        record(v) &&
        text(v.code) &&
        ["warning", "unknown"].includes(String(v.severity)) &&
        text(v.message) &&
        text(v.action),
    ) &&
    // Even a syntactically valid but contradictory "ok" envelope must not
    // turn missing/failed observations into a healthy badge.
    (value.status !== "ok" ||
      (clock.synchronised === true &&
        record(clock.service) &&
        clock.service.active_state === "active" &&
        systemd.available === true &&
        Array.isArray(systemd.failed_units) &&
        systemd.failed_units.length === 0 &&
        network.default_route === true &&
        issues.length === 0 &&
        ((tpm.present === false && tpm.status === "not-present") ||
          (tpm.present === true && tpm.status === "ok"))))
  );
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
  /** Empty for this appliance, otherwise the exact configured stack member. */
  member(): string;
  refresh(): Promise<unknown>;
  navigate(
    destination:
      | "interfaces"
      | "rules"
      | "ha"
      | "wireguard"
      | "config"
      | "flows"
      | "system"
      | "services:resolution",
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
  health: SystemHealth | null;
  healthBusy: boolean;
  healthError: string;
  healthReceivedAt: number;
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
  member: string;
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
  health: null,
  healthBusy: false,
  healthError: "",
  healthReceivedAt: 0,
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
  member: "",
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
