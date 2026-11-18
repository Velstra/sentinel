import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Management } from "../src/controller";
import { Flows, ConfigEditor, Confirmation } from "../src/components";
import { Dashboard } from "../src/dashboard";
import { sseFrames, selectEvents } from "../src/model";
import type { Host, Telemetry, Pending } from "../src/model";

const toml = '[system]\nhostname = "sentinel"\n';
function fixture() {
  const host: Host = {
    api: vi.fn(
      async () =>
        new Response(JSON.stringify({ toml, revision: "revision-1" })),
    ),
    credential: () => "private-test-token",
    canWrite: () => true,
    remote: () => false,
    member: () => (host.remote() ? "test-peer" : ""),
    refresh: vi.fn(async () => {}),
    navigate: vi.fn(),
    signOut: vi.fn(),
    notice: vi.fn(),
    staged: () => [],
    restore: vi.fn(),
    dirty: vi.fn(),
    completed: vi.fn(),
  };
  const manager = new Management(host);
  manager.contextChanged();
  return { host, manager };
}
const frame = (overrides: Partial<Telemetry> = {}): Telemetry => ({
  sequence: 1,
  sampled_at: 1700000000,
  interfaces: [
    {
      name: "wan0",
      state: "up",
      rx_bytes: 10240,
      tx_bytes: 2000,
      rx_packets: 100,
      tx_packets: 20,
      rates: {
        rx_bytes_per_second: 2048,
        tx_bytes_per_second: 1024,
        rx_pps: 12,
        tx_pps: 6,
      },
    },
  ],
  events: Array.from({ length: 120 }, (_, i) => ({
    id: i + 1,
    src: "2001:db8::1",
    dst: "2001:db8::2",
    src_port: 2345,
    dst_port: 443,
    protocol: 6,
    interface: 2,
    interface_name: "wan0",
    rule: i % 2 ? "web-in" : "default",
    rule_id: 7,
    action: i % 2 ? "drop" : "accept",
  })),
  ha: { role: "Backup", cluster: "edge", node: "b", term: 3, sync_age_ms: 125 },
  conntrack: { total: 40 },
  routing: {
    bgp: "192.0.2.2 Established",
    ospf: "Full",
    routes: "10.0.0.0/24 via 192.0.2.2",
  },
  wireguard: "wg0 peer-key 1700000000",
  errors: {},
  ...overrides,
});
const pending: Pending = {
  id: "pending-1",
  remaining_seconds: 60,
  ready: true,
};
const reply = (value: unknown) =>
  Promise.resolve(new Response(JSON.stringify(value)));
const failure = (message: string, status?: number) =>
  Object.assign(new Error(message), { status });
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("React dashboard and packet inspector", () => {
  it("renders real interface rates, HA replica age, BGP, routing and VPN sessions", () => {
    const { manager } = fixture();
    manager.acceptFrame(frame());
    render(<Dashboard manager={manager} />);
    expect(screen.getAllByText("wan0")[0]).toBeVisible();
    expect(screen.getAllByText("16.4 kbit/s")).toHaveLength(2);
    expect(screen.getAllByText("Backup")).toHaveLength(2);
    expect(screen.getByText(/replica update 125 ms/)).toBeVisible();
    expect(screen.getByText(/192.0.2.2 Established/)).toBeVisible();
    expect(screen.getByText("peer-key")).toBeVisible();
    expect(screen.getByText("0 seconds ago")).toBeVisible();
    expect(screen.getByText("40 active firewall states")).toBeVisible();
  });
  it("says why a standby could not take over instead of a bare Backup", () => {
    const { manager } = fixture();
    manager.acceptFrame(
      frame({
        ha: {
          role: "Backup",
          cluster: "edge",
          node: "b",
          term: 4,
          sync_age_ms: 2300,
          ready: false,
          not_ready:
            "policy differs from the owner's; awaiting configuration sync",
        },
      }),
    );
    render(<Dashboard manager={manager} />);
    expect(
      screen.getAllByText(
        "Backup (not ready: policy differs from the owner's; awaiting configuration sync)",
      ),
    ).toHaveLength(2);
    expect(screen.queryByText("Backup")).toBeNull();
  });
  it("keeps missing measurements unknown and never invents Master sync latency", async () => {
    const { manager } = fixture();
    manager.acceptFrame(
      frame({
        interfaces: [],
        ha: { role: "Master" },
        conntrack: { total: null },
        routing: {},
        wireguard: null,
        errors: { bgp: "BGP unavailable", conntrack: "Agent unreachable" },
      }),
    );
    render(<Dashboard manager={manager} />);
    const detail = screen.getByText("BGP unavailable");
    expect(detail).not.toBeVisible();
    await userEvent.click(detail.closest("details")!.querySelector("summary")!);
    expect(detail).toBeVisible();
    expect(screen.getByText("Agent unreachable")).toBeInTheDocument();
    expect(screen.getAllByText("Status unavailable").length).toBeGreaterThan(0);
    expect(
      screen.getByText(/Remote apply latency is not measured/),
    ).toBeVisible();
    expect(screen.queryByText(/0 ms/)).toBeNull();
  });
  it("withholds local telemetry while inspecting a peer", () => {
    const { manager, host } = fixture();
    manager.acceptFrame(frame());
    host.remote = () => true;
    manager.contextChanged();
    render(<Dashboard manager={manager} />);
    expect(screen.queryByText("wan0")).toBeNull();
    expect(screen.queryByText("Backup")).toBeNull();
    expect(
      screen.getByText(/Connecting to selected member telemetry/),
    ).toBeVisible();
  });
  it("isolates measured history on member changes and collector restarts", () => {
    const { manager, host } = fixture();
    manager.acceptFrame(frame());
    render(<Dashboard manager={manager} />);
    expect(screen.getByText("24.6 kbit/s")).toBeVisible();
    expect(screen.queryByRole("img")).toBeNull();
    act(() => manager.acceptFrame(frame({ sequence: 2 })));
    expect(
      screen.getByRole("img", { name: /throughput samples/ }),
    ).toBeVisible();
    expect(screen.getByText("Peak 24.6 kbit/s")).toBeVisible();
    host.remote = () => true;
    act(() => manager.contextChanged());
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.queryByText("Peak 24.6 kbit/s")).toBeNull();
    act(() => manager.acceptFrame(frame()));
    expect(screen.getByText("24.6 kbit/s")).toBeVisible();
    expect(screen.queryByRole("img")).toBeNull();
    act(() => manager.acceptFrame(frame({ sequence: 2 })));
    expect(
      screen.getByRole("img", { name: /throughput samples/ }),
    ).toBeVisible();
    act(() =>
      manager.acceptFrame(frame({ sequence: 1, sampled_at: 1700000100 })),
    );
    expect(screen.queryByRole("img")).toBeNull();
  });
  it("does not plot an incomplete aggregate and distinguishes down from unknown links", () => {
    const { manager } = fixture();
    const sample = frame();
    manager.acceptFrame(
      frame({
        interfaces: [
          ...sample.interfaces,
          { ...sample.interfaces[0], name: "lan0", state: "down", rates: null },
        ],
      }),
    );
    render(<Dashboard manager={manager} />);
    expect(screen.queryByText("3 KiB/s")).toBeNull();
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.getByText("down")).toHaveClass("health-down");
    expect(screen.getByText(/chart appears after two/)).toBeVisible();
  });
  it("shows a held zoned link as waiting for the datapath, not as unknown", () => {
    const { manager } = fixture();
    const sample = frame();
    manager.acceptFrame(
      frame({
        interfaces: [
          ...sample.interfaces,
          {
            ...sample.interfaces[0],
            name: "lan0",
            state: "held: waiting for datapath",
            held: true,
            rates: null,
          },
        ],
      }),
    );
    render(<Dashboard manager={manager} />);
    expect(screen.getByText("held: waiting for datapath")).toHaveClass(
      "health-down",
    );
  });
  it("shows the member's own vitals and never a zero for one it could not read", () => {
    const { manager } = fixture();
    manager.acceptFrame(
      frame({
        system: {
          uptime_seconds: 93784,
          load: [0.52, 0.31, 0.1],
          cpus: 2,
          cpu_percent: 12.5,
          memory: {
            total_bytes: 4 * 1024 ** 3,
            available_bytes: 3 * 1024 ** 3,
          },
          filesystems: [
            {
              name: "data",
              path: "/var/lib/sentinel",
              total_bytes: 10 * 1024 ** 3,
              available_bytes: 1024 ** 3,
            },
          ],
        },
      }),
    );
    const { unmount } = render(<Dashboard manager={manager} />);
    expect(screen.getByText("1 d 2 h")).toBeVisible();
    expect(screen.getAllByText("13 %").length).toBeGreaterThan(0);
    expect(screen.getAllByText("25 %").length).toBeGreaterThan(0);
    expect(screen.getAllByText("1 GiB of 4 GiB").length).toBeGreaterThan(0);
    const disk = screen.getByRole("meter", { name: "data filesystem use" });
    expect(disk).toHaveAttribute("aria-valuenow", "90");
    expect(disk).toHaveClass("high");
    expect(screen.getByText("9 GiB of 10 GiB")).toBeVisible();
    unmount();
    // An older member, or a first sample: unknown, not idle.
    manager.acceptFrame(
      frame({
        sequence: 2,
        system: {
          uptime_seconds: null,
          load: null,
          cpus: null,
          cpu_percent: null,
          memory: null,
          filesystems: [],
        },
      }),
    );
    const second = render(<Dashboard manager={manager} />);
    expect(
      screen.getAllByRole("meter", { name: "Processor use" })[0],
    ).toHaveAttribute("aria-valuetext", "unknown");
    expect(screen.queryByText("0 %")).toBeNull();
    second.unmount();
    manager.acceptFrame(frame({ sequence: 3 }));
    render(<Dashboard manager={manager} />);
    expect(
      screen.getByText("This member does not report system vitals."),
    ).toBeVisible();
  });
  it("counts refused packets from the rule counters between samples, never from the first one", () => {
    const { manager } = fixture();
    const counters = (dropped: number, accepted: number) => ({
      rules: [
        {
          rule: "no-telnet",
          policy: 1,
          accepted: 0,
          dropped,
          packets: dropped,
          bytes: dropped * 60,
        },
        {
          rule: null,
          policy: 1,
          accepted,
          dropped: 0,
          packets: accepted,
          bytes: accepted * 900,
        },
      ],
    });
    const event = (id: number) => ({
      id,
      src: id % 2 ? "198.51.100.7" : "198.51.100.9",
      dst: "10.0.0.5",
      src_port: 40000 + id,
      dst_port: 23,
      protocol: 6,
      interface: 2,
      rule: "no-telnet",
      rule_id: 3,
      action: "reject",
    });
    manager.acceptFrame(
      frame({ rule_counters: counters(100, 5000), events: [event(1)] }),
    );
    render(<Dashboard manager={manager} />);
    const tile = () => screen.getByRole("button", { name: "Open flows" });
    // One sample is a total since the data plane started, not a rate.
    expect(tile()).toHaveTextContent("—");
    act(() =>
      manager.acceptFrame(
        frame({
          sequence: 2,
          sampled_at: 1700000005,
          rule_counters: counters(107, 5400),
          events: [event(1), event(2), event(3)],
        }),
      ),
    );
    expect(tile()).toHaveTextContent("7");
    expect(tile()).toHaveTextContent("400 allowed");
    // The busiest rules, by name, with the default action told apart.
    const rules = document.querySelector("#live-rules")!;
    expect(rules).toHaveTextContent("default actions and established traffic");
    expect(rules.querySelector("tbody tr")).toHaveTextContent("no-telnet");
    expect(rules.querySelector(".refused")).toHaveTextContent("107");
    // Sources are ranked over the retained events, most refused first.
    const ranked = screen
      .getAllByRole("meter", { name: /share of refused packets/ })
      .map((meter) => meter.getAttribute("aria-label"));
    expect(ranked[0]).toBe("198.51.100.7 share of refused packets");
    // A restarted data plane starts counting again instead of going negative.
    act(() =>
      manager.acceptFrame(
        frame({
          sequence: 3,
          sampled_at: 1700000010,
          rule_counters: counters(2, 10),
        }),
      ),
    );
    expect(tile()).toHaveTextContent("—");
    // A member without counters is unknown, not quiet.
    act(() =>
      manager.acceptFrame(frame({ sequence: 4, sampled_at: 1700000015 })),
    );
    expect(tile()).toHaveTextContent("—");
    expect(tile()).not.toHaveTextContent("0");
  });
  it("draws receive and transmit separately, leaves loopback out and folds a long route table", () => {
    const { manager } = fixture();
    const sample = frame();
    const routes = Array.from(
      { length: 12 },
      (_, i) => `10.${i}.0.0/16 via 192.0.2.2 proto bgp metric 1`,
    );
    const withLo = (sequence: number) =>
      frame({
        sequence,
        interfaces: [
          ...sample.interfaces,
          { ...sample.interfaces[0], name: "lo" },
        ],
        routing: { routes: routes.join("\n") },
      });
    manager.acceptFrame(withLo(1));
    const { container } = render(<Dashboard manager={manager} />);
    act(() => manager.acceptFrame(withLo(2)));
    const chart = screen.getByRole("img", { name: /throughput samples/ });
    expect(chart.querySelectorAll("polyline")).toHaveLength(2);
    expect(screen.queryByText("lo")).toBeNull();
    expect(
      container.querySelector("#live-interfaces svg.spark"),
    ).not.toBeNull();
    expect(screen.getByText(/12 learned \(12 bgp\)/)).toBeVisible();
    expect(screen.getAllByText(/10\.0\.0\.0\/16/)[0]).toBeVisible();
    const all = container.querySelector(".dash-routes")!;
    expect(all.querySelector("summary")).toHaveTextContent("All 12 lines");
    expect(all).not.toHaveAttribute("open");
  });
  it("follows one chosen link in the chart instead of the double-counted sum", async () => {
    const { manager } = fixture();
    const sample = frame();
    const two = (sequence: number) =>
      frame({
        sequence,
        interfaces: [
          sample.interfaces[0],
          {
            ...sample.interfaces[0],
            name: "lan0",
            rates: {
              rx_bytes_per_second: 125000,
              tx_bytes_per_second: 250000,
              rx_pps: 1,
              tx_pps: 1,
            },
          },
        ],
      });
    manager.acceptFrame(two(1));
    render(<Dashboard manager={manager} />);
    act(() => manager.acceptFrame(two(2)));
    // The sum of both links, in the tile and in the chart's caption.
    expect(
      screen.getByRole("button", { name: "Open interfaces" }),
    ).toHaveTextContent("3 Mbit/s");
    expect(screen.getByText("Peak 3 Mbit/s")).toBeVisible();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Interface shown in the chart" }),
      "lan0",
    );
    // A different link is a different measurement: its history starts again.
    expect(screen.queryByRole("img")).toBeNull();
    act(() => manager.acceptFrame(two(3)));
    act(() => manager.acceptFrame(two(4)));
    expect(screen.getByText("Peak 3 Mbit/s")).toBeVisible();
    expect(screen.getAllByText("1 Mbit/s").length).toBeGreaterThan(1);
    // The link goes away: the chart returns to the sum rather than to nothing.
    act(() => manager.acceptFrame(frame({ sequence: 5 })));
    expect(
      screen.getByRole("combobox", { name: "Interface shown in the chart" }),
    ).toHaveValue("");
  });
  it("names links as the configuration does and lists only what an operator can act on", async () => {
    const { manager, host } = fixture();
    host.links = () => ({
      wan0: { zone: "wan", description: "uplink" },
      lan0: { zone: "lan" },
    });
    const sample = frame();
    const quiet = frame({
      routing: { bgp: '192.0.2.2 AS 65010 Established hold 180 "isp"\n' },
      ha: { role: "standalone" },
    });
    manager.acceptFrame(quiet);
    const { unmount } = render(<Dashboard manager={manager} />);
    expect(screen.getAllByText("uplink · wan")[0]).toBeVisible();
    expect(
      screen.queryByRole("region", { name: "Needs attention" }),
    ).toBeNull();
    expect(screen.getByText("Established")).toHaveClass("health-up");
    // Standalone is said once, by the tile.
    expect(
      screen.queryByRole("region", { name: "High availability" }),
    ).toBeNull();
    unmount();
    manager.acceptFrame(
      frame({
        sequence: 2,
        interfaces: [
          ...sample.interfaces,
          { ...sample.interfaces[0], name: "lan0", state: "down", rates: null },
          {
            ...sample.interfaces[0],
            name: "spare3",
            state: "down",
            rates: null,
          },
        ],
        routing: { bgp: '192.0.2.2 AS 65010 Idle hold 180 "isp"\n' },
        ha: { role: "Backup", not_ready: "policy differs" },
        system: {
          uptime_seconds: 10,
          load: null,
          cpus: null,
          cpu_percent: null,
          memory: { total_bytes: 1000, available_bytes: 50 },
          filesystems: [
            {
              name: "data",
              path: "/var/lib/sentinel",
              total_bytes: 100,
              available_bytes: 4,
            },
          ],
        },
      }),
    );
    render(<Dashboard manager={manager} />);
    const list = screen.getByRole("region", { name: "Needs attention" });
    const items = [...list.querySelectorAll("li")].map(
      (li) => li.firstElementChild!.textContent,
    );
    expect(items).toEqual([
      "lan (lan0) is down.",
      "BGP neighbour isp is Idle.",
      "The standby could not take over: policy differs.",
      "Memory is 95 % used.",
      "Data disk is 96 % full.",
    ]);
    // A port nobody configured is a spare port, not a fault.
    expect(list).not.toHaveTextContent("spare3");
    expect(screen.getByText("Idle")).toHaveClass("health-down");
    await userEvent.click(list.querySelectorAll("button")[1]);
    expect(host.navigate).toHaveBeenLastCalledWith("routing:bgp");
  });
  it("charts the appliance's recorded history on request and never a peer's", async () => {
    const { manager, host } = fixture();
    const series = (values: number[]) => ({
      points: values.map((value, i) => ({ at: 1700000000 + i * 60, value })),
    });
    vi.mocked(host.api).mockImplementation(async (path: string) => {
      if (path === "/api/v1/metrics")
        return new Response(
          JSON.stringify({
            series: [
              "iface.wan0.rx",
              "iface.wan0.tx",
              "iface.lo.rx",
              "gauge.x",
            ],
          }),
        );
      return new Response(
        JSON.stringify(
          path.endsWith(".rx")
            ? series([1000, 3000, 2000])
            : series([100, 200, 125000]),
        ),
      );
    });
    manager.acceptFrame(frame());
    render(<Dashboard manager={manager} />);
    expect(host.api).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "1 h" }));
    const chart = await screen.findByRole("img", {
      name: /Recorded throughput, 3 one-minute averages/,
    });
    expect(chart.querySelectorAll("polyline")).toHaveLength(2);
    expect(screen.getByText("Peak 1 Mbit/s")).toBeVisible();
    const asked = vi.mocked(host.api).mock.calls.map((call) => call[0]);
    expect(asked).toContain("/api/v1/metrics/minute/iface.wan0.rx");
    expect(asked.some((path) => String(path).includes("iface.lo"))).toBe(false);
    // Looking at a peer: its history is on the peer, so the chart is live.
    host.remote = () => true;
    act(() => manager.contextChanged());
    expect(screen.getByRole("button", { name: "1 h" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Live" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.queryByRole("img")).toBeNull();
  });
  it("opens real management destinations from the overview without mutating configuration", async () => {
    const { manager, host } = fixture();
    manager.acceptFrame(frame());
    render(<Dashboard manager={manager} />);
    await userEvent.click(
      screen.getByRole("button", { name: "Open interfaces" }),
    );
    expect(host.navigate).toHaveBeenLastCalledWith("interfaces");
    await userEvent.click(
      screen.getByRole("button", { name: /Review configuration/ }),
    );
    expect(host.navigate).toHaveBeenLastCalledWith("config");
    expect(host.api).not.toHaveBeenCalled();
  });
  it("filters drops and rejects together, retains search and resets pagination", async () => {
    const { manager } = fixture();
    const events = frame().events.map((event, i) => ({
      ...event,
      action: i % 3 === 0 ? "reject" : i % 3 === 1 ? "drop" : "accept",
    }));
    manager.acceptFrame(frame({ events }));
    render(<Flows manager={manager} />);
    await userEvent.click(screen.getByRole("button", { name: /Blocked/ }));
    expect(screen.getByLabelText("Action")).toHaveValue("blocked");
    expect(screen.getByText("1–50 of 80")).toBeVisible();
    await userEvent.click(screen.getByText("Next"));
    expect(screen.getByText("51–80 of 80")).toBeVisible();
    await userEvent.type(screen.getByLabelText("Filter events"), "web-in");
    expect(screen.getByText("1–40 of 40")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: /Allowed/ }));
    expect(screen.getByLabelText("Filter events")).toHaveValue("web-in");
    expect(screen.getByText("1–20 of 20")).toBeVisible();
  });
  it("filters named IPv6 flows, paginates, clears with focus and retains paused history", async () => {
    const user = userEvent.setup(),
      { manager } = fixture();
    manager.acceptFrame(frame());
    render(<Flows manager={manager} />);
    expect(document.querySelectorAll("#live-flows tbody tr")).toHaveLength(50);
    await user.type(screen.getByLabelText("Filter events"), "web-in");
    await user.selectOptions(screen.getByLabelText("Action"), "drop");
    expect(screen.getByText("1–50 of 60")).toBeVisible();
    expect(screen.getAllByText("[2001:db8::1]:2345")).toHaveLength(50);
    await user.click(screen.getByText("Next"));
    expect(screen.getByText("51–60 of 60")).toBeVisible();
    await user.click(screen.getByLabelText("Clear event filter"));
    expect(screen.getByLabelText("Filter events")).toHaveFocus();
    await user.click(screen.getByLabelText("Pause display"));
    act(() => manager.acceptFrame(frame({ sequence: 2, events: [] })));
    expect(screen.getByText("1–50 of 60")).toBeVisible();
    await user.click(screen.getByLabelText("Pause display"));
    expect(screen.getByText("0 events")).toBeVisible();
    await user.type(screen.getByLabelText("Filter events"), "absent");
    expect(
      screen.getAllByText("No events match these filters.").length,
    ).toBeGreaterThan(0);
  });
  it("says how many packet events this view lost", () => {
    const { manager } = fixture();
    manager.acceptFrame(frame());
    render(<Flows manager={manager} />);
    expect(screen.queryByRole("note")).toBeNull();
    act(() => manager.acceptFrame(frame({ events_lost: 1234 })));
    expect(screen.getByRole("note")).toHaveTextContent("1,234 events lost");
  });
  it("keeps the route table when a frame marks it unchanged", () => {
    const { manager } = fixture();
    manager.acceptFrame(frame());
    manager.acceptFrame(
      frame({ routing: { bgp: "Idle", routes_unchanged: true } }),
    );
    const routing = manager.getSnapshot().frame?.routing;
    expect(routing?.routes).toBe("10.0.0.0/24 via 192.0.2.2");
    expect(routing?.bgp).toBe("Idle");
    manager.acceptFrame(frame({ routing: { bgp: "Idle" } }));
    expect(manager.getSnapshot().frame?.routing?.routes).toBeUndefined();
  });
  it("bounds packet retention and clears sensitive filters/history on sign-out", async () => {
    const { manager } = fixture();
    const events = Array.from({ length: 700 }, (_, i) => ({
      ...frame().events[0],
      id: i,
    }));
    manager.acceptFrame(frame({ events }));
    expect(manager.getSnapshot().frame?.events).toHaveLength(512);
    render(<Flows manager={manager} />);
    fireEvent.input(screen.getByLabelText("Filter events"), {
      target: { value: "private-address" },
    });
    act(() => manager.stop());
    expect(screen.getByLabelText("Filter events")).toHaveValue("");
    expect(screen.getByText("0 events")).toBeVisible();
  });
});

describe("React document editor and safe apply", () => {
  it("shows configuration advisories after review and provisional admission without treating them as errors", async () => {
    const { manager, host } = fixture();
    render(<ConfigEditor manager={manager} />);
    await act(() => manager.loadEditor());
    act(() => manager.changeCandidate(toml.replace("sentinel", "proposed")));
    const warning =
      'rule "telnet": `to wan` matches only connected destination prefixes, not routed traffic. <img src=x onerror=alert(1)>';
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({ valid: true, diff: "-old\n+new", warnings: [warning] }),
    );
    await act(() => manager.submitEditor(true));
    expect(
      screen.getByRole("status", { name: "Configuration advisories" }),
    ).toHaveTextContent(warning);
    expect(document.querySelector("#toml-warnings img")).toBeNull();
    expect(
      screen.getByText("Valid configuration. Nothing applied."),
    ).toBeVisible();
    expect(screen.getByText("Apply with confirmation")).toBeEnabled();
    expect(
      screen.getByLabelText("Proposed appliance.toml"),
    ).not.toHaveAttribute("aria-invalid", "true");
    const accepted = { ...pending, ready: false };
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({ accepted: true, pending: accepted, warnings: [warning] }),
    );
    await act(() => manager.submitEditor(false));
    expect(
      screen.getByRole("status", { name: "Configuration advisories" }),
    ).toHaveTextContent(warning);
    expect(manager.getSnapshot().pending).toEqual(accepted);
    expect(screen.getByText(/Application accepted/)).toBeVisible();
    expect(screen.getByText("Apply with confirmation")).toBeDisabled();
    expect(host.api).toHaveBeenCalledTimes(3);
  });

  it("clears configuration advisories when the draft, baseline or validation result changes", async () => {
    const { manager, host } = fixture();
    render(<ConfigEditor manager={manager} />);
    await act(() => manager.loadEditor());
    const validate = async () => {
      vi.mocked(host.api).mockImplementationOnce(() =>
        reply({
          valid: true,
          diff: "reviewed",
          warnings: ["Review this route."],
        }),
      );
      await act(() => manager.submitEditor(true));
      expect(screen.getByText("Review this route.")).toBeVisible();
    };
    await validate();
    act(() => manager.changeCandidate(toml.replace("sentinel", "edited")));
    expect(screen.queryByText("Review this route.")).toBeNull();
    await validate();
    await act(() => manager.loadEditor(true));
    expect(screen.queryByText("Review this route.")).toBeNull();
    expect(manager.getSnapshot().editor.candidate).toContain("edited");
    await validate();
    vi.mocked(host.api)
      .mockRejectedValueOnce(failure("Invalid route", 400))
      .mockImplementationOnce(() => reply({ pending: null }));
    await act(() => manager.submitEditor(true));
    expect(screen.queryByText("Review this route.")).toBeNull();
    expect(screen.getByText("Invalid route")).toBeVisible();
    expect(manager.getSnapshot().editor.candidate).toContain("edited");
    await validate();
    act(() => manager.stop());
    expect(manager.getSnapshot().editor.warnings).toEqual([]);
    expect(screen.queryByText("Review this route.")).toBeNull();
  });

  it("validates configuration advisory types without hiding valid advice or blocking apply", async () => {
    const { manager, host } = fixture();
    render(<ConfigEditor manager={manager} />);
    await act(() => manager.loadEditor());
    for (const warnings of [
      undefined,
      [],
      null,
      "not-an-array",
      { warning: "not-a-list" },
      ["A valid advisory", null, false, {}, 1, "", "   ", "A valid advisory"],
    ]) {
      vi.mocked(host.api).mockImplementationOnce(() =>
        reply({ valid: true, diff: "reviewed", warnings }),
      );
      await act(() => manager.submitEditor(true));
      if (
        warnings === undefined ||
        (Array.isArray(warnings) && !warnings.length)
      ) {
        expect(
          screen.queryByRole("status", { name: "Configuration advisories" }),
        ).toBeNull();
      } else {
        expect(
          screen.getByText(
            /Some configuration advisories could not be displayed/,
          ),
        ).toBeVisible();
      }
      if (Array.isArray(warnings) && warnings.length) {
        expect(screen.getAllByText("A valid advisory")).toHaveLength(1);
      }
      expect(screen.getByText("Apply with confirmation")).toBeEnabled();
      expect(manager.getSnapshot().editor.invalid).toBe(false);
    }
  });

  it("does not restore a stale document response or advisories after identity or member changes", async () => {
    for (const context of ["member", "credential", "permission"] as const) {
      const { manager, host } = fixture();
      await manager.loadEditor();
      let resolve!: (response: Response) => void;
      vi.mocked(host.api).mockImplementationOnce(
        () => new Promise((done) => (resolve = done)),
      );
      const validating = manager.submitEditor(true);
      if (context === "member") host.remote = () => true;
      if (context === "credential")
        host.credential = () => "replacement-session";
      if (context === "permission") host.canWrite = () => false;
      manager.contextChanged();
      resolve(
        new Response(
          JSON.stringify({
            valid: true,
            diff: "PRIVATE OLD DIFF",
            warnings: ["OLD PRIVATE ADVISORY"],
          }),
        ),
      );
      await validating;
      expect(manager.getSnapshot().editor.diff, context).toBe("");
      expect(manager.getSnapshot().editor.warnings, context).toEqual([]);
      expect(manager.getSnapshot().editor.feedback, context).not.toBe(
        "Valid configuration. Nothing applied.",
      );
      manager.stop();
    }
  });

  it("does not restore stale document errors and recovers pending admission through transaction polling", async () => {
    const { manager, host } = fixture();
    await manager.loadEditor();
    let reject!: (error: Error) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((_done, fail) => (reject = fail)),
    );
    const applying = manager.submitEditor(false);
    host.remote = () => true;
    manager.contextChanged();
    reject(failure("PRIVATE OLD ERROR", 400));
    await applying;
    expect(manager.getSnapshot().editor.feedback).not.toContain(
      "PRIVATE OLD ERROR",
    );
    expect(manager.getSnapshot().editor.invalid).toBe(false);
    expect(manager.getSnapshot().editor.warnings).toEqual([]);
    host.remote = () => false;
    manager.contextChanged();
    vi.mocked(host.api).mockImplementationOnce(() => reply({ pending }));
    await manager.refreshTransaction();
    expect(manager.getSnapshot().pending).toEqual(pending);
    expect(host.api).toHaveBeenCalledTimes(3);
    expect(vi.mocked(host.api).mock.calls.at(-1)?.[0]).toBe(
      "/api/v1/config/transaction",
    );
  });

  it("does not reveal a delayed document after leaving and returning to the local member", async () => {
    const { manager, host } = fixture();
    let resolve!: (response: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((done) => (resolve = done)),
    );
    const loading = manager.loadEditor();
    host.remote = () => true;
    manager.contextChanged();
    host.remote = () => false;
    manager.contextChanged();
    resolve(
      new Response(
        JSON.stringify({ toml: "STALE PRIVATE DOCUMENT", revision: "old" }),
      ),
    );
    await loading;
    expect(manager.getSnapshot().editor.visible).toBe(false);
    expect(manager.getSnapshot().editor.baseline).toBe("");
    expect(manager.getSnapshot().editor.busy).toBe(false);
  });

  it("does not let a stale document finalizer clear the next request's busy state", async () => {
    const { manager, host } = fixture();
    let old!: (response: Response) => void;
    let current!: (response: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((done) => (old = done)),
    );
    const first = manager.loadEditor();
    host.canWrite = () => false;
    manager.contextChanged();
    manager.clearEditor();
    host.canWrite = () => true;
    manager.contextChanged();
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((done) => (current = done)),
    );
    const second = manager.loadEditor();
    old(new Response(JSON.stringify({ toml: "OLD PRIVATE", revision: "old" })));
    await first;
    expect(manager.getSnapshot().editor.busy).toBe(true);
    expect(manager.getSnapshot().editor.baseline).toBe("");
    current(new Response(JSON.stringify({ toml, revision: "current" })));
    await second;
    expect(manager.getSnapshot().editor.busy).toBe(false);
    expect(manager.getSnapshot().editor.baseline).toBe(toml);
    expect(manager.getSnapshot().editor.revision).toBe("current");
  });

  it("reveals secrets only on request and provides a real side-by-side visual diff", async () => {
    const { manager, host } = fixture(),
      user = userEvent.setup();
    render(<ConfigEditor manager={manager} />);
    expect(host.api).not.toHaveBeenCalled();
    await user.click(screen.getByText("Show configuration"));
    await waitFor(() =>
      expect(screen.getByLabelText("Proposed appliance.toml")).toHaveValue(
        toml,
      ),
    );
    fireEvent.input(screen.getByLabelText("Proposed appliance.toml"), {
      target: { value: toml.replace("sentinel", "edge-1") },
    });
    await user.click(screen.getByText("Side-by-side visual diff"));
    expect(document.querySelector(".diff-removed")).toHaveTextContent(
      "sentinel",
    );
    expect(document.querySelector(".diff-added")).toHaveTextContent("edge-1");
    await user.click(screen.getByText("Hide configuration"));
    expect(screen.getByLabelText("Proposed appliance.toml")).toBeVisible();
    expect(screen.getByText(/unsaved changes/)).toBeVisible();
  });
  it("blocks read-only accounts and does not fetch full documents", async () => {
    const { manager, host } = fixture();
    host.canWrite = () => false;
    manager.contextChanged();
    render(<ConfigEditor manager={manager} />);
    expect(screen.getByText("Show configuration")).toBeDisabled();
    await manager.loadEditor();
    expect(host.api).not.toHaveBeenCalled();
  });
  it("uses authoritative schema validation, retains rejected TOML and recovers a CAS conflict", async () => {
    const { manager, host } = fixture();
    render(<ConfigEditor manager={manager} />);
    await act(() => manager.loadEditor());
    act(() => manager.changeCandidate("[system\ninvalid"));
    vi.mocked(host.api)
      .mockRejectedValueOnce(failure("Invalid TOML: expected ]", 400))
      .mockResolvedValueOnce(new Response('{"pending":null}'));
    await act(() => manager.submitEditor(true));
    expect(screen.getByLabelText("Proposed appliance.toml")).toHaveAttribute(
      "aria-invalid",
      "true",
    );
    expect(screen.getByLabelText("Proposed appliance.toml")).toHaveFocus();
    expect(screen.getByLabelText("Proposed appliance.toml")).toHaveValue(
      "[system\ninvalid",
    );
    act(() => manager.changeCandidate(toml.replace("sentinel", "proposed")));
    vi.mocked(host.api)
      .mockRejectedValueOnce(
        failure(
          "configuration changed; reload and review the new baseline",
          409,
        ),
      )
      .mockResolvedValueOnce(new Response('{"pending":null}'));
    await act(() => manager.submitEditor(true));
    expect(screen.getByText(/configuration changed;/)).toBeVisible();
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({
        toml: toml.replace("sentinel", "concurrent"),
        revision: "revision-2",
      }),
    );
    await act(() => manager.loadEditor(true));
    expect(manager.getSnapshot().editor.candidate).toContain("proposed");
    expect(manager.getSnapshot().editor.baseline).toContain("concurrent");
    expect(manager.getSnapshot().editor.revision).toBe("revision-2");
  });
  it("does not replay an uncertain write before checking/reloading the baseline", async () => {
    const { manager, host } = fixture();
    await manager.loadEditor();
    manager.changeCandidate(toml.replace("sentinel", "new"));
    vi.mocked(host.api)
      .mockRejectedValueOnce(failure("Network unreachable"))
      .mockImplementationOnce(() => reply({ pending: null }));
    await manager.submitEditor(false);
    expect(manager.getSnapshot().editor.uncertain).toBe(true);
    const calls = vi.mocked(host.api).mock.calls.length;
    await manager.submitEditor(false);
    expect(host.api).toHaveBeenCalledTimes(calls);
    expect(manager.getSnapshot().editor.candidate).toContain("new");
  });
  it("ignores in-flight document responses after session teardown", async () => {
    const { manager, host } = fixture();
    let resolve!: (value: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((r) => (resolve = r)),
    );
    const loading = manager.loadEditor();
    manager.stop();
    resolve(new Response(JSON.stringify({ toml: "SECRET", revision: "old" })));
    await loading;
    expect(manager.getSnapshot().editor.visible).toBe(false);
    expect(manager.getSnapshot().editor.candidate).toBe("");
  });
  it("prevents duplicate apply and sends the revision and validate_only flag", async () => {
    const { manager, host } = fixture();
    await manager.loadEditor();
    let resolve!: (r: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((r) => (resolve = r)),
    );
    const applying = manager.submitEditor(false);
    await manager.submitEditor(false);
    expect(host.api).toHaveBeenCalledTimes(2);
    expect(
      JSON.parse(vi.mocked(host.api).mock.calls[1][1]!.body as string),
    ).toMatchObject({ expected_revision: "revision-1", validate_only: false });
    resolve(new Response(JSON.stringify({ pending })));
    await applying;
    expect(manager.getSnapshot().pending?.id).toBe("pending-1");
  });
  it("recovers a pending 60-second banner and only confirms after explicit action", async () => {
    const { manager, host } = fixture(),
      user = userEvent.setup();
    vi.mocked(host.api).mockImplementationOnce(() => reply({ pending }));
    await manager.refreshTransaction();
    render(<Confirmation manager={manager} />);
    expect(
      screen.getByText("60 seconds until automatic rollback"),
    ).toBeVisible();
    expect(host.api).toHaveBeenCalledTimes(1);
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({ confirmed: true }),
    );
    await user.click(screen.getByText("Keep change"));
    expect(host.api).toHaveBeenCalledWith(
      "/api/v1/config/confirm",
      expect.objectContaining({ body: JSON.stringify({ id: "pending-1" }) }),
      120,
    );
    expect(manager.getSnapshot().pending).toBeNull();
    expect(host.completed).toHaveBeenCalledWith(
      "pending-1",
      "confirmed",
      expect.any(String),
    );
  });
  it("disables confirmation before reconciliation and after expiry, and prevents double confirmation", async () => {
    const { manager, host } = fixture();
    manager.setPending({ ...pending, ready: false });
    render(<Confirmation manager={manager} />);
    expect(screen.getByText("Keep change")).toBeDisabled();
    act(() => manager.setPending({ ...pending, remaining_seconds: 0 }));
    expect(screen.getByText("Keep change")).toBeDisabled();
    await manager.finishTransaction("confirm");
    expect(host.api).not.toHaveBeenCalled();
    act(() => manager.setPending(pending));
    let resolve!: (r: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((r) => (resolve = r)),
    );
    let done!: Promise<void>;
    act(() => {
      done = manager.finishTransaction("confirm");
    });
    await act(() => manager.finishTransaction("confirm"));
    expect(host.api).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Keep change")).toBeDisabled();
    await act(async () => {
      resolve(new Response("{}"));
      await done;
    });
  });
  it("offers to accept the live network only after recovery gave up", async () => {
    const { manager, host } = fixture();
    manager.setPending({ ...pending, reverting: true, recovery_attempts: 2 });
    render(<Confirmation manager={manager} />);
    expect(screen.getByRole("status")).toHaveTextContent("failed 2 time");
    expect(screen.queryByText("Accept current network")).toBeNull();
    await manager.finishTransaction("recovery/accept");
    expect(host.api).not.toHaveBeenCalled();
    act(() =>
      manager.setPending({
        ...pending,
        ready: false,
        reverting: true,
        recovery_attempts: 5,
        recovery_failed: true,
      }),
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Automatic recovery failed after 5 attempts",
    );
    expect(screen.getByText("Keep change")).toBeDisabled();
    expect(screen.getByText("Revert now")).toBeDisabled();
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({ abandoned: true, id: pending.id }),
    );
    await act(() =>
      userEvent.click(screen.getByText("Accept current network")),
    );
    expect(host.api).toHaveBeenCalledWith(
      "/api/v1/config/recovery/accept",
      expect.objectContaining({ body: JSON.stringify({ id: pending.id }) }),
      120,
    );
    expect(manager.getSnapshot().pending).toBeNull();
    expect(host.completed).toHaveBeenCalledWith(
      pending.id,
      "recovery-abandoned",
      expect.stringContaining("live network was accepted"),
    );
  });
  it("restores staged form edits and the TOML draft after server-driven automatic rollback", async () => {
    const { manager, host } = fixture();
    await manager.loadEditor();
    manager.changeCandidate(toml.replace("sentinel", "must-roll-back"));
    manager.setPending(pending);
    manager.rememberBatch(pending, [
      { label: "Hostname", cmds: ["set system hostname must-roll-back"] },
    ]);
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({
        pending: null,
        last_result: { id: pending.id, outcome: "expired" },
      }),
    );
    await manager.refreshTransaction();
    expect(host.restore).toHaveBeenCalledWith({
      label: "Hostname",
      cmds: ["set system hostname must-roll-back"],
    });
    expect(manager.getSnapshot().editor.candidate).toContain("must-roll-back");
    expect(host.dirty).toHaveBeenLastCalledWith(true);
  });
});

describe("navigation and visible-value filtering", () => {
  it("retains the local draft across a peer view without exposing or applying it there", async () => {
    const { manager, host } = fixture();
    await manager.loadEditor();
    manager.changeCandidate(toml.replace("sentinel", "retained-private-draft"));
    render(<ConfigEditor manager={manager} />);
    host.remote = () => true;
    act(() => manager.contextChanged());
    expect(screen.queryByLabelText("Proposed appliance.toml")).toBeNull();
    expect(screen.getByText(/local draft is retained/)).toBeVisible();
    const calls = vi.mocked(host.api).mock.calls.length;
    await manager.submitEditor(false);
    expect(host.api).toHaveBeenCalledTimes(calls);
    host.remote = () => false;
    act(() => manager.contextChanged());
    expect(screen.getByLabelText("Proposed appliance.toml")).toHaveValue(
      toml.replace("sentinel", "retained-private-draft"),
    );
    expect(host.dirty).toHaveBeenLastCalledWith(true);
  });
  it("searches displayed protocol names, complete IPv6 endpoints and fallback policy labels", () => {
    const events = frame().events;
    expect(selectEvents(events, "TCP", "", 0).total).toBe(120);
    expect(selectEvents(events, "[2001:db8::1]:2345", "", 0).total).toBe(120);
    expect(
      selectEvents([{ ...events[0], rule: undefined }], "default policy", "", 0)
        .total,
    ).toBe(1);
  });
  it("explains why confirmation is unavailable while a peer is selected", () => {
    const { manager, host } = fixture();
    manager.setPending(pending);
    host.remote = () => true;
    manager.contextChanged();
    render(<Confirmation manager={manager} />);
    expect(
      screen.getByText(/Select the local member to confirm/),
    ).toBeVisible();
    expect(screen.getByText("Keep change")).toBeDisabled();
  });
});

describe("management concurrency protection", () => {
  it("does not resurrect an older pending status after explicit confirmation", async () => {
    const { manager, host } = fixture();
    manager.setPending(pending);
    let resolve!: (r: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () => new Promise((r) => (resolve = r)),
    );
    const polling = manager.refreshTransaction();
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({ confirmed: true }),
    );
    await manager.finishTransaction("confirm");
    resolve(new Response(JSON.stringify({ pending })));
    await polling;
    expect(manager.getSnapshot().pending).toBeNull();
  });
  it("preserves edits made after a provisional apply when confirming that earlier revision", async () => {
    const { manager, host } = fixture();
    await manager.loadEditor();
    manager.changeCandidate(toml.replace("sentinel", "first"));
    vi.mocked(host.api).mockImplementationOnce(() => reply({ pending }));
    await manager.submitEditor(false);
    manager.changeCandidate(toml.replace("sentinel", "second"));
    vi.mocked(host.api).mockImplementationOnce(() =>
      reply({ confirmed: true }),
    );
    await manager.finishTransaction("confirm");
    expect(manager.getSnapshot().editor.candidate).toContain("second");
    expect(host.dirty).toHaveBeenLastCalledWith(true);
  });
  it("marks a stalled telemetry source stale instead of displaying it as live indefinitely", async () => {
    vi.useFakeTimers();
    const { manager } = fixture();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(new ReadableStream({}))),
    );
    manager.start();
    manager.acceptFrame(frame());
    await vi.advanceTimersByTimeAsync(16000);
    expect(manager.getSnapshot().connected).toBe(false);
    expect(manager.getSnapshot().status).toContain("stale");
    manager.stop();
  });
});

describe("console adapter permissions", () => {
  // The legacy page's adapter, run as the page runs it: free variables for
  // the page's own state, and a mount that hands back the host it was given.
  async function adapter(permission: unknown) {
    const source = (await import("../../src/management.js?raw")).default;
    let host: Host | undefined;
    const window = {
      SentinelReact: {
        mount: (h: Host) => {
          host = h;
          return {};
        },
      },
    };
    new Function("window", "permission", "token", "target", source)(
      window,
      permission,
      "token",
      "",
    );
    return host!;
  }
  it("offers writes only to an account the appliance said is read-write", async () => {
    expect((await adapter("read-write")).canWrite()).toBe(true);
    for (const permission of ["read-only", "unknown", "", undefined])
      expect((await adapter(permission)).canWrite()).toBe(false);
  });
});

describe("authenticated SSE transport", () => {
  it("polls peer snapshots, drops late member responses and never mixes routes or paused packets", async () => {
    vi.useFakeTimers();
    const { manager, host } = fixture();
    let member = "fw-a:8080";
    host.member = () => member;
    host.remote = () => !!member;
    let release!: (response: Response) => void;
    const signals: AbortSignal[] = [];
    const fetcher = vi.fn((_url: unknown, options?: RequestInit) => {
      signals.push(options!.signal as AbortSignal);
      return new Promise<Response>((resolve) => {
        release = resolve;
      });
    });
    vi.stubGlobal("fetch", fetcher);
    manager.start();
    render(
      <>
        <Dashboard manager={manager} />
        <Flows manager={manager} />
      </>,
    );
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/stack/fw-a%3A8080/telemetry",
      expect.anything(),
    );
    await act(async () =>
      release(
        new Response(
          JSON.stringify(frame({ routing: { routes: "old-peer-route" } })),
        ),
      ),
    );
    expect(screen.getAllByText("wan0")[0]).toBeVisible();
    expect(screen.getByText("old-peer-route")).toBeVisible();
    fireEvent.click(screen.getByRole("checkbox", { name: "Pause display" }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1100);
    });
    const oldRelease = release;
    act(() => {
      member = "fw-b:8080";
      manager.contextChanged();
    });
    expect(signals[1].aborted).toBe(true);
    expect(screen.queryByText("wan0")).toBeNull();
    expect(screen.queryByText("old-peer-route")).toBeNull();
    expect(
      screen.getByRole("checkbox", { name: "Pause display" }),
    ).not.toBeChecked();
    // A fetch implementation may ignore abort. Its old 401 must not sign out
    // this valid session or overwrite the newly selected member.
    await act(async () => oldRelease(new Response("", { status: 401 })));
    expect(host.signOut).not.toHaveBeenCalled();
    const peerFrame = frame({
      interfaces: [{ ...frame().interfaces[0], name: "peer-b-nic" }],
      events: [],
      routing: { routes_unchanged: true },
    });
    await act(async () => release(new Response(JSON.stringify(peerFrame))));
    expect(screen.getAllByText("peer-b-nic")[0]).toBeVisible();
    expect(screen.queryByText("old-peer-route")).toBeNull();
    expect(screen.getByText("24.6 kbit/s")).toBeVisible();
    expect(
      screen.queryByRole("img", { name: /throughput samples/ }),
    ).toBeNull();
    act(() => manager.stop());
    expect(signals.every((s) => s.aborted)).toBe(true);
  });
  it("does not refresh freshness for duplicate peer snapshots or fall back to local telemetry", async () => {
    vi.useFakeTimers();
    const { manager, host } = fixture();
    host.remote = () => true;
    const fetcher = vi.fn(
      async (_path: unknown) => new Response(JSON.stringify(frame())),
    );
    vi.stubGlobal("fetch", fetcher);
    manager.start();
    await vi.advanceTimersByTimeAsync(100);
    const received = manager.getSnapshot().receivedAt;
    await vi.advanceTimersByTimeAsync(16000);
    expect(manager.getSnapshot().receivedAt).toBe(received);
    expect(manager.getSnapshot().connected).toBe(false);
    expect(manager.getSnapshot().status).toContain("stale");
    fetcher.mockImplementation(async () => new Response("", { status: 502 }));
    await vi.advanceTimersByTimeAsync(2000);
    expect(manager.getSnapshot().status).toContain(
      "Selected member telemetry unavailable",
    );
    expect(
      fetcher.mock.calls.every(([path]) => String(path).includes("/stack/")),
    ).toBe(true);
    expect(host.signOut).not.toHaveBeenCalled();
    manager.stop();
  });
  it("aborts a silent (half-open) telemetry connection and reconnects with backoff", async () => {
    vi.useFakeTimers();
    const { manager } = fixture();
    const signals: AbortSignal[] = [];
    // A stream that stays open and never sends a byte: what a half-open TCP
    // connection looks like to fetch.
    const fetcher = vi.fn(async (_url: unknown, options?: RequestInit) => {
      signals.push(options?.signal as AbortSignal);
      return new Response(new ReadableStream({}));
    });
    vi.stubGlobal("fetch", fetcher);
    manager.start();
    await vi.advanceTimersByTimeAsync(14000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(signals[0].aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(4000);
    expect(signals[0].aborted).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(manager.getSnapshot().status).toContain("Reconnecting");
    // Still silent: the next attempt waits longer than the first did.
    await vi.advanceTimersByTimeAsync(16000);
    expect(fetcher).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(2500);
    expect(fetcher).toHaveBeenCalledTimes(3);
    manager.stop();
    expect(signals.every((signal) => signal.aborted)).toBe(true);
  });
  it("handles split CRLF delimiters, UTF-8, comments and multiple frames", async () => {
    const chunks = [
      ": keepalive\r\n\r",
      '\ndata: {"name":"ä"}\r',
      "\n\r",
      '\ndata: {"next":2}\n\n',
    ];
    const bytes = new TextEncoder().encode(chunks.join(""));
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        for (const b of bytes) c.enqueue(new Uint8Array([b]));
        c.close();
      },
    });
    const results = [];
    for await (const value of sseFrames(body, new AbortController().signal))
      results.push(value);
    expect(results).toEqual([{ name: "ä" }, { next: 2 }]);
  });
  it("cancels a stalled read on sign-out", async () => {
    const abort = new AbortController(),
      cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    const iterator = sseFrames(body, abort.signal);
    const read = iterator.next();
    abort.abort();
    await expect(read).resolves.toMatchObject({ done: true });
    expect(cancel).toHaveBeenCalledOnce();
  });
  it("uses a bearer header, never a query credential, and aborts telemetry on teardown", async () => {
    const { manager } = fixture();
    let signal: AbortSignal | undefined;
    const fetcher = vi.fn(async (_url: unknown, options?: RequestInit) => {
      signal = options?.signal as AbortSignal;
      return new Response(new ReadableStream({}));
    });
    vi.stubGlobal("fetch", fetcher);
    manager.start();
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/telemetry",
      expect.objectContaining({
        headers: { Authorization: "Bearer private-test-token" },
        cache: "no-store",
      }),
    );
    manager.stop();
    expect(signal?.aborted).toBe(true);
  });
});
