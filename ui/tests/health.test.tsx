import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Management } from "../src/controller";
import { ReactSystemHealth } from "../src/components";
import { isSystemHealth } from "../src/model";
import type { Host, SystemHealth } from "../src/model";

const healthy = (): SystemHealth => ({
  status: "ok",
  clock: {
    unix_seconds: 1793554000,
    utc: "2026-11-01 16:06:40 UTC",
    synchronised: true,
    ntp_configured: false,
    ntp_servers: [],
    service: {
      unit: "chronyd.service",
      load_state: "loaded",
      active_state: "active",
      sub_state: "running",
      result: "success",
      exit_status: 0,
      condition_result: true,
    },
  },
  systemd: { available: true, failed_units: [], error: null },
  network: { default_route: true },
  tpm: {
    present: false,
    devices: [],
    setup: null,
    status: "not-present",
    advice: "Do not clear or reset the TPM.",
  },
  issues: [],
});
const response = (body: unknown) => new Response(JSON.stringify(body));
function fixture() {
  const host: Host = {
    api: vi.fn(async (path) =>
      response(path.endsWith("system/health") ? healthy() : { pending: null }),
    ),
    credential: () => "health-private-test-token",
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
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("shared system health observations", () => {
  it("isolates peer-to-peer health responses and shows actual remote diagnostics", async () => {
    const { manager, host } = fixture();
    host.remote = () => true;
    let member = "fw-a";
    host.member = () => member;
    manager.contextChanged();
    let release!: (response: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    const old = manager.refreshHealth();
    member = "fw-b";
    manager.contextChanged();
    await old;
    const value = healthy();
    value.clock.utc = "2026-11-02 15:00:00 UTC";
    vi.mocked(host.api).mockResolvedValueOnce(response(value));
    await manager.refreshHealth();
    release(
      response({
        ...healthy(),
        clock: { ...healthy().clock, utc: "wrong peer clock" },
      }),
    );
    render(<ReactSystemHealth manager={manager} />);
    expect(screen.getByText(value.clock.utc)).toBeVisible();
    expect(screen.queryByText("wrong peer clock")).toBeNull();
    expect(
      screen.getByRole("button", { name: "Configure NTP" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Retry health check" }),
    ).toBeEnabled();
    expect(host.api).toHaveBeenLastCalledWith(
      "/api/v1/stack/fw-b/system/health",
      expect.anything(),
      10,
    );
  });
  it("does not fetch on component mount and displays explicit unknown/loading states", async () => {
    const { manager, host } = fixture();
    render(<ReactSystemHealth manager={manager} />);
    expect(screen.getByText("Unknown")).toBeVisible();
    expect(screen.getByText(/has not been checked/)).toBeVisible();
    expect(host.api).not.toHaveBeenCalled();
    let release!: (response: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    let pending!: Promise<void>;
    act(() => {
      pending = manager.refreshHealth();
    });
    expect(screen.getByText("Checking system health…")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Retry health check" }),
    ).toBeDisabled();
    await act(async () => {
      release(response(healthy()));
      await pending;
    });
    expect(screen.getByText("Healthy")).toBeVisible();
    expect(
      screen.getByText("None configured; image defaults apply"),
    ).toBeVisible();
    expect(screen.getByText("Synchronised")).toBeVisible();
    expect(screen.getByText("No TPM detected")).toBeVisible();
  });

  it("shows real clock, route and TPM warnings with safe advice on both surfaces", async () => {
    const { manager, host } = fixture();
    const value = healthy();
    value.status = "warning";
    value.clock.synchronised = false;
    value.network.default_route = false;
    value.tpm = {
      ...value.tpm,
      present: true,
      devices: ["/dev/tpm0"],
      status: "warning",
    };
    value.systemd.failed_units = [
      {
        ...value.clock.service!,
        unit: "systemd-tpm2-setup.service",
        active_state: "failed",
        result: "exit-code",
        exit_status: 1,
      },
    ];
    value.issues = [
      {
        code: "clock-unsynchronised",
        severity: "warning",
        message: "The system clock is not synchronised.",
        action: "Configure reachable NTP upstreams.",
      },
      {
        code: "network.no_default_route",
        severity: "warning",
        message:
          "No IPv4/IPv6 default route; external time servers may be unreachable.",
        action: "Configure a gateway or reachable local NTP.",
      },
      {
        code: "tpm-setup-failed",
        severity: "warning",
        message: "TPM initialisation failed.",
        action:
          "Inspect systemd-tpm2-setup.service. Do not clear or reset the TPM.",
      },
    ];
    vi.mocked(host.api).mockResolvedValueOnce(response(value));
    await manager.refreshHealth();
    const { rerender } = render(<ReactSystemHealth manager={manager} />);
    expect(screen.getByText("Needs attention")).toBeVisible();
    expect(screen.getByText(/No IPv4\/IPv6 default route;/)).toBeVisible();
    expect(screen.getByText(/Do not clear or reset the TPM/)).toBeVisible();
    expect(screen.getByText("systemd-tpm2-setup.service")).toBeVisible();
    expect(screen.queryByText("Healthy")).toBeNull();
    rerender(<ReactSystemHealth manager={manager} compact />);
    expect(screen.getByText("TPM initialisation failed.")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Open system health" }));
    expect(host.navigate).toHaveBeenCalledWith("system");
  });

  it("keeps unavailable and malformed observations unknown and offers retry", async () => {
    const { manager, host } = fixture();
    vi.mocked(host.api).mockResolvedValueOnce(response({ status: "ok" }));
    await manager.refreshHealth();
    render(<ReactSystemHealth manager={manager} />);
    expect(screen.getByText("Unknown")).toBeVisible();
    expect(screen.getByText(/System health is unavailable/)).toBeVisible();
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Retry health check" }),
      );
    });
    expect(screen.getByText("Healthy")).toBeVisible();
    vi.mocked(host.api).mockRejectedValueOnce(Error("private-backend-token"));
    await act(() => manager.refreshHealth());
    expect(screen.getByText("Unknown · stale")).toBeVisible();
    expect(screen.getByText("Synchronised")).toBeVisible();
    expect(screen.queryByText(/private-backend-token/)).toBeNull();
    expect(screen.queryByText("Healthy")).toBeNull();
  });

  it("permits read-only diagnostics and navigates to the canonical NTP form without writing", async () => {
    const { manager, host } = fixture();
    host.canWrite = () => false;
    manager.contextChanged();
    await manager.refreshHealth();
    render(<ReactSystemHealth manager={manager} />);
    fireEvent.click(screen.getByRole("button", { name: "Configure NTP" }));
    expect(host.navigate).toHaveBeenCalledWith("services:resolution");
    expect(
      vi
        .mocked(host.api)
        .mock.calls.every(
          ([, options]) => !options?.method || options.method === "GET",
        ),
    ).toBe(true);
  });

  it("withholds local health and invalidates in-flight responses on peer selection and sign-out", async () => {
    const { manager, host } = fixture();
    let release!: (response: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    const pending = manager.refreshHealth();
    host.remote = () => true;
    manager.contextChanged();
    await pending;
    release(response(healthy()));
    render(<ReactSystemHealth manager={manager} />);
    expect(
      screen.getByText(/System health has not been checked yet/),
    ).toBeVisible();
    expect(screen.queryByText("chronyd.service")).toBeNull();
    expect(
      screen.getByRole("button", { name: "Configure NTP" }),
    ).toBeDisabled();
    await manager.refreshHealth();
    expect(host.api).toHaveBeenCalledTimes(2);
    expect(host.api).toHaveBeenLastCalledWith(
      "/api/v1/stack/test-peer/system/health",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
      10,
    );
    host.remote = () => false;
    act(() => manager.contextChanged());
    vi.mocked(host.api).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    let old!: Promise<void>;
    act(() => {
      old = manager.refreshHealth();
      manager.stop();
    });
    await old;
    await act(async () => {
      release(response(healthy()));
      await Promise.resolve();
    });
    expect(manager.getSnapshot().health).toBeNull();
    expect(screen.queryByText("Healthy")).toBeNull();
  });

  it("bounds duplicate and hanging health requests, including adapters that ignore cancellation", async () => {
    vi.useFakeTimers();
    const { manager, host } = fixture();
    vi.mocked(host.api).mockImplementationOnce(() => new Promise(() => {}));
    const pending = manager.refreshHealth();
    await manager.refreshHealth();
    expect(host.api).toHaveBeenCalledTimes(1);
    expect(manager.getSnapshot().healthBusy).toBe(true);
    await vi.advanceTimersByTimeAsync(10000);
    await pending;
    expect(manager.getSnapshot().healthBusy).toBe(false);
    expect(manager.getSnapshot().health).toBeNull();
    expect(manager.getSnapshot().healthError).toContain("unavailable");
    await manager.refreshHealth();
    expect(manager.getSnapshot().health?.status).toBe("ok");
  });

  it("starts and polls every 15 seconds only through the shared controller", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(new ReadableStream())),
    );
    const { manager, host } = fixture();
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(
      vi
        .mocked(host.api)
        .mock.calls.filter(([path]) => path.endsWith("system/health")),
    ).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(15000);
    expect(
      vi
        .mocked(host.api)
        .mock.calls.filter(([path]) => path.endsWith("system/health")),
    ).toHaveLength(2);
    manager.stop();
    await vi.advanceTimersByTimeAsync(15000);
    expect(
      vi
        .mocked(host.api)
        .mock.calls.filter(([path]) => path.endsWith("system/health")),
    ).toHaveLength(2);
  });

  it("validates nullable unknowns and rejects missing or malformed observations", () => {
    expect(isSystemHealth(healthy())).toBe(true);
    const unknown = healthy();
    unknown.status = "unknown";
    unknown.clock.synchronised = null;
    unknown.clock.ntp_configured = null;
    unknown.clock.ntp_servers = null;
    unknown.clock.service = null;
    unknown.systemd = {
      available: false,
      failed_units: null,
      error: "probe unavailable",
    };
    unknown.network.default_route = null;
    expect(isSystemHealth(unknown)).toBe(true);
    for (const value of [
      null,
      [],
      { status: "ok" },
      { ...healthy(), clock: { ...healthy().clock, synchronised: "yes" } },
      {
        ...healthy(),
        systemd: { available: true, failed_units: [null], error: null },
      },
    ])
      expect(isSystemHealth(value)).toBe(false);
    expect(
      isSystemHealth({
        ...healthy(),
        clock: { ...healthy().clock, synchronised: false },
      }),
    ).toBe(false);
    expect(
      isSystemHealth({
        ...healthy(),
        systemd: { ...healthy().systemd, available: false },
      }),
    ).toBe(false);
  });
});
