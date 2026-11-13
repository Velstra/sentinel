import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Management } from "../src/controller";
import { SystemUpdates } from "../src/updates-view";
import { isUpdateStatus } from "../src/updates";
import type { UpdateStatus, UpdateJob } from "../src/updates";
import type { Host } from "../src/model";

const hash = (c: string) => c.repeat(64);
const status = (): UpdateStatus => ({
  schema: 1,
  generation: hash("a"),
  mutation_context: {
    boot_id: "b",
    mutation_epoch: hash("c"),
    config_revision: hash("d"),
    public_key_sha256: hash("e"),
    release: "v0.9.0",
    slot: "sentinel-a",
    verity: hash("f"),
    selected_entry: "sentinel-a.conf",
    next_entry: "sentinel-a.conf",
    uki_sha256: hash("1"),
    verity_guid: "v",
    store_guid: "s",
    permanent: true,
  },
  current: {
    boot_id: "boot-current",
    release: "v0.9.0",
    slot: "sentinel-a",
    permanent: true,
    selected_entry: "sentinel-a.conf",
    next_entry: "sentinel-a.conf",
  },
  offer: {
    id: hash("b"),
    verified: {
      manifest: {
        version: "v1.0.0",
        image: "sentinel_v1.0.0.raw",
        sha256: hash("2"),
      },
      manifest_sha256: hash("3"),
      public_key_sha256: hash("e"),
    },
  },
  jobs: [],
  can_check: true,
  can_stage: true,
  unavailable: null,
  observation: { state: "fresh", age_ms: 0 },
});
const response = (v: unknown) => new Response(JSON.stringify(v));
function fixture() {
  const host: Host = {
    api: vi.fn(async () => response(status())),
    credential: () => "disposable-token",
    canWrite: () => true,
    remote: () => false,
    member: () => "",
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
  return { manager, host, updates: manager.updates };
}
const checkButton = () =>
  screen.getByRole("button", { name: "Check signed channel" });
const reviewButton = () =>
  screen.getByRole("button", { name: "Review available update" });
const stageButton = () =>
  screen.getByRole("button", { name: "Download & stage update" });
const job = (request_id: string, phase = "accepted"): UpdateJob => ({
  id: hash("8"),
  request_id,
  boot_id: "boot-current",
  action: "stage",
  phase,
  error: null,
  message: null,
});
afterEach(() => vi.useRealTimers());

describe("operational local update console", () => {
  it("does not fetch on mount or offer mutations without a current observation", () => {
    const { manager, host } = fixture();
    render(<SystemUpdates manager={manager} />);
    expect(host.api).not.toHaveBeenCalled();
    expect(checkButton()).toBeDisabled();
    expect(reviewButton()).toBeDisabled();
    expect(screen.getByText("No retained jobs available.")).toBeVisible();
  });
  it("shows exact running identity and requires explicit review before Stage", async () => {
    const { manager, updates, host } = fixture();
    render(<SystemUpdates manager={manager} />);
    await act(() => updates.refresh());
    expect(screen.getByText("Slot A")).toBeVisible();
    expect(screen.getByText("Permanent")).toBeVisible();
    await act(() => updates.submit("stage"));
    expect(host.api).toHaveBeenCalledTimes(1);
    fireEvent.click(reviewButton());
    expect(
      screen.getByRole("region", { name: "Review signed update" }),
    ).toBeVisible();
    expect(screen.getByText(hash("2"))).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Cancel update review" }),
    );
    expect(
      screen.queryByRole("region", { name: "Review signed update" }),
    ).toBeNull();
  });
  it("submits exactly one reviewed offer with its CAS context, never an override or reboot", async () => {
    const { manager, updates, host } = fixture();
    let result = status();
    vi.mocked(host.api).mockImplementation(async (_path, options) => {
      if (options?.method === "POST") {
        const body = JSON.parse(String(options.body));
        result = {
          ...status(),
          can_stage: false,
          can_check: false,
          generation: hash("9"),
          jobs: [job(body.request_id)],
        };
        return response(result.jobs[0]);
      }
      return response(result);
    });
    render(<SystemUpdates manager={manager} />);
    await act(() => updates.refresh());
    fireEvent.click(reviewButton());
    await act(async () => {
      fireEvent.click(stageButton());
      await updates.submit("stage");
    });
    const calls = vi
      .mocked(host.api)
      .mock.calls.filter(([, o]) => o?.method === "POST");
    expect(calls).toHaveLength(1);
    const [path, options] = calls[0];
    expect(path).toBe("/api/v1/system/updates/stage");
    expect(options?.headers).toEqual({
      "Content-Type": "application/json",
      Authorization: "Bearer disposable-token",
    });
    expect(JSON.parse(String(options?.body))).toEqual({
      request_id: expect.stringMatching(/^[a-f0-9]{64}$/),
      expected_generation: hash("a"),
      expected: status().mutation_context,
      offer_id: hash("b"),
    });
    expect(reviewButton()).toBeDisabled();
    expect(screen.getByText("stage · accepted")).toBeVisible();
  });
  it("invalidates review when config, signing context, offer or generation changes", async () => {
    const { updates, host } = fixture();
    for (const changed of [
      { ...status(), generation: hash("7") },
      {
        ...status(),
        mutation_context: {
          ...status().mutation_context,
          config_revision: hash("7"),
        },
      },
      { ...status(), offer: { ...status().offer!, id: hash("7") } },
    ]) {
      vi.mocked(host.api).mockResolvedValueOnce(response(status()));
      await updates.refresh();
      updates.review();
      expect(updates.getSnapshot().review).not.toBeNull();
      vi.mocked(host.api).mockResolvedValueOnce(response(changed));
      await updates.refresh();
      expect(updates.getSnapshot().review).toBeNull();
      await updates.submit("stage");
    }
    expect(
      vi.mocked(host.api).mock.calls.filter(([, o]) => o?.method === "POST"),
    ).toHaveLength(0);
  });
  it("withholds writes on stale, refreshing, unavailable, pending config or staged drafts", async () => {
    const { updates, host } = fixture();
    for (const state of [
      "initializing",
      "refreshing",
      "stale",
      "unavailable",
    ]) {
      vi.mocked(host.api).mockResolvedValueOnce(
        response({ ...status(), observation: { state, age_ms: 0 } }),
      );
      await updates.refresh();
      expect(updates.permitted("check")).toBe(false);
      expect(updates.permitted("stage")).toBe(false);
    }
    await updates.refresh();
    host.staged = () => [
      { label: "draft", cmds: ["set system hostname pending"] },
    ];
    expect(updates.permitted("check")).toBe(false);
    host.staged = () => [];
    expect(updates.permitted("check")).toBe(true);
    vi.spyOn(performance, "now").mockReturnValueOnce(
      updates.getSnapshot().receivedAt + 6000,
    );
    expect(updates.permitted("check")).toBe(false);
  });
  it("read-only accounts observe but never check or stage", async () => {
    const { manager, updates, host } = fixture();
    host.canWrite = () => false;
    manager.contextChanged();
    render(<SystemUpdates manager={manager} />);
    await act(() => updates.refresh());
    expect(checkButton()).toBeDisabled();
    expect(reviewButton()).toBeDisabled();
    expect(screen.getByText(/Read-only access/)).toBeVisible();
    await updates.submit("check");
    expect(host.api).toHaveBeenCalledTimes(1);
  });
  it("revokes local observations and ignores delayed replies after member or credential changes", async () => {
    const { manager, updates, host } = fixture();
    let release!: (v: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    const pending = updates.refresh();
    host.remote = () => true;
    host.member = () => "fw-b";
    manager.contextChanged();
    release(response(status()));
    await pending;
    expect(updates.getSnapshot().status).toBeNull();
    await updates.refresh();
    render(<SystemUpdates manager={manager} />);
    expect(screen.getByText(/Select the local member/)).toBeVisible();
    expect(host.api).toHaveBeenCalledTimes(1);
  });
  it("never retries a lost POST and correlates the durable job through read-only refresh", async () => {
    const { updates, host } = fixture();
    await updates.refresh();
    updates.review();
    let correlation = "";
    vi.mocked(host.api).mockImplementation(async (_path, options) => {
      if (options?.method === "POST") {
        correlation = JSON.parse(String(options.body)).request_id;
        throw Error("upstream-secret-never-rendered");
      }
      return response(status());
    });
    await updates.submit("stage");
    await updates.refresh();
    expect(updates.getSnapshot().uncertain).toBe(correlation);
    expect(updates.permitted("check")).toBe(false);
    expect(updates.getSnapshot().error).not.toContain("upstream-secret");
    await updates.submit("stage");
    vi.mocked(host.api).mockResolvedValueOnce(
      response({ ...status(), jobs: [job(correlation)] }),
    );
    await updates.refresh();
    expect(updates.getSnapshot().uncertain).toBe("");
    expect(
      vi.mocked(host.api).mock.calls.filter(([, o]) => o?.method === "POST"),
    ).toHaveLength(1);
  });
  it("handles the actual shell's thrown HTTP refusals without displaying upstream bodies", async () => {
    const { updates, host } = fixture();
    await updates.refresh();
    vi.mocked(host.api).mockRejectedValueOnce(
      Object.assign(Error("private-upstream-body"), { status: 409 }),
    );
    await updates.submit("check");
    expect(updates.getSnapshot().uncertain).toBe("");
    expect(updates.getSnapshot().error).toMatch(/Request refused/);
  });
  it("renders write-outcome-unknown as a warning, never as staged or reboot-safe", async () => {
    const { manager, updates, host } = fixture();
    vi.mocked(host.api).mockResolvedValueOnce(
      response({
        ...status(),
        can_stage: false,
        jobs: [
          {
            ...job(hash("6"), "interrupted"),
            error: "write-outcome-unknown",
            message: "Inspect boot selection before rebooting.",
          },
        ],
      }),
    );
    render(<SystemUpdates manager={manager} />);
    await act(() => updates.refresh());
    expect(
      screen.getByText("Inspect boot selection before rebooting."),
    ).toBeVisible();
    expect(screen.queryByText(/Image staged/)).toBeNull();
    expect(reviewButton()).toBeDisabled();
  });
  it("distinguishes retained staging history from the independently assessed current boot", async () => {
    const { manager, updates, host } = fixture();
    render(<SystemUpdates manager={manager} />);
    vi.mocked(host.api).mockResolvedValueOnce(
      response({ ...status(), jobs: [job(hash("6"), "staged")] }),
    );
    await act(() => updates.refresh());
    expect(screen.getByText(/Image staged during this boot/)).toBeVisible();
    for (const slot of ["sentinel-a", "sentinel-b"]) {
      vi.mocked(host.api).mockResolvedValueOnce(
        response({
          ...status(),
          current: { ...status().current, boot_id: "boot-after-restart", slot },
          jobs: [job(hash("6"), "staged")],
        }),
      );
      await act(() => updates.refresh());
      expect(
        screen.getByText(/Stage recorded on a previous boot/),
      ).toBeVisible();
      expect(screen.queryByText(/Image staged during this boot/)).toBeNull();
      expect(screen.getByText("Permanent")).toBeVisible();
    }
  });
  it("restores keyboard focus to the review action after cancelling", async () => {
    const { manager, updates } = fixture();
    render(<SystemUpdates manager={manager} />);
    await act(() => updates.refresh());
    fireEvent.click(reviewButton());
    const cancel = screen.getByRole("button", { name: "Cancel update review" });
    cancel.focus();
    fireEvent.click(cancel);
    expect(reviewButton()).toHaveFocus();
  });
  it("returns focus to the panel if observation refresh temporarily disables the trigger", async () => {
    const { manager, updates, host } = fixture();
    render(<SystemUpdates manager={manager} />);
    await act(() => updates.refresh());
    fireEvent.click(reviewButton());
    let release!: (response: Response) => void;
    vi.mocked(host.api).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    let pending!: Promise<void>;
    act(() => {
      pending = updates.refresh();
    });
    const cancel = screen.getByRole("button", { name: "Cancel update review" });
    cancel.focus();
    fireEvent.click(cancel);
    expect(
      screen.getByRole("region", { name: "System updates" }),
    ).toHaveFocus();
    await act(async () => {
      release(response(status()));
      await pending;
    });
  });
  it("does not infer an unbooted image when current boot identity is unavailable", async () => {
    const { manager, updates, host } = fixture();
    render(<SystemUpdates manager={manager} />);
    vi.mocked(host.api).mockResolvedValueOnce(
      response({
        ...status(),
        current: null,
        mutation_context: null,
        can_check: false,
        can_stage: false,
        jobs: [job(hash("6"), "staged")],
      }),
    );
    await act(() => updates.refresh());
    expect(
      screen.getByText("Stage completed. Current boot state is unavailable."),
    ).toBeVisible();
    expect(screen.queryByText(/Image staged during this boot/)).toBeNull();
  });
  it("rejects malformed status envelopes instead of inventing healthy or writable state", () => {
    for (const value of [
      null,
      {},
      { ...status(), jobs: [{}] },
      { ...status(), current: {} },
      { ...status(), current: null },
      { ...status(), offer: null },
      { ...status(), observation: { state: "fresh", age_ms: -1 } },
      { ...status(), mutation_context: { source: "override" } },
    ])
      expect(isUpdateStatus(value)).toBe(false);
    expect(isUpdateStatus(status())).toBe(true);
  });
  it("bounds reads and uncertain admissions even when a transport ignores cancellation", async () => {
    vi.useFakeTimers();
    const { updates, host } = fixture();
    vi.mocked(host.api).mockImplementationOnce(() => new Promise(() => {}));
    const reading = updates.refresh();
    await vi.advanceTimersByTimeAsync(10001);
    await reading;
    expect(updates.getSnapshot().busy).toBe(false);
    expect(updates.getSnapshot().error).toMatch(/unavailable/);
    await updates.refresh();
    updates.review();
    vi.mocked(host.api).mockImplementationOnce(() => new Promise(() => {}));
    const writing = updates.submit("stage");
    await vi.advanceTimersByTimeAsync(35001);
    await writing;
    expect(updates.getSnapshot().sending).toBe(false);
    expect(updates.getSnapshot().uncertain).toMatch(/^[a-f0-9]{64}$/);
    expect(updates.permitted("stage")).toBe(false);
  });
});
