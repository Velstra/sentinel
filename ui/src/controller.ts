import { emptyEditor, initialState, isTelemetry, sseFrames } from "./model";
import type { Host, Pending, StagedChange, State, Telemetry } from "./model";

export class Management {
  private state = initialState();
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private abort: AbortController | null = null;
  private epoch = 0;
  private polling = false;
  private transactionGeneration = 0;
  private appliedCandidate: string | null = null;
  private batch: { id: string; changes: StagedChange[] } | null = null;
  private completedId: string | null = null;
  constructor(private host: Host) {}
  getSnapshot = () => this.state;
  navigate = (destination: Parameters<Host["navigate"]>[0]) =>
    this.host.navigate(destination);
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  private update(patch: Partial<State>) {
    this.state = { ...this.state, ...patch };
    for (const notify of this.listeners) notify();
  }
  private edit(patch: Partial<State["editor"]>) {
    this.update({ editor: { ...this.state.editor, ...patch } });
  }
  contextChanged = () => {
    const writable = this.host.canWrite(),
      remote = this.host.remote();
    if (writable !== this.state.writable || remote !== this.state.remote)
      this.update({ writable, remote });
    // Revoke revealed documents when write access is lost. A peer view hides
    // the local editor while retaining its in-memory draft for the local member.
    if (!writable && this.state.editor.visible) this.clearEditor();
  };
  private writable() {
    return this.host.canWrite() && !this.host.remote();
  }
  private async json<T>(path: string, body?: unknown): Promise<T> {
    const options =
      body === undefined
        ? undefined
        : {
            method: "POST",
            headers: {
              Authorization: "Bearer " + this.host.credential(),
              "Content-Type": "application/json",
            },
            body: JSON.stringify(body),
          };
    return (
      await this.host.api(
        "/api/v1/" + path,
        options,
        body === undefined ? 30 : 120,
      )
    ).json() as Promise<T>;
  }
  setPending = (pending: Pending | null) => {
    this.transactionGeneration++;
    this.update({
      pending: pending || null,
      deadline: pending
        ? performance.now() + Math.max(0, pending.remaining_seconds) * 1000
        : 0,
      now: performance.now(),
    });
  };
  rememberBatch = (pending: Pending | undefined, changes: StagedChange[]) => {
    if (pending)
      this.batch = {
        id: pending.id,
        changes: changes.map((c) => ({ label: c.label, cmds: [...c.cmds] })),
      };
  };
  private complete(id: string, outcome: string) {
    if (this.completedId === id) return;
    this.completedId = id;
    const confirmed = outcome === "confirmed";
    const message = confirmed
      ? "Configuration confirmed and saved."
      : outcome === "apply-failed"
        ? "Application failed. The previous working configuration was restored; review the retained changes before retrying."
        : outcome === "recovery-abandoned"
          ? "Transaction ended. The saved configuration is unchanged; the live network was accepted as it is."
          : "Previous working configuration restored. Your proposed changes remain available for review.";
    if (this.batch?.id === id) {
      if (!confirmed)
        for (const change of this.batch.changes)
          if (!this.host.staged().some((c) => c.label === change.label))
            this.host.restore(change);
      this.batch = null;
    }
    const e = this.state.editor;
    if (
      confirmed &&
      (e.candidate === e.baseline ||
        (this.appliedCandidate !== null &&
          e.candidate === this.appliedCandidate))
    )
      this.clearEditor();
    else if (e.revision && e.candidate !== e.baseline) {
      this.host.dirty(true);
      this.edit({
        feedback:
          message + " Reload the current baseline before applying again.",
        uncertain: false,
      });
    }
    this.appliedCandidate = null;
    this.host.completed(id, outcome, message);
    this.host.notice(message);
  }
  refreshTransaction = async () => {
    if (!this.host.credential() || this.polling) return;
    const epoch = this.epoch,
      generation = this.transactionGeneration;
    this.polling = true;
    try {
      const result = await this.json<{
        pending: Pending | null;
        last_result?: { id: string; outcome: string };
      }>("config/transaction");
      if (epoch !== this.epoch || generation !== this.transactionGeneration)
        return;
      const previous = this.state.pending;
      this.setPending(result.pending);
      this.update({ transactionError: "" });
      const finished = previous?.id || this.batch?.id;
      if (!result.pending && finished && result.last_result?.id === finished)
        this.complete(finished, result.last_result.outcome);
      if (result.pending && this.state.editor.uncertain)
        this.edit({ uncertain: false });
    } catch {
      if (epoch === this.epoch)
        this.update({
          transactionError:
            "The appliance is unreachable. Recovery runs independently; reconnect before the deadline to confirm.",
        });
    } finally {
      if (epoch === this.epoch) this.polling = false;
    }
  };
  finishTransaction = async (
    action: "confirm" | "revert" | "recovery/accept",
  ) => {
    const pending = this.state.pending;
    if (
      !pending ||
      this.state.confirming ||
      !this.writable() ||
      (action === "confirm" &&
        (!pending.ready || this.state.deadline <= performance.now())) ||
      // Accepting the live network is the way out of a recovery that gave
      // up, never a shortcut past one that may still succeed.
      (action === "recovery/accept") !== !!pending.recovery_failed
    )
      return;
    const epoch = this.epoch;
    this.update({ confirming: true });
    try {
      const result = await this.json<{ reverting?: boolean }>(
        "config/" + action,
        { id: pending.id },
      );
      if (epoch !== this.epoch) return;
      if (result.reverting) {
        this.setPending({ ...pending, reverting: true });
        await this.refreshTransaction();
        this.host.notice(
          "Rollback requested. Recovery continues independently of this connection.",
        );
      } else {
        this.setPending(null);
        this.complete(
          pending.id,
          action === "confirm"
            ? "confirmed"
            : action === "revert"
              ? "reverted"
              : "recovery-abandoned",
        );
        await this.host.refresh();
      }
    } catch (e) {
      if (epoch !== this.epoch) return;
      this.update({ transactionError: message(e) });
      await this.refreshTransaction();
    } finally {
      if (epoch === this.epoch) this.update({ confirming: false });
    }
  };
  clearEditor = () => {
    this.host.dirty(false);
    this.update({ editor: emptyEditor() });
  };
  hideEditor = () => {
    if (this.state.editor.busy) return;
    if (this.state.editor.candidate !== this.state.editor.baseline) {
      this.edit({
        feedback:
          "The TOML draft has unsaved changes. Apply it or restore the current document before hiding it.",
      });
      return;
    }
    this.clearEditor();
  };
  changeCandidate = (candidate: string) => {
    if (this.state.editor.busy) return;
    this.host.dirty(candidate !== this.state.editor.baseline);
    this.edit({
      candidate,
      invalid: false,
      diff: "",
      feedback:
        candidate === this.state.editor.baseline
          ? "No changes."
          : "Draft changed. Validate against the appliance schema before applying.",
    });
  };
  loadEditor = async (preserveDraft = false) => {
    if (this.state.editor.busy || !this.writable()) return;
    const epoch = this.epoch;
    this.edit({ busy: true });
    try {
      const document = await this.json<{ toml: string; revision: string }>(
        "config/document",
      );
      if (epoch !== this.epoch || !this.writable()) return;
      const candidate = preserveDraft
        ? this.state.editor.candidate
        : document.toml;
      this.host.dirty(candidate !== document.toml);
      this.edit({
        baseline: document.toml,
        candidate,
        revision: document.revision,
        visible: true,
        invalid: false,
        diff: "",
        uncertain: false,
        feedback: preserveDraft
          ? "Current baseline reloaded. Your draft is preserved; review the side-by-side changes before applying."
          : "No changes. Secrets are visible only in this tab.",
      });
    } catch (e) {
      if (epoch === this.epoch) this.edit({ feedback: message(e) });
    } finally {
      if (epoch === this.epoch) this.edit({ busy: false });
    }
  };
  submitEditor = async (validateOnly: boolean) => {
    const editor = this.state.editor;
    if (
      editor.busy ||
      !editor.revision ||
      !this.writable() ||
      this.state.pending ||
      editor.uncertain
    )
      return;
    if (this.host.staged().length) {
      this.edit({
        feedback:
          "Apply or discard the staged form changes before submitting a complete TOML revision.",
      });
      return;
    }
    const epoch = this.epoch;
    this.edit({ busy: true });
    try {
      const result = await this.json<{ diff?: string; pending?: Pending }>(
        "config/document",
        {
          toml: editor.candidate,
          expected_revision: editor.revision,
          validate_only: validateOnly,
        },
      );
      if (epoch !== this.epoch) return;
      this.edit({
        invalid: false,
        diff: result.diff || "No changes.",
        feedback: validateOnly
          ? "Valid configuration. Nothing applied."
          : result.pending?.ready
            ? "Applied provisionally. Verify connectivity and use Keep change before the rollback deadline."
            : "Application accepted. The independent worker is reconciling; confirmation becomes available when it completes.",
      });
      if (result.pending) {
        this.appliedCandidate = editor.candidate;
        this.setPending(result.pending);
      }
      if (!validateOnly) this.host.dirty(false);
    } catch (e) {
      if (epoch !== this.epoch) return;
      const status =
        typeof e === "object" && e !== null && "status" in e
          ? Number(e.status)
          : 0;
      this.edit({
        invalid: status === 400,
        uncertain: !validateOnly && !status,
        feedback:
          message(e) +
          (!validateOnly && !status
            ? " The operation may have started. Reconnect and reload the current baseline before retrying."
            : ""),
      });
      await this.refreshTransaction();
    } finally {
      if (epoch === this.epoch) this.edit({ busy: false });
    }
  };
  acceptFrame = (frame: Telemetry) => {
    // The route table arrives once per change; an unchanged frame keeps it.
    const routes = frame.routing?.routes_unchanged
      ? this.state.frame?.routing?.routes
      : frame.routing?.routes;
    // The collector is authoritative, but its bounded window is enforced again at this boundary.
    this.update({
      frame: {
        ...frame,
        events: frame.events.slice(-512),
        ...(frame.routing ? { routing: { ...frame.routing, routes } } : {}),
      },
      receivedAt: performance.now(),
      connected: true,
      status: "Live telemetry connected.",
    });
  };
  private async consume(signal: AbortSignal, epoch: number) {
    let delay = 1000;
    while (!signal.aborted && epoch === this.epoch) {
      // One controller per connection. A half-open link never errors and
      // never ends, so the read below would wait forever; silence past the
      // staleness window aborts this connection (not the session) instead.
      const connection = new AbortController(),
        forward = () => connection.abort();
      signal.addEventListener("abort", forward, { once: true });
      let heard = performance.now();
      const watchdog = setInterval(() => {
        if (performance.now() - heard > STALE_MS) connection.abort();
      }, 1000);
      try {
        const response = await fetch("/api/v1/telemetry", {
          headers: { Authorization: "Bearer " + this.host.credential() },
          cache: "no-store",
          signal: connection.signal,
        });
        if (response.status === 401) {
          this.host.signOut("That token was not accepted.");
          return;
        }
        if (!response.ok || !response.body)
          throw Error("Telemetry HTTP " + response.status);
        for await (const value of sseFrames(response.body, connection.signal)) {
          if (signal.aborted || epoch !== this.epoch) return;
          if (isTelemetry(value)) {
            heard = performance.now();
            this.acceptFrame(value);
            delay = 1000;
          }
        }
        if (signal.aborted) return;
        throw Error("Telemetry connection closed");
      } catch {
        if (signal.aborted || epoch !== this.epoch) return;
        this.update({
          connected: false,
          status:
            "Telemetry disconnected; displayed values are stale. Reconnecting…",
        });
        await wait(delay, signal);
        delay = Math.min(15000, delay * 2);
      } finally {
        clearInterval(watchdog);
        signal.removeEventListener("abort", forward);
      }
    }
  }
  start = () => {
    this.stop();
    this.contextChanged();
    const epoch = this.epoch;
    void this.refreshTransaction();
    this.abort = new AbortController();
    void this.consume(this.abort.signal, epoch);
    let tick = 0;
    this.timer = setInterval(() => {
      const now = performance.now();
      this.update({
        now,
        ...(this.state.frame && now - this.state.receivedAt > STALE_MS
          ? {
              connected: false,
              status: "Telemetry is stale. Waiting for a fresh sample…",
            }
          : {}),
      });
      this.contextChanged();
      if (++tick % 5 === 0) void this.refreshTransaction();
    }, 1000);
  };
  stop = () => {
    this.epoch++;
    this.abort?.abort();
    this.abort = null;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.polling = false;
    this.batch = null;
    this.completedId = null;
    this.appliedCandidate = null;
    this.transactionGeneration++;
    this.host.dirty(false);
    this.update(initialState());
  };
  abortTelemetry = () => {
    this.abort?.abort();
  };
}
/** Silence after which telemetry is stale and its connection is replaced. */
const STALE_MS = 15000;
function message(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
function wait(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    const timer = setTimeout(finish, ms);
    function finish() {
      clearTimeout(timer);
      signal.removeEventListener("abort", finish);
      resolve();
    }
    signal.addEventListener("abort", finish, { once: true });
    if (signal.aborted) finish();
  });
}
