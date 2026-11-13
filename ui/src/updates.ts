import type { Host } from "./model";

type Action = "check" | "stage";
type Context = Record<string, string | boolean>;
export interface UpdateJob {
  id: string;
  request_id: string;
  action: Action;
  phase: string;
  error: string | null;
  message: string | null;
}
export interface UpdateStatus {
  schema: number;
  generation: string | null;
  mutation_context: Context | null;
  current: null | {
    release: string;
    slot: string;
    permanent: boolean;
    selected_entry: string;
    next_entry: string;
  };
  offer: null | {
    id: string;
    verified: {
      manifest: { version: string; image: string; sha256: string };
      manifest_sha256: string;
      public_key_sha256: string;
    };
  };
  jobs: UpdateJob[];
  can_check: boolean;
  can_stage: boolean;
  unavailable: string | null;
  observation: { state: string; age_ms: number | null };
}
export const terminal = (phase: string) =>
  ["checked", "staged", "failed", "interrupted"].includes(phase);
const record = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string =>
  typeof v === "string" && v.length <= 512;
const id = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const nullableText = (v: unknown) => v === null || text(v);
async function abortable<T>(
  promise: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  let rejectAbort!: () => void;
  const interrupted = new Promise<never>((_, reject) => {
    rejectAbort = () => reject(Error("Request interrupted"));
    signal.addEventListener("abort", rejectAbort, { once: true });
    if (signal.aborted) rejectAbort();
  });
  try {
    return await Promise.race([promise, interrupted]);
  } finally {
    signal.removeEventListener("abort", rejectAbort);
  }
}
export function isUpdateJob(v: unknown): v is UpdateJob {
  return (
    record(v) &&
    id(v.id) &&
    id(v.request_id) &&
    ["check", "stage"].includes(String(v.action)) &&
    [
      "accepted",
      "metadata",
      "downloading",
      "verifying",
      "preflight",
      "writing",
      "publishing",
      "checked",
      "staged",
      "failed",
      "interrupted",
    ].includes(String(v.phase)) &&
    nullableText(v.error) &&
    nullableText(v.message)
  );
}
export function isUpdateStatus(v: unknown): v is UpdateStatus {
  if (!record(v)) return false;
  const { current, offer, observation, mutation_context: context } = v;
  const contextKeys = [
    "boot_id",
    "mutation_epoch",
    "config_revision",
    "public_key_sha256",
    "release",
    "slot",
    "verity",
    "selected_entry",
    "next_entry",
    "uki_sha256",
    "verity_guid",
    "store_guid",
  ];
  return (
    v.schema === 1 &&
    (v.generation === null || id(v.generation)) &&
    (context === null ||
      (record(context) &&
        contextKeys.every((k) => text(context[k])) &&
        typeof context.permanent === "boolean" &&
        Object.keys(context).length === 13)) &&
    (current === null ||
      (record(current) &&
        [current.release, current.selected_entry, current.next_entry].every(
          text,
        ) &&
        ["sentinel-a", "sentinel-b"].includes(String(current.slot)) &&
        typeof current.permanent === "boolean")) &&
    (offer === null ||
      (record(offer) &&
        id(offer.id) &&
        record(offer.verified) &&
        id(offer.verified.manifest_sha256) &&
        id(offer.verified.public_key_sha256) &&
        record(offer.verified.manifest) &&
        text(offer.verified.manifest.version) &&
        text(offer.verified.manifest.image) &&
        text(offer.verified.manifest.sha256))) &&
    Array.isArray(v.jobs) &&
    v.jobs.length <= 9 &&
    v.jobs.every(isUpdateJob) &&
    typeof v.can_check === "boolean" &&
    typeof v.can_stage === "boolean" &&
    nullableText(v.unavailable) &&
    record(observation) &&
    ["initializing", "fresh", "refreshing", "stale", "unavailable"].includes(
      String(observation.state),
    ) &&
    (observation.age_ms === null ||
      (typeof observation.age_ms === "number" &&
        Number.isFinite(observation.age_ms) &&
        observation.age_ms >= 0)) &&
    (!(v.can_check || v.can_stage) ||
      (id(v.generation) && record(context) && record(current))) &&
    (!v.can_stage ||
      (record(offer) &&
        record(current) &&
        current.permanent === true &&
        current.selected_entry === current.next_entry))
  );
}

interface State {
  status: UpdateStatus | null;
  receivedAt: number;
  busy: boolean;
  sending: boolean;
  error: string;
  notice: string;
  uncertain: string;
  review: UpdateStatus | null;
  writable: boolean;
  remote: boolean;
  now: number;
}
const empty = (): State => ({
  status: null,
  receivedAt: 0,
  busy: false,
  sending: false,
  error: "",
  notice: "",
  uncertain: "",
  review: null,
  writable: false,
  remote: false,
  now: performance.now(),
});
export class Updates {
  private state = empty();
  private listeners = new Set<() => void>();
  private epoch = 0;
  private context = "";
  private read: AbortController | null = null;
  private write: AbortController | null = null;
  constructor(
    private host: Host,
    private configBusy: () => boolean,
  ) {}
  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  private set(patch: Partial<State>) {
    this.state = { ...this.state, ...patch };
    for (const listener of this.listeners) listener();
  }
  contextChanged = () => {
    const context = JSON.stringify([
      this.host.credential(),
      this.host.remote(),
      this.host.member(),
      this.host.canWrite(),
    ]);
    if (context !== this.context) {
      this.context = context;
      this.epoch++;
      this.read?.abort();
      this.read = null;
      this.write?.abort();
      this.write = null;
      this.set({
        ...empty(),
        writable: this.host.canWrite(),
        remote: this.host.remote(),
      });
    }
    if (this.configBusy() && this.state.review) this.set({ review: null });
    this.set({ now: performance.now() });
  };
  stop = () => {
    this.epoch++;
    this.read?.abort();
    this.read = null;
    this.write?.abort();
    this.write = null;
    this.context = "";
    this.set(empty());
  };
  fresh = () =>
    !!this.state.status &&
    this.state.status.observation.state === "fresh" &&
    this.state.status.observation.age_ms !== null &&
    this.state.status.observation.age_ms <= 5000 &&
    performance.now() - this.state.receivedAt <= 5000;
  permitted = (action: Action) =>
    !this.host.remote() &&
    this.host.canWrite() &&
    !!this.host.credential() &&
    !this.configBusy() &&
    !this.state.sending &&
    !this.state.busy &&
    !this.state.uncertain &&
    this.fresh() &&
    !!this.state.status?.[action === "check" ? "can_check" : "can_stage"];
  refresh = async () => {
    if (
      this.read ||
      this.state.sending ||
      !this.host.credential() ||
      this.host.remote()
    )
      return;
    const epoch = this.epoch,
      abort = new AbortController();
    this.read = abort;
    this.set({ busy: true });
    const timer = setTimeout(() => abort.abort(), 10000);
    try {
      const response = await abortable(
        this.host.api("/api/v1/system/updates", { signal: abort.signal }, 10),
        abort.signal,
      );
      if (epoch !== this.epoch) return;
      if (response.status === 401) {
        this.host.signOut("That token was not accepted.");
        return;
      }
      if (!response.ok)
        throw Error(
          "Update observations unavailable. Refresh to inspect retained jobs.",
        );
      const value: unknown = await abortable(response.json(), abort.signal);
      if (epoch !== this.epoch || abort.signal.aborted) return;
      if (!isUpdateStatus(value))
        throw Error("Invalid update observation; no update is authorized.");
      const found =
        this.state.uncertain &&
        value.jobs.find((j) => j.request_id === this.state.uncertain);
      const reviewed = this.state.review;
      this.set({
        status: value,
        receivedAt: performance.now(),
        now: performance.now(),
        error:
          !found &&
          (this.state.uncertain ||
            this.state.error.startsWith("Request refused."))
            ? this.state.error
            : "",
        ...(found
          ? {
              uncertain: "",
              notice: "The retained job was recovered. No request was retried.",
            }
          : {}),
        review:
          reviewed &&
          reviewed.generation === value.generation &&
          JSON.stringify(reviewed.mutation_context) ===
            JSON.stringify(value.mutation_context) &&
          reviewed.offer?.id === value.offer?.id &&
          value.can_stage &&
          value.observation.state === "fresh"
            ? reviewed
            : null,
      });
    } catch {
      if (epoch === this.epoch)
        this.set({
          error:
            "Update observations unavailable. Refresh to inspect retained jobs.",
          review: null,
        });
    } finally {
      clearTimeout(timer);
      if (epoch === this.epoch) {
        this.read = null;
        this.set({ busy: false });
      }
    }
  };
  review = () => {
    if (this.permitted("stage"))
      this.set({ review: this.state.status, notice: "" });
  };
  cancelReview = () => this.set({ review: null });
  submit = async (action: Action) => {
    if (!this.permitted(action)) return;
    const status = action === "stage" ? this.state.review : this.state.status;
    if (
      !status ||
      !status.generation ||
      !status.mutation_context ||
      (action === "stage" &&
        status.generation !== this.state.status?.generation)
    )
      return;
    const requestId = Array.from(
      crypto.getRandomValues(new Uint8Array(32)),
      (b) => b.toString(16).padStart(2, "0"),
    ).join("");
    const body = {
      request_id: requestId,
      expected_generation: status.generation,
      expected: status.mutation_context,
      ...(action === "stage" ? { offer_id: status.offer?.id } : {}),
    };
    const epoch = this.epoch,
      abort = new AbortController();
    this.write = abort;
    this.set({
      sending: true,
      review: null,
      error: "",
      notice: "Submitting to the independent update worker…",
    });
    const timer = setTimeout(() => abort.abort(), 35000);
    try {
      const response = await abortable(
        this.host.api(
          "/api/v1/system/updates/" + action,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: "Bearer " + this.host.credential(),
            },
            body: JSON.stringify(body),
            signal: abort.signal,
          },
          35,
        ),
        abort.signal,
      );
      if (epoch !== this.epoch) return;
      if (response.status === 401) {
        this.host.signOut("That token was not accepted.");
        return;
      }
      if ([400, 403, 409, 413, 415].includes(response.status)) {
        this.set({
          error:
            "Request refused. Refresh and review the current boot, configuration and offer before trying again.",
          notice: "",
        });
        return;
      }
      if (!response.ok) throw Error("uncertain");
      const job: unknown = await abortable(response.json(), abort.signal);
      if (epoch !== this.epoch || abort.signal.aborted) return;
      if (
        !isUpdateJob(job) ||
        job.request_id !== requestId ||
        job.action !== action
      )
        throw Error("uncertain");
      this.set({
        notice:
          "Job accepted. It continues independently; staging never reboots this appliance.",
      });
      this.host.notice("Update job accepted. No reboot requested.");
    } catch (error) {
      if (epoch === this.epoch) {
        const refused =
          record(error) &&
          [400, 403, 409, 413, 415].includes(Number(error.status));
        this.set({
          uncertain: refused ? "" : requestId,
          notice: "",
          error: refused
            ? "Request refused. Refresh and review the current boot, configuration and offer before trying again."
            : "The request outcome is unknown. Refresh retained jobs; do not submit it again.",
        });
      }
    } finally {
      clearTimeout(timer);
      if (epoch === this.epoch) {
        this.write = null;
        // Invalidate the pre-admission generation before enabling any action.
        this.set({ sending: false, receivedAt: -Infinity });
        await this.refresh();
      }
    }
  };
}
