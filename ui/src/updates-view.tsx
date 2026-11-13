import { useRef, useSyncExternalStore } from "react";
import type { Management } from "./controller";
import { terminal } from "./updates";
import { Panel } from "./components";

export function SystemUpdates({ manager }: { manager: Management }) {
  const updates = manager.updates;
  const state = useSyncExternalStore(updates.subscribe, updates.getSnapshot);
  const status = state.status;
  const current = status?.current;
  const offer = status?.offer;
  const fresh = updates.fresh();
  const reviewTrigger = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLElement>(null);
  const cancelReview = () => {
    updates.cancelReview();
    if (reviewTrigger.current && !reviewTrigger.current.disabled)
      reviewTrigger.current.focus();
    else panel.current?.focus();
  };
  return (
    <Panel title="System updates" focusRef={panel}>
      <span className="pill">
        {state.remote
          ? "Local appliance only"
          : fresh
            ? "Current observation"
            : "Not current"}
      </span>
      {state.remote ? (
        <p>
          Select the local member to inspect and stage its updates. Cluster
          members are updated separately.
        </p>
      ) : (
        <>
          <dl className="system-health-summary">
            <div>
              <dt>Running OS release</dt>
              <dd>{current?.release || "Unknown"}</dd>
            </div>
            <div>
              <dt>Active slot</dt>
              <dd>
                {current
                  ? current.slot === "sentinel-a"
                    ? "Slot A"
                    : "Slot B"
                  : "Unknown"}
              </dd>
            </div>
            <div>
              <dt>Running image assessment</dt>
              <dd>
                {current
                  ? current.permanent
                    ? "Permanent"
                    : "Provisional — not yet blessed"
                  : "Unknown"}
              </dd>
            </div>
            <div>
              <dt>Next boot entry</dt>
              <dd>{current?.next_entry || "Unknown"}</dd>
            </div>
          </dl>
          <p className="source-empty">
            Stage a signed image into the inactive slot. Reboot separately after
            inspecting boot selection and cluster readiness.
          </p>
          {!state.writable && (
            <p>
              Read-only access. An administrator must check or stage updates.
            </p>
          )}
          {status?.unavailable && (
            <p role="status">
              {status.unavailable === "unsupported-runtime"
                ? "Updates require the live A/B appliance. Off-box and no-apply consoles cannot stage images."
                : "Updates unavailable: " +
                  status.unavailable +
                  ". Inspect boot health and configuration before proceeding."}
            </p>
          )}
          <div className="row" aria-busy={state.busy || state.sending}>
            <button
              className="btn"
              type="button"
              disabled={state.busy || state.sending}
              onClick={() => void updates.refresh()}
            >
              {state.busy ? "Refreshing…" : "Refresh update status"}
            </button>
            <button
              className="btn"
              type="button"
              disabled={!updates.permitted("check")}
              onClick={() => void updates.submit("check")}
            >
              {state.sending ? "Submitting…" : "Check signed channel"}
            </button>
            <button
              className="btn"
              type="button"
              disabled={!updates.permitted("stage")}
              onClick={updates.review}
              ref={reviewTrigger}
            >
              Review available update
            </button>
          </div>
          <p role="status" aria-live="polite">
            {state.notice ||
              (!fresh
                ? "Refresh before checking or staging. Displayed observations may be stale."
                : !offer
                  ? "No current verified offer. Check the saved signed channel."
                  : "Verified offer: " + offer.verified.manifest.version)}
          </p>
          {state.error && (
            <p className="source-error" role="alert">
              {state.error}
            </p>
          )}
          {state.uncertain && (
            <p className="update-proof">
              Request correlation: <code>{state.uncertain}</code>. If it is not
              retained, inspect the appliance services before any further
              update.
            </p>
          )}
          {state.review?.offer && (
            <section
              className="update-review"
              aria-label="Review signed update"
            >
              <h4>Stage {state.review.offer.verified.manifest.version}?</h4>
              <p>
                The inactive slot will be replaced and the new image selected
                for a counted boot. The current slot remains available. No
                automatic reboot.
              </p>
              <dl className="system-health-summary">
                <div>
                  <dt>Image</dt>
                  <dd>{state.review.offer.verified.manifest.image}</dd>
                </div>
                <div>
                  <dt>Image SHA-256</dt>
                  <dd>
                    <code>{state.review.offer.verified.manifest.sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Signing key SHA-256</dt>
                  <dd>
                    <code>{state.review.offer.verified.public_key_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Reviewed offer ID</dt>
                  <dd>
                    <code>{state.review.offer.id}</code>
                  </dd>
                </div>
              </dl>
              <div className="row">
                <button
                  className="btn primary"
                  type="button"
                  disabled={!updates.permitted("stage")}
                  onClick={() => {
                    void updates.submit("stage");
                    panel.current?.focus();
                  }}
                >
                  Download &amp; stage update
                </button>
                <button className="btn" type="button" onClick={cancelReview}>
                  Cancel update review
                </button>
              </div>
            </section>
          )}
          <h4>Retained update jobs</h4>
          {!status?.jobs.length ? (
            <p>No retained jobs available.</p>
          ) : (
            <ol className="update-jobs">
              {[...status.jobs].reverse().map((job) => (
                <li key={job.id}>
                  <span
                    className={
                      "pill " +
                      (job.error ? "warn" : terminal(job.phase) ? "ok" : "rest")
                    }
                  >
                    {job.action} · {job.phase}
                  </span>
                  <code>{job.id}</code>
                  {job.message && <p>{job.message}</p>}
                  {job.phase === "staged" && (
                    <p>
                      {!current
                        ? "Stage completed. Current boot state is unavailable."
                        : job.boot_id !== current.boot_id
                          ? "Stage recorded on a previous boot. Current boot assessment is shown above."
                          : "Image staged during this boot. Inspect boot selection before rebooting and assessing the new image."}
                    </p>
                  )}
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </Panel>
  );
}
