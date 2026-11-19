// Unit tests for the harness's browser-process and profile-directory cleanup.
// No browser needed: stand-in processes play the browser.
//
//   node --test tests/console/harness-cleanup.unit.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  attachProcess, liveProfiles, reapAll, registerProfile, releaseProfile,
} from "./harness.mjs";

const here = dirname(fileURLToPath(import.meta.url));

function profileWithContent() {
  const profile = mkdtempSync(join(tmpdir(), "sentinel-console-unit-"));
  writeFileSync(join(profile, "Preferences"), "{}");
  return profile;
}

function alive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return false; }
}

test("close waits for the browser to exit, then removes its profile", async () => {
  const profile = profileWithContent();
  registerProfile(profile);
  const proc = spawn("sleep", ["30"], { stdio: "ignore", detached: true });
  attachProcess(profile, proc);

  await releaseProfile(profile, { graceMs: 2000 });

  assert.notEqual(proc.exitCode === null && proc.signalCode === null, true, "the browser stand-in still runs");
  assert.equal(existsSync(profile), false, "the profile directory was left behind");
  assert.equal(liveProfiles().includes(profile), false);
});

test("a browser that ignores SIGTERM is killed after the grace period", async () => {
  const profile = profileWithContent();
  registerProfile(profile);
  const proc = spawn("sh", ["-c", "trap '' TERM; while :; do sleep 0.1; done"], { stdio: "ignore", detached: true });
  attachProcess(profile, proc);
  await new Promise((r) => setTimeout(r, 200));

  const started = Date.now();
  await releaseProfile(profile, { graceMs: 300 });

  assert.equal(proc.signalCode, "SIGKILL");
  assert.ok(Date.now() - started < 5000, "escalation was not bounded");
  assert.equal(existsSync(profile), false);
});

test("the children of the browser are stopped with it", async () => {
  const profile = profileWithContent();
  registerProfile(profile);
  // The stand-in forks a child and reports its pid, like a renderer process.
  const proc = spawn("sh", ["-c", "sleep 30 & echo $!; wait"], { stdio: ["ignore", "pipe", "ignore"], detached: true });
  const child = Number(await new Promise((r) => proc.stdout.once("data", (d) => r(String(d).trim()))));
  attachProcess(profile, proc);

  await releaseProfile(profile, { graceMs: 2000 });
  await new Promise((r) => setTimeout(r, 100));

  assert.equal(alive(child), false, "a child of the browser survived close()");
  assert.equal(existsSync(profile), false);
});

test("reapAll kills and removes everything still registered", () => {
  const profile = profileWithContent();
  registerProfile(profile);
  const proc = spawn("sleep", ["30"], { stdio: "ignore", detached: true });
  attachProcess(profile, proc);

  reapAll();

  assert.equal(existsSync(profile), false);
  assert.deepEqual(liveProfiles(), []);
  proc.unref();
});

test("a process that exits without close() still removes its profiles", () => {
  // A test file that throws before close(): the 'exit' handler must clean up.
  const script = `
    import { attachProcess, registerProfile } from ${JSON.stringify(join(here, "harness.mjs"))};
    import { spawn } from "node:child_process";
    import { mkdtempSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    const profile = mkdtempSync(join(tmpdir(), "sentinel-console-unit-"));
    registerProfile(profile);
    const proc = spawn("sleep", ["30"], { stdio: "ignore", detached: true });
    attachProcess(profile, proc);
    console.log(JSON.stringify({ profile, pid: proc.pid }));
    process.exit(1);
  `;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  const { profile, pid } = JSON.parse(run.stdout.trim().split("\n").pop());

  assert.equal(run.status, 1);
  assert.equal(existsSync(profile), false, "the exit handler left the profile behind");
  assert.equal(alive(pid), false, "the exit handler left the browser running");
});

test("a browser that fails to start leaves no profile directory", () => {
  const before = new Set(readdirSync(tmpdir()).filter((n) => n.startsWith("sentinel-console-")));
  const script = `
    import { browser } from ${JSON.stringify(join(here, "harness.mjs"))};
    try { await browser(); console.log("started"); }
    catch (e) { console.log("refused: " + e.message); }
  `;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", script],
    { encoding: "utf8", env: { ...process.env, CHROMIUM: "false" } });
  const after = readdirSync(tmpdir()).filter((n) => n.startsWith("sentinel-console-") && !before.has(n));

  assert.match(run.stdout, /refused: the browser exited before it listened/);
  assert.deepEqual(after, [], "a failed launch left a profile directory");
});
