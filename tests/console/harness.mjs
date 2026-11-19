// A browser, driven directly over the DevTools protocol.
//
// The console is one generated document, and the failures that hurt it are the
// ones a parser cannot see: a function that was never written, an element a
// redesign removed, a command the appliance answers with "unknown set path".
// All three load, parse and render — and then do nothing. The only thing that
// catches them is a real browser clicking real buttons, so that is what this is.
//
// It speaks CDP over a WebSocket rather than using a driver library: the
// appliance's test story is nix + the standard library, and one file with no
// dependencies is something that still runs in five years.

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CHROME = process.env.CHROMIUM || "chromium";

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/// A port nothing else is on. A fixed debugging port is the worst kind of test
/// dependency: a browser left behind by an interrupted run keeps listening on
/// it, the browser this run starts cannot bind and dies, and the harness then
/// attaches to *the old page* — which is showing an old build against a dead
/// API. Everything after that is a lie, and it reads as the console being
/// broken rather than as the harness talking to a ghost.
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

// ---- browser processes and their profile directories ------------------------
//
// Every launched browser owns a throwaway profile directory. Those directories
// used to outlive the run: `close()` sent SIGTERM and removed the directory in
// the same tick, while Chromium was still writing to it, and a test that threw
// before `close()` never removed it at all — over a thousand
// `/tmp/sentinel-console-*` directories piled up. Now each browser is
// registered here, `close()` removes its profile only once the whole process
// group has exited, and the process 'exit' handler (also reached from SIGINT,
// SIGTERM and SIGHUP) kills and removes whatever is still registered.

const live = new Map(); // profile directory -> { proc, gone: Promise<void> }
const CLOSE_GRACE_MS = Number(process.env.CONSOLE_CLOSE_GRACE_MS || 5000);
let handlersInstalled = false;

function signalGroup(proc, signal) {
  // The browser runs in its own process group (spawned detached), so its
  // renderer and utility children are signalled too, not orphaned onto the
  // profile they were writing.
  try { process.kill(-proc.pid, signal); return; } catch (e) { /* no group */ }
  try { proc.kill(signal); } catch (e) { /* already gone */ }
}

function removeProfile(profile) {
  // A renderer can still be flushing a file for a moment after the group was
  // signalled; retry instead of leaving a half-removed directory behind.
  try { rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  catch (e) { console.error(`could not remove browser profile ${profile}: ${e.message}`); }
}

/// Kill every browser still registered and remove its profile, synchronously.
/// Runs from the process 'exit' handler, where nothing asynchronous happens.
export function reapAll() {
  for (const [profile, entry] of live) {
    if (entry.proc && entry.proc.exitCode === null && entry.proc.signalCode === null) {
      signalGroup(entry.proc, "SIGKILL");
    }
    removeProfile(profile);
    live.delete(profile);
  }
}

function installHandlers() {
  if (handlersInstalled) return;
  handlersInstalled = true;
  process.on("exit", reapAll);
  for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]]) {
    process.once(signal, () => process.exit(code));
  }
}

/// Register a new profile directory (before the browser that uses it starts,
/// so a launch that fails still has its directory removed).
export function registerProfile(profile) {
  installHandlers();
  live.set(profile, { proc: null, gone: Promise.resolve() });
}

/// Attach the browser process that uses a registered profile.
export function attachProcess(profile, proc) {
  const gone = new Promise((resolve) => {
    if (proc.exitCode !== null || proc.signalCode !== null) resolve();
    else proc.once("exit", () => resolve());
  });
  live.set(profile, { proc, gone });
}

/// Stop the browser of a profile and remove the directory once it has exited:
/// SIGTERM, then SIGKILL after a bounded grace period. Resolves when the
/// directory is gone. Safe to call twice; callers that do not await it are
/// still covered by the 'exit' handler.
export async function releaseProfile(profile, { graceMs = CLOSE_GRACE_MS } = {}) {
  const entry = live.get(profile);
  if (!entry) return;
  const { proc, gone } = entry;
  if (proc && proc.exitCode === null && proc.signalCode === null) {
    signalGroup(proc, "SIGTERM");
    let timer;
    const timedOut = new Promise((resolve) => { timer = setTimeout(() => resolve(true), graceMs); });
    if (await Promise.race([gone.then(() => false), timedOut])) {
      signalGroup(proc, "SIGKILL");
      await gone;
    }
    clearTimeout(timer);
  }
  // The whole group was signalled; give its children a moment to let go.
  if (proc) signalGroup(proc, "SIGKILL");
  removeProfile(profile);
  live.delete(profile);
}

/// The profile directories this process still owns (for tests of the above).
export function liveProfiles() {
  return [...live.keys()];
}

/// Launch a headless browser and connect to its first page.
export async function browser({ port = 0, width = 1600, height = 1000 } = {}) {
  if (!port) port = await freePort();
  const profile = mkdtempSync(join(tmpdir(), "sentinel-console-"));
  registerProfile(profile);
  try {
    return await launch(profile, { port, width, height });
  } catch (e) {
    await releaseProfile(profile);
    throw e;
  }
}

async function launch(profile, { port, width, height }) {
  const proc = spawn(CHROME, [
    "--headless=new",
    `--remote-debugging-port=${port}`,
    "--no-first-run",
    "--no-default-browser-check",
    // In a build sandbox there is no user namespace to sandbox into, and the
    // page we load is one we generated ourselves.
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    `--window-size=${width},${height}`,
    `--user-data-dir=${profile}`,
    "about:blank",
  ], { stdio: ["ignore", "pipe", "pipe"], detached: true });
  attachProcess(profile, proc);

  // The browser's own last words. When it dies mid-run — out of memory in a
  // build sandbox, a renderer crash — the only evidence is on its stderr, and
  // a harness that discards it can only report that nothing answered.
  const said = [];
  const keep = (chunk) => {
    said.push(String(chunk));
    if (said.length > 40) said.shift();
  };
  proc.stdout.on("data", keep);
  proc.stderr.on("data", keep);

  let socket = null, died = null;
  proc.on("exit", (code, signal) => { died = signal ? `signal ${signal}` : `code ${code}`; });
  for (let i = 0; i < 120 && !socket; i++) {
    if (died !== null) throw new Error(`the browser exited before it listened (${died})`);
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) socket = page.webSocketDebuggerUrl;
    } catch (e) { /* not listening yet */ }
    if (!socket) await sleep(250);
  }
  if (!socket) throw new Error("the browser never came up");

  const ws = new WebSocket(socket);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error("could not attach to the browser"));
  });

  let id = 0;
  const pending = new Map();
  const thrown = [];
  const requests = [];
  const responses = [], failedRequests = [], consoleMessages = [], logs = [];
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    // An uncaught exception is the failure mode this harness exists for: the
    // page keeps rendering and every button wired after it is dead.
    if (m.method === "Network.requestWillBeSent") {
      requests.push(m.params.request.url);
      if (requests.length > 16384) requests.shift();
    }
    if (m.method === "Runtime.exceptionThrown") {
      const d = m.params.exceptionDetails;
      thrown.push(`${d.exception?.description || d.text} (line ${d.lineNumber})`);
    }
    if (m.method === "Network.responseReceived") {
      const r = m.params.response;
      responses.push({url:r.url,status:r.status,type:m.params.type});
    }
    if (m.method === "Network.loadingFailed") {
      failedRequests.push({requestId:m.params.requestId,error:m.params.errorText,canceled:!!m.params.canceled});
    }
    if (m.method === "Runtime.consoleAPICalled") {
      consoleMessages.push({level:m.params.type,text:m.params.args.map(a=>a.value??a.description).join(" ")});
    }
    if (m.method === "Log.entryAdded") logs.push(m.params.entry);
    for (const list of [responses,failedRequests,consoleMessages,logs]) if(list.length>16384)list.shift();
    if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") {
      thrown.push("console.error: " +
        m.params.args.map((a) => a.value ?? a.description).join(" "));
    }
  };

  // Every call is bounded. A page that stops answering — a fetch that never
  // settles, a browser that died — must fail the check loudly; a harness that
  // waits forever turns a broken console into a build that hangs, which is the
  // one outcome nobody can debug from a log. Generous by default, because one
  // call here can be a walk over sixty rail entries and every one of those
  // makes the appliance shell out to its own binary for a `show`.
  const CALL_TIMEOUT = Number(process.env.CONSOLE_CALL_TIMEOUT || 300000);

  // A browser that has died must not be waited out. Every pending call is
  // failed the moment the process exits or the socket closes, with the reason
  // and the browser's last words — otherwise a crash reports as "the page
  // stopped answering" ten minutes later, which is the same sentence a slow
  // page produces and sends the reader looking in the wrong place entirely.
  const giveUp = (why) => {
    const tail = said.join("").trim().split("\n").slice(-8).join("\n");
    const e = new Error(why + (tail ? `\n  the browser said:\n  ${tail.split("\n").join("\n  ")}` : ""));
    for (const [, settle] of pending) settle({ __dead: e });
    pending.clear();
  };
  proc.on("exit", (code, signal) =>
    giveUp(`the browser exited mid-run (${signal ? `signal ${signal}` : `code ${code}`})`));
  ws.addEventListener("close", () => giveUp("the browser closed the debugging socket mid-run"));

  const send = (method, params = {}) =>
    new Promise((res, rej) => {
      const callId = ++id;
      const timer = setTimeout(() => {
        pending.delete(callId);
        rej(new Error(`the page stopped answering (${method} after ${CALL_TIMEOUT}ms)`));
      }, CALL_TIMEOUT);
      pending.set(callId, (m) => {
        clearTimeout(timer);
        if (m && m.__dead) rej(m.__dead);
        else res(m);
      });
      ws.send(JSON.stringify({ id: callId, method, params }));
    });

  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true,
    });
    const failed = r.result?.exceptionDetails;
    if (failed) throw new Error(failed.exception?.description || failed.text);
    return r.result?.result?.value;
  };

  await send("Runtime.enable");
  await send("Page.enable");
  await send("Network.enable");
  await send("Log.enable");

  return {
    evaluate,
    send,
    requests,
    thrown,
    responses,
    failedRequests,
    consoleMessages,
    logs,
    async goto(url) { await send("Page.navigate", { url }); await sleep(1200); },
    async screenshot() {
      return (await send("Page.captureScreenshot", { format: "png" })).result.data;
    },
    /// Stop the browser and remove its profile once it has exited. Returns a
    /// promise; `await` it where the next step needs the directory gone.
    close() {
      try { ws.close(); } catch (e) {}
      return releaseProfile(profile);
    },
  };
}

/// Sign in with the machine token, the way an operator does before any account
/// exists — through the form, not by writing the token into storage, so the
/// sign-in path is covered too.
async function waitForSignInForm(page, id) {
  // Navigation completion is asynchronous. Finding server-rendered inputs
  // does not mean the trailing script has installed their submit handlers.
  // Under load, dispatching before that point is a silent test-only no-op.
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await page.evaluate(`typeof document.getElementById(${JSON.stringify(id)})?.onsubmit === "function"`)) return;
    await sleep(100);
  }
  throw new Error(`the sign-in form did not become interactive (${id})`);
}

export async function signIn(page, token) {
  await waitForSignInForm(page, "tokenform");
  await page.evaluate(`(() => {
    document.getElementById("tokentoggle").click();
    document.getElementById("token").value = ${JSON.stringify(token)};
    document.getElementById("tokenform").dispatchEvent(new Event("submit", {cancelable: true}));
    return 1;
  })()`);
  await sleep(1200);
  const signedIn = await page.evaluate(`!document.getElementById("app").classList.contains("hidden")`);
  if (!signedIn) {
    const why = await page.evaluate(`document.getElementById("loginerr").textContent`);
    throw new Error(`signing in left the login screen up: ${why}`);
  }
}

/// Sign in as an account, with a username and a password.
export async function signInAs(page, username, password) {
  await waitForSignInForm(page, "loginform");
  await page.evaluate(`(() => {
    document.getElementById("username").value = ${JSON.stringify(username)};
    document.getElementById("password").value = ${JSON.stringify(password)};
    document.getElementById("loginform").dispatchEvent(new Event("submit", {cancelable: true}));
    return 1;
  })()`);
  await sleep(2000);
  return page.evaluate(`({
    inside: !document.getElementById("app").classList.contains("hidden"),
    said: document.getElementById("loginerr").textContent,
  })`);
}

// ---- the smallest test runner that reports usefully -------------------------

const results = [];

export async function test(name, body) {
  try {
    await body();
    results.push({ name, ok: true });
    console.log(`  ok   ${name}`);
  } catch (e) {
    results.push({ name, ok: false, why: String(e.message || e) });
    console.log(`  FAIL ${name}\n       ${String(e.message || e).split("\n").join("\n       ")}`);
  }
}

export function check(condition, message) {
  if (!condition) throw new Error(message);
}

export function equal(actual, expected, message) {
  const a = JSON.stringify(actual), b = JSON.stringify(expected);
  if (a !== b) throw new Error(`${message}\n  expected ${b}\n  got      ${a}`);
}

export function summary() {
  const bad = results.filter((r) => !r.ok);
  console.log(`\n${results.length - bad.length}/${results.length} passed`);
  return bad.length;
}
