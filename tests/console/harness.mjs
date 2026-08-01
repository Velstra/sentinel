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

/// Launch a headless browser and connect to its first page.
export async function browser({ port = 0, width = 1600, height = 1000 } = {}) {
  if (!port) port = await freePort();
  const profile = mkdtempSync(join(tmpdir(), "sentinel-console-"));
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
  ], { stdio: ["ignore", "pipe", "pipe"] });

  let socket = null, died = null;
  proc.on("exit", (code) => { died = code; });
  for (let i = 0; i < 120 && !socket; i++) {
    if (died !== null) throw new Error(`the browser exited before it listened (code ${died})`);
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
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    // An uncaught exception is the failure mode this harness exists for: the
    // page keeps rendering and every button wired after it is dead.
    if (m.method === "Runtime.exceptionThrown") {
      const d = m.params.exceptionDetails;
      thrown.push(`${d.exception?.description || d.text} (line ${d.lineNumber})`);
    }
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
  const send = (method, params = {}) =>
    new Promise((res, rej) => {
      const callId = ++id;
      const timer = setTimeout(() => {
        pending.delete(callId);
        rej(new Error(`the page stopped answering (${method} after ${CALL_TIMEOUT}ms)`));
      }, CALL_TIMEOUT);
      pending.set(callId, (m) => { clearTimeout(timer); res(m); });
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

  return {
    evaluate,
    thrown,
    async goto(url) { await send("Page.navigate", { url }); await sleep(1200); },
    async screenshot() {
      return (await send("Page.captureScreenshot", { format: "png" })).result.data;
    },
    close() {
      try { ws.close(); } catch (e) {}
      proc.kill();
      try { rmSync(profile, { recursive: true, force: true }); } catch (e) {}
    },
  };
}

/// Sign in with the machine token, the way an operator does before any account
/// exists — through the form, not by writing the token into storage, so the
/// sign-in path is covered too.
export async function signIn(page, token) {
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
