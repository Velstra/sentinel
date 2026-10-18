import { test } from "node:test";
import assert from "node:assert/strict";
import { walkAll } from "./coverage.mjs";

// Inventory errors must fail the test, rather than count an unreadable tab as
// empty or silently credit fields collected on another page.
function pageWith(...answers) {
  return {
    async evaluate() {
      assert.ok(answers.length, "unexpected inventory operation");
      const answer = answers.shift();
      if (answer instanceof Error) throw answer;
      return answer;
    },
  };
}

test("an unreadable tab list fails inventory", async () => {
  await assert.rejects(
    walkAll(pageWith([], ["routing"], new Error("tab list unavailable"))),
    /tab list unavailable/,
  );
});

test("a failed tab navigation fails inventory", async () => {
  await assert.rejects(
    walkAll(pageWith([], ["routing"], 1, new Error("tab navigation failed"))),
    /tab navigation failed/,
  );
});
