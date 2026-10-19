import { test } from "node:test";
import assert from "node:assert/strict";
import { browser } from "./harness.mjs";

test("calls after browser closure fail immediately instead of waiting for a page timeout", async () => {
  const page = await browser();
  try {
    assert.equal(await page.evaluate("1 + 1"), 2);
    page.close();
    let timer;
    try {
      await assert.rejects(Promise.race([
        page.evaluate("1 + 1"),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("closed browser call hung")), 1000);
        }),
      ]), /browser.*(socket|exited)/);
    } finally {
      clearTimeout(timer);
    }
  } finally {
    page.close();
  }
});
