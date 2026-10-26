import { browser, signIn, summary, test, equal } from "./harness.mjs";
import { managementTests } from "./management.test.mjs";
const page = await browser();
try {
  await page.goto(process.env.CONSOLE_URL);
  await signIn(page, process.env.CONSOLE_TOKEN);
  await managementTests(page);
  await test("management interactions do not throw", () => equal(page.thrown, [], "browser exceptions"));
} finally { page.close(); }
process.exit(summary() ? 1 : 0);
