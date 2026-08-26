import { browser, signIn, sleep } from "./harness.mjs";
const page = await browser({ width: 1400, height: 900 });
await page.goto(process.env.CONSOLE_URL);
await signIn(page, process.env.CONSOLE_TOKEN);
await sleep(1200);
console.log(await page.evaluate(`JSON.stringify(SECTIONS.map(s => [s[0], (s[2]||[]).map(p => p[0])]))`));
page.close();
