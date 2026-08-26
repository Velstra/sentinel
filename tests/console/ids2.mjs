import { browser, signIn, sleep } from "./harness.mjs";
const page = await browser({ width: 1400, height: 900 });
await page.goto(process.env.CONSOLE_URL);
await signIn(page, process.env.CONSOLE_TOKEN);
await sleep(1200);
console.log(await page.evaluate(`JSON.stringify(SECTIONS[1])`));
console.log(await page.evaluate(`JSON.stringify([...document.querySelectorAll('[id^="view-"]')].map(e=>e.id).slice(0,40))`));
page.close();
