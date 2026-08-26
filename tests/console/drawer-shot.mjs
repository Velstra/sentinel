import { browser, signIn, sleep } from "./harness.mjs";
import { writeFileSync } from "node:fs";
const page = await browser({ width: 1600, height: 1000 });
await page.goto(process.env.CONSOLE_URL);
await signIn(page, process.env.CONSOLE_TOKEN);
await sleep(1500);
const OUT = process.env.OUT;
const shoot = async (n) => { writeFileSync(`${OUT}/${n}.png`, Buffer.from(await page.screenshot(), "base64")); console.log("shot", n); };
await shoot("dr-0-header");
// Add-Drawer: Firewall-Regeln → New rule
await page.evaluate(`goto("rules")`); await sleep(1400);
await page.evaluate(`document.getElementById("togglerule").click()`); await sleep(900);
await shoot("dr-1-addrule");
await page.evaluate(`document.getElementById("togglerule").click()`); await sleep(400);
// Editor-Drawer: bestehende Regel bearbeiten
await page.evaluate(`(() => { const b=[...document.querySelectorAll("#rulelist button")].find(x=>x.textContent.trim()==="Edit"); if(b) b.click(); })()`);
await sleep(1100);
await shoot("dr-2-editrule");
page.close();
