import { browser, signIn, sleep } from "./harness.mjs";
import { writeFileSync } from "node:fs";
const page = await browser({ width: 1600, height: 1000 });
await page.goto(process.env.CONSOLE_URL);
await signIn(page, process.env.CONSOLE_TOKEN);
await sleep(1500);
const OUT = process.env.OUT;
const shoot = async (n) => { writeFileSync(`${OUT}/${n}.png`, Buffer.from(await page.screenshot(), "base64")); console.log("shot", n); };
const go = async (v, tab) => {
  const key = tab ? `${v}:${tab}` : v;
  const r = await page.evaluate(`(() => { try { goto(${JSON.stringify(key)}); return "ok"; } catch (e) { return String(e); } })()`);
  await sleep(1500);
  return r;
};
for (const [key, name] of [["users","sn-aaa"], ["services:management","sn-mgmt"],
                           ["system","sn-system"], ["ha","sn-ha"]]) {
  const [v, tab] = key.split(":");
  const r = await go(v, tab);
  if (r === "ok") await shoot(name); else console.log("skip", key, r);
}
page.close();
