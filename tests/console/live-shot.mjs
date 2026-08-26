import { browser, signIn, sleep } from "./harness.mjs";
import { writeFileSync } from "node:fs";
const page = await browser({ width: 1600, height: 1000 });
await page.goto(process.env.CONSOLE_URL);
await signIn(page, process.env.CONSOLE_TOKEN);
await sleep(1500);
const OUT = process.env.OUT;
const shoot = async (name) => {
  writeFileSync(`${OUT}/${name}.png`, Buffer.from(await page.screenshot(), "base64"));
  console.log("shot", name);
};
await shoot("sn-01-dashboard");
for (const [view, name] of [["rules","sn-03-rules"],["interfaces","sn-02-interfaces"],
                            ["routing","sn-04-routing"],["config","sn-05-config"]]) {
  const r = await page.evaluate(`(() => { try { goto(${JSON.stringify(view)}); return "ok"; } catch (e) { return String(e); } })()`);
  await sleep(1600);
  if (r === "ok") await shoot(name); else console.log("skip", view, r);
}
page.close();
