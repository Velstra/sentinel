import { browser, signIn, sleep } from "./harness.mjs";
import { writeFileSync } from "node:fs";
const page = await browser({ width: 1600, height: 1000 });
await page.goto(process.env.CONSOLE_URL);
await signIn(page, process.env.CONSOLE_TOKEN);
await sleep(1400);
await page.evaluate(`goto("users")`); await sleep(1600);
const found = await page.evaluate(`(() => {
  const t = document.body.innerText;
  return JSON.stringify({
    radius: t.includes("RADIUS"), ldap: t.includes("LDAP"), tacacs: t.includes("TACACS"),
  });
})()`);
console.log("AAA-Flächen:", found);
await page.evaluate(`(() => { const h=[...document.querySelectorAll("h3,h2")].find(x=>/TACACS/i.test(x.textContent)); if(h) h.scrollIntoView({block:"start"}); return 1; })()`);
await sleep(700);
writeFileSync(`${process.env.OUT}/sn-tacacs.png`, Buffer.from(await page.screenshot(), "base64"));
console.log("shot sn-tacacs");
page.close();
