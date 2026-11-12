import { browser, signIn, summary } from "./harness.mjs";
import { stageContractTests } from "./stage-contract.mjs";

const page = await browser({width:1440,height:1000});
try {
  await page.goto(process.env.CONSOLE_URL);
  await signIn(page,process.env.CONSOLE_TOKEN);
  await stageContractTests(page);
} finally {
  page.close();
}
process.exitCode=summary()?1:0;
