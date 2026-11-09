// Real browser + local --no-apply API + on-disk revision boundary. The separate
// Nix archive-privacy gate proves actual UID isolation and live system effects.
import {execFileSync} from 'node:child_process';
import {readFileSync,readdirSync,statSync,writeFileSync,mkdirSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {browser,signIn,sleep,test,check,equal,summary} from './harness.mjs';

const config=process.env.CONSOLE_CONFIG,binary=process.env.CONSOLE_BINARY;
check(config&&binary&&new URL(process.env.CONSOLE_URL).hostname==='127.0.0.1',
 'Run this only through tests/console/run.sh against its disposable local no-apply API');
const archive=join(dirname(config),'archive');
const text=()=>readFileSync(config,'utf8');
const hostname=()=>text().match(/^hostname = "([^"]+)"/m)?.[1];
const secret=text().match(/^private-key = (.+)$/m)?.[1];
check(secret,'the public QA WireGuard credential fixture is missing');
const revisions=()=>readdirSync(archive).filter(n=>/^config-\d+\.toml$/.test(n)).sort((a,b)=>{
 const x=BigInt(a.slice(7,-5)),y=BigInt(b.slice(7,-5));return x===y?0:x>y?-1:1;
});
function privateRevisions(){
 equal(statSync(archive).mode&0o7777,0o750,'archive traversal permission');
 for(const file of readdirSync(archive)){
  const metadata=statSync(join(archive,file));
  equal(metadata.mode&0o7777,0o640,'revision permission');
  equal(metadata.uid,process.getuid(),'local fixture owner changed');
 }
 check(text().match(/^private-key = (.+)$/m)?.[1]===secret,'a configuration path lost the credential');
}
function cli(lines){
 const output=execFileSync(binary,['configure','--no-apply','--config',config],
  {input:lines.concat('exit').join('\n')+'\n',timeout:20000,encoding:'utf8',stdio:['pipe','pipe','pipe']});
 check(!output.includes('error:'),'CLI rejected a valid local revision');
}
async function until(expression,message){
 for(let i=0;i<160;i++){if(await page.evaluate(expression))return;await sleep(100);}
 throw new Error(message);
}
async function editor(){
 await page.evaluate('goto("config")');
 await until('document.querySelector("#revtable button")','revision list did not load');
 if(await page.evaluate('!management.getSnapshot().editor.visible'))await page.evaluate('$("toml-load").click()');
 else await page.evaluate('$("toml-reload").click()');
 await until('management.getSnapshot().editor.visible&&!management.getSnapshot().editor.busy','editor did not load');
}
async function candidate(value){
 await page.evaluate(`(()=>{const input=$("toml-candidate");input.value=${JSON.stringify(value)};input.dispatchEvent(new Event('input',{bubbles:true}));})()`);
 await sleep(30);
}
const page=await browser({width:1440,height:1000});
try{
 await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
 await test('CLI save remains visible through the actual UI with protected revisions',async()=>{
  cli(['set system hostname archive-cli-ui','commit','save']);
  equal(hostname(),'archive-cli-ui','CLI did not save the hostname');privateRevisions();
  await editor();
  check(await page.evaluate('$("toml-baseline").textContent.includes(\'hostname = "archive-cli-ui"\')'),'UI did not read the CLI revision');
 });
 await test('invalid UI validation neither persists nor creates a revision',async()=>{
  const saved=text(),files=revisions();
  await candidate('[system\nhostname=broken');
  await page.evaluate('$("toml-validate").click()');
  await until('$("toml-candidate").getAttribute("aria-invalid")==="true"&&!management.getSnapshot().editor.busy','invalid draft was not rejected');
  equal(text(),saved,'invalid candidate changed saved configuration');equal(revisions(),files,'validation created an archive');
 });
 await test('UI validation and explicit Keep change create a protected revision without losing credentials',async()=>{
  const baseline=await page.evaluate('management.getSnapshot().editor.baseline');
  await candidate(baseline.replace(/hostname = "[^"]+"/,'hostname = "archive-gui"'));
  await page.evaluate('$("toml-validate").click()');
  await until('$("toml-feedback").textContent.includes("Valid configuration")&&!management.getSnapshot().editor.busy','valid UI candidate was rejected');
  await page.evaluate('$("toml-apply").click()');
  await until('!!management.getSnapshot().pending?.ready&&!$("confirm-change").disabled','provisional change did not become confirmable');
  await page.evaluate('$("confirm-change").click()');
  await until('!management.getSnapshot().pending&&!management.getSnapshot().confirming','confirmation did not finish');
  equal(hostname(),'archive-gui','UI confirmation did not persist');privateRevisions();
  check(revisions().some(n=>readFileSync(join(archive,n),'utf8').includes('hostname = "archive-gui"')),'confirmed UI revision was not archived');
 });
 await test('UI revision button stages rollback, and Apply restores the CLI revision with private history',async()=>{
  await page.evaluate('management.clearEditor()');await sleep(30);
  await page.evaluate('goto("config")');
  const index=revisions().findIndex(n=>readFileSync(join(archive,n),'utf8').includes('hostname = "archive-cli-ui"'));
  check(index>=0,'CLI revision not retained');
  try{await until(`Array.from(document.querySelectorAll('#revtable tr')).some(r=>Number.parseInt(r.cells[0]?.textContent,10)===${index}&&r.querySelector('button'))`,'CLI revision has no rollback control');}
  catch(error){throw new Error(error.message+'; '+JSON.stringify({index,rows:await page.evaluate('[...document.querySelectorAll("#revtable tr")].map(r=>({text:r.textContent,buttons:r.querySelectorAll("button").length}))')}));}
  await page.evaluate(`(()=>{const row=[...document.querySelectorAll('#revtable tr')].find(r=>Number.parseInt(r.cells[0]?.textContent,10)===${index});row.querySelector('button').click();})()`);
  equal(hostname(),'archive-gui','staging rollback applied it prematurely');
  equal(await page.evaluate('stagedCommands()'),['rollback '+index],'revision control staged the wrong command');
  await page.evaluate('$("applystaged").click()');
  await until('!applying&&staged.length===0','rollback apply did not finish');
  equal(hostname(),'archive-cli-ui','UI rollback did not reach saved config');privateRevisions();
 });
 await test('CLI rollback of a GUI-created revision is reflected in the UI without credential drift',async()=>{
  const index=revisions().findIndex(n=>readFileSync(join(archive,n),'utf8').includes('hostname = "archive-gui"'));
  check(index>=0,'GUI revision not retained');cli(['rollback '+index]);
  equal(hostname(),'archive-gui','CLI rollback did not restore GUI state');privateRevisions();
  await page.evaluate('if($("result").open)$("result").close();management.clearEditor()');await sleep(30);
  await editor();
  check(await page.evaluate('$("toml-baseline").textContent.includes(\'hostname = "archive-gui"\')'),'UI stale after CLI rollback');
  await page.evaluate('$("toml-hide").click()');await sleep(30);
  await page.evaluate('$("revtable").scrollIntoView({block:"center"})');await sleep(100);
  if(process.env.CONSOLE_SCREENSHOTS){mkdirSync(process.env.CONSOLE_SCREENSHOTS,{recursive:true});writeFileSync(join(process.env.CONSOLE_SCREENSHOTS,'archive-revisions.png'),Buffer.from(await page.screenshot(),'base64'));}
 });
 await test('archive workflows have no uncaught JavaScript or console errors',()=>{
  equal(page.thrown,[],'uncaught browser exceptions');
  equal(page.consoleMessages.filter(m=>m.level==='error'),[],'console errors');
 });
}finally{page.close();}
process.exitCode=summary()?1:0;
