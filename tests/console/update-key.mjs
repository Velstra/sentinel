// Actual browser and installed test CLI round trips. Only the runner's private
// --no-apply fixture changes; this does not certify a native channel download.
import {browser,signIn,sleep,test,check} from './harness.mjs';
import {click} from './creation.mjs';
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

const PEM='-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----';
async function fill(page,selector,value){
 await click(page,selector);
 await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:2});
 await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:2});
 if(value)await page.send('Input.insertText',{text:value});
 else{
  await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});
  await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});
 }
}
async function wait(page,expression){
 const deadline=Date.now()+15000;
 while(Date.now()<deadline){if(await page.evaluate(expression))return;await sleep(100);}
 throw Error('Real key form did not reach '+expression);
}
function cli(commands){
 const out=spawnSync(process.env.CONSOLE_BINARY,['configure','--config',process.env.CONSOLE_CONFIG,'--no-apply'],{
  env:{...process.env,SENTINEL_CONFIG:process.env.CONSOLE_CONFIG},input:commands.concat(['commit','save','exit']).join('\n')+'\n',encoding:'utf8',timeout:30000});
 // The REPL deliberately reports commit/save status on stderr, just as it
 // does interactively. Exit status and BOTH streams are the actual oracle.
 const output=(out.stdout||'')+(out.stderr||'');
 check(!out.error&&out.status===0&&!/^error:/im.test(output)&&output.includes('commit ok'),
  'Actual fixture CLI refused the key round trip: '+JSON.stringify({status:out.status,signal:out.signal,error:out.error?.message,output:output.slice(-6000)}));
}
async function validate(page){
 await click(page,'#validate');await wait(page,'document.querySelector("#result").open&&!applying');
 const result=await page.evaluate('document.querySelector("#resultout").textContent');
 check(!/refused|error:/i.test(result),'Actual configuration validation refused the public key');
 await click(page,'#resultclose');
}
async function refresh(page,selector){
 // An empty old form can satisfy the value oracle before the asynchronous
 // configuration read redraws it. Wait for the real replacement, not time.
 await page.evaluate(`globalThis.qaPreviousKeyControl=document.querySelector(${JSON.stringify(selector)})`);
 await click(page,'#refresh');
 await wait(page,`document.querySelector(${JSON.stringify(selector)})&&document.querySelector(${JSON.stringify(selector)})!==globalThis.qaPreviousKeyControl&&!document.querySelector('#toggleupchan').disabled&&typeof document.querySelector('#toggleupchan').onclick==='function'`);
 await page.evaluate('delete globalThis.qaPreviousKeyControl');
}
export async function updateKeyTests(){
 check(process.env.CONSOLE_CONFIG&&process.env.CONSOLE_BINARY,'Only the private --no-apply runner fixture may change');
 const before=readFileSync(process.env.CONSOLE_CONFIG);
 for(const width of [1440,390]){
  const page=await browser({width,height:1000});let changed=false;
  try{
   await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});
   await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
   check(await page.evaluate('innerWidth')===width,'Key form viewport differs from its receipt');
   await page.evaluate('goto("system")');
   await wait(page,'!!document.querySelector(\'#sys-update [aria-label="Signing key"]\')?.getClientRects().length');
   const selector='#sys-update [aria-label="Signing key"]';
   await test('public release key has a multiline format-safe control at '+width,async()=>{
    const control=await page.evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});return{tag:n.tagName,placeholder:n.placeholder,described:n.getAttribute('aria-describedby'),label:!!n.labels?.length,resize:getComputedStyle(n).resize};})()`);
    check(control.tag==='TEXTAREA'&&control.placeholder.includes('-----BEGIN PUBLIC KEY-----')&&control.described&&control.label&&control.resize==='none',JSON.stringify(control));
    await fill(page,'#sys-update [aria-label="Default channel URL"]','https://updates.example.com/release');
    for(const bad of ['file:','file:/etc/sentinel/key.pem\n','-----BEGIN PRIVATE KEY-----\nPRIVATE_FIXTURE\n-----END PRIVATE KEY-----','-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----']){
     await fill(page,selector,bad);await click(page,'#sys-update .maskfoot > .primary');
     check(await page.evaluate(`document.querySelector(${JSON.stringify(selector)}).getAttribute('aria-invalid')==='true'&&stagedCommands().length===0`),'Invalid public/private key was staged');
    }
    // Exercise the browser's real TextEncoder byte bound, not just the PEM
    // branch or an empty file: reference which short-circuits before encoding.
    const reference='file:/etc/sentinel/releases/clé-publique.pem';
    await fill(page,selector,reference);
    check(await page.evaluate(`document.querySelector(${JSON.stringify(selector)}).value===${JSON.stringify(reference)}&&document.querySelector(${JSON.stringify(selector)}).getAttribute('aria-invalid')!=='true'`),'A UTF-8 public-key reference was rejected or retargeted');
   });
   await test('default public PEM and exact file path survive physical paste, validation and CLI readback at '+width,async()=>{
    for(const key of [PEM,'file:/etc/sentinel/releases/clé  publique.pem ']){
     await fill(page,'#sys-update [aria-label="Default channel URL"]','https://updates.example.com/release');
     await fill(page,selector,key);
     check(await page.evaluate(`document.querySelector(${JSON.stringify(selector)}).value===${JSON.stringify(key)}`),'Physical paste changed the key representation');
     await click(page,'#sys-update .maskfoot > .primary');
     const commands=await page.evaluate('stagedCommands()');
     const encoded=JSON.stringify(key.replace(/[\r\n]+/g,' '));
     check(commands.length===2&&commands.every(c=>!c.includes('\n'))&&commands.includes('set update public-key '+encoded),'Key did not stage as one exact, safe CLI token');
     await validate(page);await click(page,'#discard');changed=true;cli(commands);
     await refresh(page,selector);
     await wait(page,`document.querySelector(${JSON.stringify(selector)})?.value===${JSON.stringify(key)}`);
     await click(page,selector);
     check(await page.evaluate(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.height>=76;})()`),'Signing key control clipped or collapsed');
     const folder=process.env.CONSOLE_SCREENSHOTS||'screenshots';mkdirSync(folder,{recursive:true});
     writeFileSync(folder+'/update-public-'+(key===PEM?'PEM':'file')+'-'+width+'.png',Buffer.from(await page.screenshot(),'base64'));
     // Editing another leaf must not silently replay/reformat a stable pin.
     await fill(page,'#sys-update [aria-label="Default channel URL"]','https://updates.example.com/next');
     await click(page,'#sys-update .maskfoot > .primary');
     check(await page.evaluate('stagedCommands().length===1&&stagedCommands()[0]==="set update url https://updates.example.com/next"'),'Unchanged signing key was replayed during URL edit');
     await click(page,'#discard');
     cli(['delete update']);changed=false;await refresh(page,selector);
     await wait(page,`document.querySelector(${JSON.stringify(selector)})?.value===''`);
    }
   });
   await test('named channel uses the same multiline key and backend at '+width,async()=>{
    await wait(page,`!document.querySelector('#toggleupchan').disabled&&typeof document.querySelector('#toggleupchan').onclick==='function'`);
    await click(page,'#toggleupchan');
    const box='#addupchanpanel';
    await fill(page,box+' [aria-label=Name]','qa-public-key');
    await fill(page,box+' [aria-label="Channel URL"]','https://updates.example.com/business');
    await fill(page,box+' [aria-label="Signing key"]',PEM);
    check(await page.evaluate(`document.querySelector('${box} [aria-label="Signing key"]').value===${JSON.stringify(PEM)}`),'Named key lost its newlines');
    await click(page,box+' .maskfoot > .primary');
    const commands=await page.evaluate('stagedCommands()');
    check(commands.length===2&&commands.every(c=>c.startsWith('set update channel qa-public-key ')&&!c.includes('\n')),'Named key produced an unsafe/different command path');
    await validate(page);await click(page,'#discard');
    check(!page.thrown.length&&!page.consoleMessages.some(r=>r.level==='error'),'Actual browser error');
   });
  }finally{
   if(changed)cli(['delete update']);
   check(readFileSync(process.env.CONSOLE_CONFIG).equals(before),'Fixture was not restored through the normal CLI');
   page.close();
  }
 }
}
