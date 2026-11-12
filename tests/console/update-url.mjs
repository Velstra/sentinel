// Real shared default/Add/Edit URL validation, not channel download coverage.
import {browser,signIn,sleep,test,check,equal} from './harness.mjs';
import {click} from './creation.mjs';
import {fill} from './update-key.mjs';
import {requireValidation} from './stage-contract.mjs';
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

const PEM='-----BEGIN PUBLIC KEY----- MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE= -----END PUBLIC KEY-----';
function cli(commands,{save=false,refused=false}={}){
 const result=spawnSync(process.env.CONSOLE_BINARY,['configure','--config',process.env.CONSOLE_CONFIG,'--no-apply'],{
  input:commands.concat(['commit'],save?['save']:[]).join('\n')+'\n',encoding:'utf8',timeout:15000,
  env:{...process.env,NO_COLOR:'1'},
 });
 const output=(result.stdout||'')+(result.stderr||'');
 check(!result.error&&result.status!==null,'Actual CLI failed to execute: '+output);
 if(refused)check(result.status!==0&&output.includes('https:// or file://'),'CLI did not refuse the actual URL scheme: '+output);
 else check(result.status===0&&output.includes('commit ok')&&!/^error:/im.test(output),'CLI refused valid channel commands: '+output);
}
async function wait(page,expression){
 const until=Date.now()+15000;
 while(Date.now()<until){if(await page.evaluate(expression))return;await sleep(50);}
 throw Error('Actual update form never ready: '+expression);
}
async function key(page,key){
 await page.send('Input.dispatchKeyEvent',{type:'keyDown',key,code:key,windowsVirtualKeyCode:key==='Tab'?9:13,...(key==='Enter'?{text:'\r'}:{})});
 await page.send('Input.dispatchKeyEvent',{type:'keyUp',key,code:key,windowsVirtualKeyCode:key==='Tab'?9:13});
}

export async function updateUrlTests(){
 check(process.env.CONSOLE_CONFIG&&process.env.CONSOLE_BINARY,'Only the actual private --no-apply fixture may be used');
 const before=readFileSync(process.env.CONSOLE_CONFIG),observations=[];
 for(const width of [1440,390,320]){
  const page=await browser({width,height:1000});
  try{
   cli(['set update channel qa-existing url https://updates.example.com/current',
    'set update channel qa-existing public-key '+JSON.stringify(PEM)],{save:true});
   const seeded=readFileSync(process.env.CONSOLE_CONFIG);
   await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});
   await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
   await page.evaluate('goto("system")');
   await wait(page,'!!document.querySelector(\'#sys-update [aria-label="Default channel URL"]\')?.getClientRects().length&&!document.querySelector("#toggleupchan").disabled');
   equal(await page.evaluate('innerWidth'),width,'URL viewport receipt is incorrect');
   for(const mode of ['default','add','edit']){
    const path=mode==='default'?'update':'update channel '+(mode==='add'?'qa-new':'qa-existing');
    const box=mode==='default'?'#sys-update':mode==='add'?'#addupchanpanel':'#upchanlist .editrow';
    if(mode==='add'){
     await click(page,'#toggleupchan');await fill(page,box+' [aria-label="Name"]','qa-new');
    }else if(mode==='edit'){
     await page.evaluate(`(()=>{const b=[...document.querySelectorAll('#upchanlist button')].find(n=>n.textContent==='Edit');if(!b)throw Error('Named channel Edit absent');b.id='qa-url-edit';})()`);
     await click(page,'#qa-url-edit');
    }
    const selector=box+' [aria-label="'+(mode==='default'?'Default channel URL':'Channel URL')+'"]';
    const primary=box+' .maskfoot > button.primary';
    if(mode!=='edit')await fill(page,box+' [aria-label="Signing key"]',PEM);
    for(const bad of ['javascript:alert(1)','http://updates.example.com/insecure','ftp://updates.example.com/release']){
     await test('update '+mode+' refuses '+bad.split(':')[0]+' in UI/API/CLI at '+width,async()=>{
      await fill(page,selector,bad);
      await click(page,primary);
      equal(await page.evaluate('stagedCommands()'),[],'Invalid scheme was staged');
      const state=await page.evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)}),ids=n.getAttribute('aria-describedby').split(/\\s+/),e=document.getElementById(n.getAttribute('aria-errormessage'));return{
       value:n.value,invalid:n.getAttribute('aria-invalid'),focused:document.activeElement===n,label:!!n.labels?.length,
       associated:ids.every(id=>!!document.getElementById(id))&&ids.includes(e?.id),error:e?.textContent,visible:!!e?.getClientRects().length,
       rect:(()=>{const r=n.getBoundingClientRect();return{left:r.left,right:r.right};})(),width:innerWidth};})()`);
      check(state.value===bad&&state.invalid==='true'&&state.focused&&state.label&&state.associated&&state.visible
       &&state.error==='Use an https:// or file:// update URL.'&&state.rect.left>=0&&state.rect.right<=state.width,
       'Inline refusal lost value/focus/association or clipped: '+JSON.stringify(state));
      const lines=['set '+path+' url '+bad,'set '+path+' public-key '+JSON.stringify(PEM)];
      const reply=await page.evaluate(`configure(${JSON.stringify(lines)})`);
      check(reply?.ok===false&&reply.output.includes('https:// or file://'),'API did not refuse URL scheme: '+JSON.stringify(reply));
      cli(lines,{refused:true});
      equal(readFileSync(process.env.CONSOLE_CONFIG).toString(),seeded.toString(),'Rejected URL mutated saved document');
      const folder=process.env.CONSOLE_SCREENSHOTS;
      if(folder&&bad.startsWith('javascript:')){mkdirSync(folder,{recursive:true});writeFileSync(folder+'/update-url-'+mode+'-invalid-'+width+'.png',Buffer.from(await page.screenshot(),'base64'));}
      observations.push({mode,width,url:bad,ui_refused:true,api_refused:true,cli_refused:true,focus_retained:true});
     });
    }
    for(const url of ['https://updates.example.com/release','file:///srv/sentinel/mirror']){
     await test('update '+mode+' accepts '+url.split(':')[0]+' after correction at '+width,async()=>{
      if(mode==='add'&&!await page.evaluate(`!!document.querySelector(${JSON.stringify(box)}).getClientRects().length`)){
       await wait(page,'!document.querySelector("#toggleupchan").disabled');
       await click(page,'#toggleupchan');await fill(page,box+' [aria-label="Name"]','qa-new');
       await fill(page,box+' [aria-label="Signing key"]',PEM);
      }
      await fill(page,selector,url);
      check(await page.evaluate(`document.querySelector(${JSON.stringify(selector)}).value===${JSON.stringify(url)}&&document.querySelector(${JSON.stringify(selector)}).getAttribute('aria-invalid')==='false'`),'Correction lost value or left a stale inline error');
      // Keyboard navigation and activation must use the same real Stage path.
      await page.evaluate(`document.querySelector(${JSON.stringify(primary)}).focus()`);await key(page,'Enter');
      const lines=await page.evaluate('stagedCommands()');
      check(lines.includes('set '+path+' url '+url),'Corrected URL did not stage its exact intended path: '+JSON.stringify(lines));
      requireValidation(await page.evaluate(`configure(${JSON.stringify(lines)})`));cli(lines);
      equal(readFileSync(process.env.CONSOLE_CONFIG).toString(),seeded.toString(),'Validation changed saved fixture');
      await click(page,'#discard');
      observations.push({mode,width,url,staged:lines,api_validated:true,cli_validated:true,keyboard_stage:true});
     });
    }
    if(mode==='add'&&await page.evaluate(`!!document.querySelector(${JSON.stringify(box)}).getClientRects().length`))await click(page,box+' .maskfoot > button:not(.primary)');
   }
   await test('update URL suite has no browser exceptions or HTTP 5xx failures at '+width,()=>{
    check(!page.thrown.length&&!page.consoleMessages.some(row=>row.level==='error'),'Browser error: '+page.thrown.join('\n'));
    check(!page.responses.some(row=>row.status>=500),'Unexpected server error');
   });
  }finally{
   page.close();cli(['delete update'],{save:true});
   check(readFileSync(process.env.CONSOLE_CONFIG).equals(before),'Private fixture was not restored through the normal CLI');
  }
 }
 const folder=process.env.CONSOLE_SCREENSHOTS;
 if(folder){mkdirSync(folder,{recursive:true});writeFileSync(folder+'/update-url-contract.json',JSON.stringify({observations,network_apply:false,scope:'UI/API/CLI validation only, not OTA download or reboot'},null,2));}
}
