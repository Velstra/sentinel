// No response fixtures: drive the booted native appliance's actual UI/API.
import {readFileSync, writeFileSync} from 'node:fs';
import {browser, signIn, sleep, check} from './harness.mjs';
const action=process.argv[2];
check(['check','stage','read'].includes(action),'invalid native browser action');
const page=await browser({width:1440,height:1000});
const panel='#react-system-updates';
// The probe kills node after 120 s and then has no output at all; finish
// first, with diagnostics, so a stalled step names itself.
const started=Date.now(), BUDGET=100000;
async function until(expression) {
 const deadline=Math.min(Date.now()+90000,started+BUDGET);
 while(Date.now()<deadline){const value=await page.evaluate(expression);if(value)return value;await sleep(100);}
 throw Error('Actual native UI state did not converge: '+expression);
}
// The console asks for one observation when System opens and then only when
// the operator presses Refresh; the API answers that first request with the
// stale cached observation while it re-observes in the background. So do what
// an operator does: refresh until the panel reports a current observation.
async function ensureFresh() {
 while(Date.now()<started+BUDGET){
  if(await page.evaluate('management.updates.fresh()'))return;
  await click('Refresh update status');
  const settle=Date.now()+3000;
  while(Date.now()<settle){if(await page.evaluate('management.updates.fresh()'))return;await sleep(100);}
 }
 throw Error('the update panel never reported a current observation');
}
async function click(label) {
 await until(`(()=>{const b=[...document.querySelectorAll('${panel} button')].find(b=>b.textContent===${JSON.stringify(label)});return !!b&&!b.disabled;})()`);
 const p=await page.evaluate(`(()=>{const b=[...document.querySelectorAll('${panel} button')].find(b=>b.textContent===${JSON.stringify(label)});if(!b||b.disabled)throw Error('native action not enabled');b.scrollIntoView({block:'center'});const r=b.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()`);
 await page.send('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...p});
 await page.send('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...p});
}
// Read-only state of the update panel and its controller, for a failure.
const DIAGNOSE=`(()=>{const p=document.querySelector('${panel}');const u=typeof management==='undefined'?undefined:management.updates;
 const safe=f=>{try{return f();}catch(e){return 'threw: '+e;}};const s=safe(()=>u?.getSnapshot());
 const o=s&&typeof s==='object'?s:{};
 return {location:location.href,signed_in:!document.getElementById('login')?.offsetParent,
  panel_text:p?p.textContent.slice(0,4000):null,
  buttons:p?[...p.querySelectorAll('button')].map(b=>({text:b.textContent,disabled:b.disabled})):null,
  fresh:safe(()=>u?.fresh()),permitted_check:safe(()=>u?.permitted('check')),
  controller:typeof s==='string'?s:{busy:o.busy,sending:o.sending,uncertain:o.uncertain,notice:o.notice,
   age_since_received_ms:o.receivedAt===undefined?null:performance.now()-o.receivedAt,
   observation:o.status?.observation,can_check:o.status?.can_check,can_stage:o.status?.can_stage}};})()`;
async function diagnose(failure) {
 const report=await page.evaluate(DIAGNOSE).catch(e=>({evaluate_failed:String(e)}));
 Object.assign(report,{action,error:String(failure),elapsed_ms:Date.now()-started,thrown:page.thrown,
  console:page.consoleMessages.slice(-40),failed_requests:page.failedRequests.slice(-20)});
 writeFileSync('/var/lib/sentinel/qa-native-ui-'+action+'-failure.json',JSON.stringify(report,null,1));
 await page.screenshot().then(png=>writeFileSync('/var/lib/sentinel/qa-native-ui-'+action+'-failure.png',Buffer.from(png,'base64'))).catch(()=>{});
 console.error('NATIVE_UI_FAILURE '+JSON.stringify(report));
}
try {
 await page.goto('http://127.0.0.1:8080/');
 await signIn(page,readFileSync('/var/lib/sentinel/api-token','utf8').trim());
 await page.evaluate('goto("system")');
 await ensureFresh();
 const before=await page.evaluate('management.updates.getSnapshot().status');
 if(action==='read') {
  check(before.current.permanent&&before.current.slot==='sentinel-b','native UI did not observe assessed B boot');
  check(await page.evaluate(`document.querySelector('${panel}').textContent.includes('Slot B')&&document.querySelector('${panel}').textContent.includes('Permanent')`),'actual boot identity was not rendered');
  check(await page.evaluate(`document.querySelector('${panel}').textContent.includes('Stage recorded on a previous boot.')&&!document.querySelector('${panel}').textContent.includes('Image staged during this boot.')`),'retained staging history contradicts the assessed current boot');
  console.log(JSON.stringify({passed:true,actual_browser:true,current:before.current}));
 } else {
  if(action==='stage') {
   await ensureFresh();
   await click('Review available update');
   const offered=await page.evaluate('management.updates.getSnapshot().review.offer');
   check(offered.id===before.offer.id,'actual native review changed the offer');
   check(await page.evaluate(`document.querySelector('${panel} .update-review').textContent.includes(${JSON.stringify(offered.verified.manifest.sha256)})`),'native UI omitted exact signed digest');
   await ensureFresh();
   await click('Download & stage update');
  } else {await ensureFresh();await click('Check signed channel');}
  const previous=before.jobs.map(j=>j.id);
  const job=await until(`(()=>{const jobs=management.updates.getSnapshot().status?.jobs||[];return jobs.find(j=>j.action===${JSON.stringify(action)}&&!${JSON.stringify(previous)}.includes(j.id)${action==='check'?"&&['checked','failed','interrupted'].includes(j.phase)":""});})()`);
  check(!job.error&&(action!=='check'||job.phase==='checked'),'actual native UI action refused: '+JSON.stringify(job));
  console.log(JSON.stringify({passed:true,actual_browser:true,job}));
 }
 await page.evaluate(`document.querySelector('${panel}').scrollIntoView({block:'start'})`);
 writeFileSync('/var/lib/sentinel/qa-native-ui-'+action+'.png',Buffer.from(await page.screenshot(),'base64'));
 check(page.thrown.length===0,page.thrown.join('\n'));
} catch (failure) {await diagnose(failure);throw failure;} finally {page.close();}
