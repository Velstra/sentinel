// No response fixtures: drive the booted native appliance's actual UI/API.
import {readFileSync, writeFileSync} from 'node:fs';
import {browser, signIn, sleep, check} from './harness.mjs';
const action=process.argv[2];
check(['check','stage','read'].includes(action),'invalid native browser action');
const page=await browser({width:1440,height:1000});
const panel='#react-system-updates';
async function until(expression) {
 const deadline=Date.now()+90000;
 while(Date.now()<deadline){const value=await page.evaluate(expression);if(value)return value;await sleep(100);}
 throw Error('Actual native UI state did not converge: '+expression);
}
async function click(label) {
 await until(`(()=>{const b=[...document.querySelectorAll('${panel} button')].find(b=>b.textContent===${JSON.stringify(label)});return !!b&&!b.disabled;})()`);
 const p=await page.evaluate(`(()=>{const b=[...document.querySelectorAll('${panel} button')].find(b=>b.textContent===${JSON.stringify(label)});if(!b||b.disabled)throw Error('native action not enabled');b.scrollIntoView({block:'center'});const r=b.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()`);
 await page.send('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...p});
 await page.send('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...p});
}
try {
 await page.goto('http://127.0.0.1:8080/');
 await signIn(page,readFileSync('/var/lib/sentinel/api-token','utf8').trim());
 await page.evaluate('goto("system")');
 await until('management.updates.fresh()');
 const before=await page.evaluate('management.updates.getSnapshot().status');
 if(action==='read') {
  check(before.current.permanent&&before.current.slot==='sentinel-b','native UI did not observe assessed B boot');
  check(await page.evaluate(`document.querySelector('${panel}').textContent.includes('Slot B')&&document.querySelector('${panel}').textContent.includes('Permanent')`),'actual boot identity was not rendered');
  console.log(JSON.stringify({passed:true,actual_browser:true,current:before.current}));
 } else {
  if(action==='stage') {
   await click('Review available update');
   const offered=await page.evaluate('management.updates.getSnapshot().review.offer');
   check(offered.id===before.offer.id,'actual native review changed the offer');
   check(await page.evaluate(`document.querySelector('${panel} .update-review').textContent.includes(${JSON.stringify(offered.verified.manifest.sha256)})`),'native UI omitted exact signed digest');
   await click('Download & stage update');
  } else {await click('Check signed channel');}
  const previous=before.jobs.map(j=>j.id);
  const job=await until(`(()=>{const jobs=management.updates.getSnapshot().status?.jobs||[];return jobs.find(j=>j.action===${JSON.stringify(action)}&&!${JSON.stringify(previous)}.includes(j.id)${action==='check'?"&&['checked','failed','interrupted'].includes(j.phase)":""});})()`);
  check(!job.error&&(action!=='check'||job.phase==='checked'),'actual native UI action refused: '+JSON.stringify(job));
  console.log(JSON.stringify({passed:true,actual_browser:true,job}));
 }
 await page.evaluate(`document.querySelector('${panel}').scrollIntoView({block:'start'})`);
 writeFileSync('/var/lib/sentinel/qa-native-ui-'+action+'.png',Buffer.from(await page.screenshot(),'base64'));
 check(page.thrown.length===0,page.thrown.join('\n'));
} finally {page.close();}
