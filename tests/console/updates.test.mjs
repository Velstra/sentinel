// Actual console/API off-box refusal, followed by explicitly isolated browser
// response fixtures for UI states. Fixtures are NOT native OTA certification.
import {browser, signIn, sleep, test, check, summary} from './harness.mjs';
import {mkdirSync, writeFileSync} from 'node:fs';
const page = await browser({width:1440, height:1000});
const panel = '#react-system-updates';
async function until(expression) {
 const deadline=Date.now()+15000;
 while(Date.now()<deadline) { if(await page.evaluate(expression))return; await sleep(50); }
 throw Error('Update UI did not converge: '+expression);
}
async function button(label) {
 const point=await page.evaluate(`(()=>{const b=[...document.querySelectorAll('${panel} button')].find(n=>n.textContent===${JSON.stringify(label)});if(!b||b.disabled)throw Error('Button unavailable');b.scrollIntoView({block:'center'});const r=b.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()`);
 await page.send('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...point});
 await page.send('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...point});
}
async function capture(name) {
 const folder=process.env.CONSOLE_SCREENSHOTS;
 if(folder){mkdirSync(folder,{recursive:true});writeFileSync(folder+'/'+name+'.png',Buffer.from(await page.screenshot(),'base64'));}
}
try {
 await page.goto(process.env.CONSOLE_URL); await signIn(page, process.env.CONSOLE_TOKEN);
 await page.evaluate('goto("system")');
 await test('actual off-box API explicitly refuses operational updates without a native appliance',async()=>{
  await until(`document.querySelector('${panel}').textContent.includes('Off-box and no-apply')`);
  const observed=await page.evaluate(`(async()=>{const r=await api('/api/v1/system/updates');return r.json();})()`);
  check(!observed.can_check&&!observed.can_stage&&observed.unavailable==='unsupported-runtime','off-box adapter offered writes');
  check(await page.evaluate(`Array.from(document.querySelectorAll('${panel} button')).filter(n=>/Check signed|Review available/.test(n.textContent)).every(n=>n.disabled)`),'off-box buttons enabled');
  await capture('updates-offbox-refusal');
 });
 // Simulate only the operational endpoint response. Config, auth, navigation
 // and the embedded production React controls still use the real local API.
 await page.evaluate(`(()=>{
  const hash=c=>c.repeat(64);
  window.qaUpdateState={schema:1,generation:hash('a'),current:{release:'v0.9.0-lts',slot:'sentinel-a',permanent:true,selected_entry:'sentinel_v0.9.0-lts.efi',next_entry:'sentinel_v0.9.0-lts.efi'},
   mutation_context:{boot_id:'00000000-0000-0000-0000-000000000001',mutation_epoch:hash('c'),config_revision:hash('d'),public_key_sha256:hash('e'),release:'v0.9.0-lts',slot:'sentinel-a',verity:hash('f'),selected_entry:'sentinel_v0.9.0-lts.efi',next_entry:'sentinel_v0.9.0-lts.efi',uki_sha256:hash('1'),verity_guid:'00000000-0000-0000-0000-000000000002',store_guid:'00000000-0000-0000-0000-000000000003',permanent:true},
   offer:{id:hash('b'),verified:{manifest:{version:'v1.0.0-lts',image:'sentinel_v1.0.0-lts.raw',sha256:hash('2')},manifest_sha256:hash('3'),public_key_sha256:hash('e')}},
   jobs:[],can_check:true,can_stage:true,unavailable:null,observation:{state:'fresh',age_ms:0}};
  window.qaUpdatePosts=[];window.qaUpdateMode='accepted';
  const original=window.fetch;
  window.fetch=async(path,options)=>{
   if(path==='/api/v1/system/updates')return new Response(JSON.stringify(window.qaUpdateState));
   if(path==='/api/v1/system/updates/stage'||path==='/api/v1/system/updates/check'){
    const request=JSON.parse(options.body);window.qaUpdatePosts.push({path,request,authorization:options.headers.Authorization});
    if(window.qaUpdateMode==='lost')throw Error('disposable transfer uncertainty');
    const job={id:hash('8'),request_id:request.request_id,action:path.endsWith('stage')?'stage':'check',phase:'accepted',error:null,message:null};
    window.qaUpdateState.jobs=[job];window.qaUpdateState.can_stage=false;window.qaUpdateState.can_check=false;window.qaUpdateState.generation=hash('9');
    return new Response(JSON.stringify(job),{status:202});
   }
   return original(path,options);
  };
 })()`);
 await button('Refresh update status');
 await until(`!document.querySelector('${panel}').textContent.includes('Off-box and no-apply')`);
 await test('actual UI reviews exact signed identity and submits one CAS-bound Stage with bearer auth',async()=>{
  await button('Review available update');
  await until(`!!document.querySelector('${panel} .update-review')`);
  check(await page.evaluate(`document.querySelector('${panel} .update-review').textContent.includes('2'.repeat(64))`),'review omitted exact signed image hash');
  await capture('updates-signed-review-desktop');
  await button('Cancel update review');
  await until(`!document.querySelector('${panel} .update-review')`);
  await button('Review available update');
  await button('Download & stage update');
  await until(`document.querySelector('${panel}').textContent.includes('stage · accepted')`);
  const posts=await page.evaluate('window.qaUpdatePosts');
  check(posts.length===1&&posts[0].path.endsWith('/stage')&&posts[0].authorization==='Bearer '+process.env.CONSOLE_TOKEN,'duplicate, unauthenticated or wrong Stage request');
  check(posts[0].request.offer_id==='b'.repeat(64)&&posts[0].request.expected_generation==='a'.repeat(64)&&posts[0].request.expected.config_revision==='d'.repeat(64),'review context silently replaced');
  check(Object.keys(posts[0].request).sort().join(',')==='expected,expected_generation,offer_id,request_id','Stage offered an extra bypass');
 });
 await test('signed review uses canonical themes and contains long digests at desktop and narrow widths',async()=>{
  await page.evaluate('window.qaUpdateState.can_stage=true;window.qaUpdateState.can_check=true;window.qaUpdateState.jobs=[]');
  await button('Refresh update status');await until(`!management.updates.getSnapshot().busy`);
  await button('Review available update');
  for(const width of [1440,390,320])for(const theme of ['light','dark']){
   await page.send('Emulation.setDeviceMetricsOverride',{width,height:844,deviceScaleFactor:1,mobile:false});
   await page.evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)});document.querySelector('${panel} .update-review').scrollIntoView({block:'center'})`);
   const geometry=await page.evaluate(`(()=>{const p=document.querySelector('${panel}');return{width:innerWidth,scroll:document.documentElement.scrollWidth,controls:[...p.querySelectorAll('button')].filter(b=>b.getClientRects().length).map(b=>{const r=b.getBoundingClientRect();return{left:r.left,right:r.right};})};})()`);
   check(geometry.scroll<=geometry.width&&geometry.controls.every(r=>r.left>=0&&r.right<=geometry.width),'clipped '+width+' '+theme+': '+JSON.stringify(geometry));
   await capture('updates-review-'+width+'-'+theme);
  }
  await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await button('Cancel update review');
 });
 await test('a lost response blocks new submissions and only read-only refresh can recover it',async()=>{
  await page.evaluate('window.qaUpdateMode="lost"');
  await until(`!management.updates.getSnapshot().busy`);await button('Refresh update status');
  await until(`management.updates.permitted('stage')`);
  await button('Review available update'); await button('Download & stage update');
  await until(`document.querySelector('${panel}').textContent.includes('Request correlation:')`);
  const correlation=await page.evaluate('window.qaUpdatePosts.at(-1).request.request_id');
  check(await page.evaluate(`Array.from(document.querySelectorAll('${panel} button')).filter(n=>/Check signed|Review available/.test(n.textContent)).every(n=>n.disabled)`),'unknown write outcome permits another update');
  await button('Refresh update status');
  check((await page.evaluate('window.qaUpdatePosts')).length===2,'refresh retried a mutation');
  await page.evaluate(`window.qaUpdateState.jobs=[{id:'8'.repeat(64),request_id:${JSON.stringify(correlation)},action:'stage',phase:'interrupted',error:'write-outcome-unknown',message:'Inspect boot selection before rebooting.'}];window.qaUpdateState.can_stage=false;window.qaUpdateState.can_check=false`);
  await until(`!management.updates.getSnapshot().busy`);await button('Refresh update status');
  await until(`document.querySelector('${panel}').textContent.includes('Inspect boot selection before rebooting.')`);
  await capture('updates-write-uncertainty');
 });
 await test('the changed operational console emits no uncaught or console errors',async()=>{
  check(page.thrown.length===0,page.thrown.join('\n'));
  check(page.consoleMessages.filter(m=>m.level==='error').length===0,'browser console errors');
 });
} finally {page.close();}
process.exitCode=summary()?1:0;
