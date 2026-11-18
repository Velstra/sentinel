// Focused real-API proof for the migrated React workflows. The complete console
// run additionally exercises every existing CLI-backed configuration form.
import {browser,signIn,sleep,summary,test,check} from './harness.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
import {managementTests} from './management.test.mjs';
const page=await browser({width:1440,height:1000});
try {
 await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
 await test('React owns all three management workflows and the global confirmation banner',async()=>{
  const mounts=await page.evaluate('({dashboard:!!document.querySelector("#react-dashboard [data-react-view=dashboard]"),flows:!!document.querySelector("#react-flows [data-react-view=flows]"),config:!!document.querySelector("#react-config [data-react-view=configuration]"),confirmation:!!document.querySelector("#react-confirmation #confirm-change")})');
  check(Object.values(mounts).every(Boolean),'React workflow missing: '+JSON.stringify(mounts));
 });
 await managementTests(page);
 await test('React document advisories are visible, literal and nonfatal through provisional apply', async()=>{
  const out=process.env.CONSOLE_SCREENSHOTS;
  const geometry=[];
  if(out)mkdirSync(out,{recursive:true});
  const click=async id=>{
   const point=await page.evaluate(`(()=>{const n=document.getElementById(${JSON.stringify(id)});n.scrollIntoView({block:"center"});const r=n.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()`);
   await page.send('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',buttons:1,clickCount:1,...point});
   await page.send('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',buttons:0,clickCount:1,...point});
  };
  const settled=async()=>{
   for(let i=0;i<100;i++){
    if(!await page.evaluate('management.getSnapshot().editor.busy')){await sleep(50);return;}
    await sleep(50);
   }
   throw Error('document action did not settle');
  };
  const snapshot=async name=>{
   if(out)writeFileSync(out+'/'+name+'.png',Buffer.from(await page.screenshot(),'base64'));
  };
  try {
   await page.evaluate(`(async()=>{
    if($("result").open)$("result").close();management.clearEditor();view="config";panel=null;await refresh();await management.loadEditor();await new Promise(resolve=>setTimeout(resolve,0));
    globalThis.__advisoryExecuted=false;
    const label='advisory <img src=x onerror=globalThis.__advisoryExecuted=true> '+('long-route-label-'.repeat(20));
    // An accept rule has a nonfatal connected-prefix advisory. New routed
    // destination-zone denies are deliberately rejected by admission.
    const extra='\\n[[interface]]\\nname="advisorywan"\\nzone="wan"\\naddress="198.18.110.11/24"\\n[[rule]]\\nname='+JSON.stringify(label)+'\\nfrom="lan"\\nto="wan"\\nproto="tcp"\\nport=23\\naction="accept"\\n';
    const n=$("toml-candidate");n.value=management.getSnapshot().editor.baseline+extra;n.dispatchEvent(new Event("input",{bubbles:true}));
   })()`);
   await click('toml-validate');await settled();
   const reviewed=await page.evaluate(`(()=>{
    const n=$("toml-warnings"),e=management.getSnapshot().editor;
    return{visible:!!n?.getClientRects().length,text:n?.textContent||"",literal:!n?.querySelector('img')&&!globalThis.__advisoryExecuted,feedback:$("toml-feedback").textContent,invalid:$("toml-candidate").getAttribute('aria-invalid'),applyDisabled:$("toml-apply").disabled,warnings:e.warnings};
   })()`);
   check(reviewed.visible&&reviewed.text.includes('connected destination prefixes (198.18.110.0/24)'),'React discarded real connected-prefix advisories: '+JSON.stringify(reviewed));
   check(reviewed.literal&&reviewed.text.includes('<img src=x'),'HTML-like advisory text was interpreted as markup');
   check(reviewed.feedback.includes('Valid configuration. Nothing applied.')&&reviewed.invalid!=='true'&&!reviewed.applyDisabled,'nonfatal advice blocked the normal review/apply lifecycle');
   for(const width of [1440,390]) {
    await page.send('Emulation.setDeviceMetricsOverride',{width,height:width===390?844:1000,deviceScaleFactor:1,mobile:false});
    for(const theme of ['dark','light']) {
     await page.evaluate('document.documentElement.setAttribute("data-theme",'+JSON.stringify(theme)+');$("toml-warnings").scrollIntoView({block:"center"})');await sleep(100);
     const bounds=await page.evaluate(`(()=>{const n=$("toml-warnings"),r=n.getBoundingClientRect(),long=[...n.querySelectorAll('li')].find(li=>li.textContent.includes('long-route-label'));return{viewport:innerWidth,width:document.documentElement.scrollWidth,left:r.left,right:r.right,overflow:n.scrollWidth>n.clientWidth,lines:long?long.getBoundingClientRect().height/parseFloat(getComputedStyle(long).lineHeight):0};})()`);
     check(bounds.viewport===width&&bounds.width<=width&&bounds.left>=0&&bounds.right<=width&&!bounds.overflow&&bounds.lines>1,'advisories fail wrap/bounds '+width+'/'+theme+': '+JSON.stringify(bounds));
     geometry.push({theme,...bounds});
     await snapshot('react-advisories-'+theme+'-'+width);
    }
   }
   await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
   await page.evaluate('(()=>{const n=$("toml-candidate");n.value+="\\n# changed draft\\n";n.dispatchEvent(new Event("input",{bubbles:true}));})()');await sleep(50);
   check(await page.evaluate('!$("toml-warnings")&&management.getSnapshot().editor.warnings.length===0'),'draft changes retained stale advisories');
   await click('toml-validate');await settled();
   await click('toml-apply');await settled();
   const admitted=await page.evaluate('({pending:management.getSnapshot().pending?.id,warningVisible:!!$("toml-warnings")?.getClientRects().length,applyDisabled:$("toml-apply").disabled})');
   check(admitted.pending&&admitted.warningVisible&&admitted.applyDisabled,'provisional admission lost advice or its confirmation guard: '+JSON.stringify(admitted));
   await page.evaluate('$("toml-warnings").scrollIntoView({block:"center"})');await snapshot('react-advisories-provisional');
   await page.evaluate('management.finishTransaction("revert")');await sleep(50);
   check(await page.evaluate('!management.getSnapshot().pending&&!$("toml-warnings")'),'rollback retained stale candidate advisories');
   if(out)writeFileSync(out+'/react-advisories.json',JSON.stringify({schema:1,geometry,literal:reviewed.literal,nonfatal:true,draft_invalidates:true,provisional_preserves:true,revert_invalidates:true},null,2));
  } finally {
   await page.evaluate('(async()=>{await management.refreshTransaction();if(management.getSnapshot().pending)await management.finishTransaction("revert");management.clearEditor();document.documentElement.setAttribute("data-theme","dark");})()');
   await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  }
 });
 await test('peer navigation hides the local editor while preserving its draft',async()=>{
  const result=await page.evaluate(`(async()=>{
   view="config";panel=null;await refresh();await management.loadEditor();
   management.changeCandidate(management.getSnapshot().editor.baseline.replace(/hostname = "[^"]+"/,'hostname = "retained-peer-draft"'));
   const local=target;target="test-peer-view";renderLive();await new Promise(resolve=>setTimeout(resolve,0));
   const hidden=!$("toml-candidate");target=local;renderLive();await new Promise(resolve=>setTimeout(resolve,0));
   const retained=$("toml-candidate").value.includes("retained-peer-draft")&&dirty.has("toml-editor");management.clearEditor();return{hidden,retained};
  })()`);
  check(result.hidden&&result.retained,'peer navigation exposed or discarded the local draft: '+JSON.stringify(result));
 });
 await test('React management views keep canonical themes, keyboard access and narrow layouts',async()=>{
  const out=process.env.CONSOLE_SCREENSHOTS;
  if(out)mkdirSync(out,{recursive:true});
  const screenshot=async name=>{if(out)writeFileSync(out+'/'+name+'.png',Buffer.from(await page.screenshot(),'base64'));};
  await page.evaluate('(async()=>{view="dashboard";panel=null;await refresh();})()');
  await sleep(1500);await screenshot('react-dashboard');
  await page.evaluate('(async()=>{view="flows";panel=null;await refresh();})()');
  await screenshot('react-flow-inspector');
  await page.evaluate('(async()=>{view="config";panel=null;await refresh();await management.loadEditor();})()');await sleep(50);
  await page.evaluate(`(()=>{const n=$("toml-candidate");n.value=n.value.replace(/hostname = "[^"]+"/, 'hostname = "proposed-edge"');n.dispatchEvent(new Event("input",{bubbles:true}));document.querySelector("#react-config details summary").click();})()`);await sleep(50);
  const review=await page.evaluate('({removed:!!document.querySelector(".diff-removed"),added:!!document.querySelector(".diff-added"),font:getComputedStyle($("toml-candidate")).fontFamily})');
  check(review.removed&&review.added&&review.font.includes('Mono'),'the side-by-side visual review did not render');
  await screenshot('react-config-editor');
  await page.evaluate('document.querySelector("#react-config .visual-diff").scrollIntoView({block:"center"})');await screenshot('react-config-diff');
  await page.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});
  for(const theme of ['light','dark']) {
   await page.evaluate('document.documentElement.setAttribute("data-theme",'+JSON.stringify(theme)+');$("toml-candidate").scrollIntoView({block:"center"})');await sleep(200);
   const width=await page.evaluate('({content:document.documentElement.scrollWidth,viewport:innerWidth,resize:getComputedStyle($("toml-candidate")).resize,scrollbar:getComputedStyle(document.documentElement).scrollbarColor})');
   check(width.content<=width.viewport,'the editor overflows the '+theme+' narrow viewport: '+JSON.stringify(width));check(width.resize==='none','the editor bypasses the shared textarea contract');
   check(width.scrollbar!=='auto','the application scrollbar has no theme');await screenshot('react-config-'+theme+'-narrow');
  }
  await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await page.evaluate('management.clearEditor();document.documentElement.setAttribute("data-theme","light")');await sleep(50);
  await page.evaluate('$("toml-load").focus()');
  await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});for(let i=0;i<40&&!await page.evaluate('management.getSnapshot().editor.visible');i++)await sleep(50);
  check(await page.evaluate('management.getSnapshot().editor.visible'),'keyboard activation did not reveal the document');
  await page.evaluate('management.clearEditor()');
 });
 await test('dashboard and flow controls remain usable on narrow screens in both themes',async()=>{
  const out=process.env.CONSOLE_SCREENSHOTS;
  await page.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});
  await page.send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  for(const theme of ['light','dark']) {
   await page.evaluate('document.documentElement.setAttribute("data-theme",'+JSON.stringify(theme)+')');
   for(const destination of ['dashboard','flows']) {
    await page.evaluate('(async()=>{view='+JSON.stringify(destination)+';panel=null;await refresh();scrollTo(0,0);})()');await sleep(200);
    const layout=await page.evaluate(`(()=>{
      const nodes=[...document.querySelectorAll('[data-react-view="dashboard"] .throughput-strip,[data-react-view="flows"] .toolbar input,[data-react-view="flows"] .toolbar select')].filter(n=>n.getClientRects().length);
      return {width:document.documentElement.scrollWidth,viewport:innerWidth,controls:nodes.every(n=>{const r=n.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth;}),scrollable:document.documentElement.scrollHeight>innerHeight};
    })()`);
    check(layout.width<=layout.viewport&&layout.controls,'narrow '+destination+' '+theme+' clipped controls: '+JSON.stringify(layout));
    check(layout.scrollable,'long '+destination+' content lost its page scroller');
    if(destination==='flows') {
     await page.evaluate('$("flow-action").focus()');
     await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
     await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
     await sleep(30);
     check(await page.evaluate('$("flow-action").value==="accept"'),'native action select lost keyboard selection');
     await page.evaluate('$("flow-action").value="";$("flow-action").dispatchEvent(new Event("change",{bubbles:true}))');
    }
    if(out)writeFileSync(out+'/react-'+destination+'-'+theme+'-narrow.png',Buffer.from(await page.screenshot(),'base64'));
   }
  }
  await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await page.send('Emulation.setEmulatedMedia',{features:[]});
 });
 await test('mobile navigation opens on demand, restores focus and opens the selected destination',async()=>{
  await page.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});
  await page.evaluate('(async()=>{goto("dashboard");await new Promise(r=>setTimeout(r,50));scrollTo(0,0);})()');
  check(await page.evaluate('getComputedStyle($("navcontents")).display==="none"&&$("navtoggle").getAttribute("aria-expanded")==="false"'),'mobile navigation should start closed');
  await page.evaluate('$("navtoggle").click();$("navsearch").focus()');
  check(await page.evaluate('$("navtoggle").getAttribute("aria-expanded")==="true"&&document.activeElement.id==="navsearch"'),'mobile menu did not reveal accessible search');
  await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  check(await page.evaluate('document.activeElement.id==="navtoggle"&&getComputedStyle($("navcontents")).display==="none"'),'Escape did not close navigation and restore focus');
  await page.evaluate('$("navtoggle").click();$("navsearch").value="WireGuard";$("navsearch").dispatchEvent(new Event("input",{bubbles:true}))');
  check(await page.evaluate('!$("navclear").classList.contains("hidden")&&$("nav").textContent.includes("WireGuard")'),'navigation search did not expose its result and Clear action');
  await page.evaluate('$("navclear").click()');
  check(await page.evaluate('$("navsearch").value===""&&document.activeElement.id==="navsearch"'),'Clear did not restore navigation and focus');
  await page.evaluate('[...$("nav").querySelectorAll("button")].find(b=>b.textContent.trim()==="Network").click()');await sleep(150);
  check(await page.evaluate('view==="interfaces"&&$("navtoggle").getAttribute("aria-expanded")==="false"&&document.activeElement===$("pagehead").querySelector("h2")'),'destination selection did not close navigation and focus the destination');
  await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
 });
 await test('overview tasks use the real navigation and keep packet inspection separate from rule editing',async()=>{
  await page.evaluate('(async()=>{goto("dashboard");await new Promise(r=>setTimeout(r,100));})()');
  await page.evaluate('document.querySelector(".overview-metric").click()');await sleep(100);
  check(await page.evaluate('view==="interfaces"&&document.activeElement===$("pagehead").querySelector("h2")&&scrollY===0'),'overview navigation must open and focus the destination at the top');
  await page.evaluate('goto("rules")');await sleep(100);
  check(await page.evaluate('$("view-rules").getClientRects().length>0&&!$("react-flows").getClientRects().length'),'editing rules should not be preceded by the live packet stream');
  await page.evaluate('goto("flows")');await sleep(100);
  check(await page.evaluate('$("react-flows").getClientRects().length>0&&$("pagehead").textContent.includes("Live packets")'),'packet inspection has no dedicated, reachable view');
  check(await page.evaluate('[...$("nav").querySelectorAll(".navitem.on")].some(b=>b.textContent.includes("Policy"))'),'the active category is not highlighted');
 });
 await test('sign-out clears sensitive navigation searches and matches before the next session',async()=>{
  await page.evaluate(`(async()=>{
   $("navsearch").value="10.0.0.1";$("navsearch").dispatchEvent(new Event("input",{bubbles:true}));
   const readLeaves=leaves;let release;const held=new Promise(resolve=>release=resolve);
   leaves=()=>held;const pending=buildSearchIndex();signOut("");
   release([{path:["interface","private-old-member"],value:"private-old-address",node:"interface"}]);
   try{await pending;}finally{leaves=readLeaves;}
  })()`);
  check(await page.evaluate('$("navsearch").value===""&&$("matches").textContent===""&&$("navclear").classList.contains("hidden")&&searchIndex.length===0&&$("navtoggle").getAttribute("aria-expanded")==="false"'),'the next session can see the previous navigation query or matches');
  await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
 });
 await test('all console requests stay on the selected appliance',()=>{
  const origin=new URL(process.env.CONSOLE_URL).origin;
  check(page.requests.filter(url=>/^https?:/.test(url)).every(url=>new URL(url).origin===origin),'a console request left the appliance');
 });
 await test('the console has no uncaught browser errors',()=>{
  if(process.env.CONSOLE_SCREENSHOTS)writeFileSync(process.env.CONSOLE_SCREENSHOTS+'/react-browser-errors.json',JSON.stringify({uncaught:page.thrown,console_errors:page.consoleMessages.filter(item=>item.level==='error'),console_warnings:page.consoleMessages.filter(item=>item.level==='warning'),http_error_responses:page.responses.filter(item=>item.status>=400)},null,2));
  check(!page.thrown.length,page.thrown.join('\n'));
 });
}finally{page.close();}
process.exitCode=summary()?1:0;
