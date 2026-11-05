// Real-browser regressions for shared controls and the responsive settings shell.
// Use tests/console/run.sh: all mutations target an isolated --no-apply API.
import {browser,signIn,sleep,test,check,equal,summary} from './harness.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
const page=await browser({width:1440,height:1000});
const go=async key=>{await page.evaluate(`goto(${JSON.stringify(key)})`);await sleep(250);};
try {
 await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
 await test('switches use completed click activation, including assistive and keyboard clicks',async()=>{
  await go('ha');
  const result=await page.evaluate(`(()=>{
   const button=document.querySelector('#haform button[role=switch]');
   const widget=button.closest('.switch');widget.value='false';
   button.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,pointerType:'touch'}));
   button.dispatchEvent(new PointerEvent('pointercancel',{bubbles:true,pointerType:'touch'}));
   const cancelled=widget.value;widget.value='false';button.click();
   return {cancelled,clicked:widget.value};})()`);
  equal(result,{cancelled:'false',clicked:'true'},'a cancelled press must not mutate, a native click must toggle');
  await page.evaluate("document.querySelector('#haform button[role=switch]').focus()");
  await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:' ',code:'Space',windowsVirtualKeyCode:32});
  await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:' ',code:'Space',windowsVirtualKeyCode:32});
  check(await page.evaluate("document.querySelector('#haform .switch').value==='false'"),'Space must toggle exactly once');
 });
 await test('out-of-range numbers cannot be staged and receive associated inline errors',async()=>{
  await go('routing:bgp');
  const result=await page.evaluate(`(()=>{
   staged=[];dirty.clear();renderStaged();
   const input=document.querySelector('#bgpglobal input[type=number]');
   input.value='4294967296';input.dispatchEvent(new Event('input',{bubbles:true}));
   document.querySelector('#bgpglobal .maskfoot .primary').click();
   const error=document.getElementById(input.getAttribute('aria-errormessage'));
   return {staged:staged.length,invalid:input.getAttribute('aria-invalid'),error:error?.textContent,
    focused:document.activeElement===input,kept:input.value};})()`);
  check(result.staged===0&&result.invalid==='true'&&result.error&&result.focused&&result.kept==='4294967296',JSON.stringify(result));
  const repaired=await page.evaluate(`(()=>{const input=document.querySelector('#bgpglobal input[type=number]');
   input.value='65010';input.dispatchEvent(new Event('input',{bubbles:true}));
   document.querySelector('#bgpglobal .maskfoot .primary').click();
   const out={invalid:input.getAttribute('aria-invalid'),commands:staged.flatMap(s=>s.cmds)};
   staged=[];dirty.clear();renderStaged();return out;})()`);
  check(repaired.invalid!=='true'&&repaired.commands.includes('set protocols bgp local-as 65010'),JSON.stringify(repaired));
 });
 await test('suggestion disclosure has an accessible name, keyboard focus and Escape recovery',async()=>{
  await go('routing:bgp');
  await page.evaluate(`(()=>{const holder=document.createElement('div');holder.id='ux-combo';
    holder.append(comboWidget(el('input',{'aria-label':'Peer source'}),['192.0.2.1','192.0.2.2'],'Peer source'));
    document.querySelector('#bgpglobal').prepend(holder);})()`);
  const trigger=await page.evaluate(`(()=>{const b=document.querySelector('#ux-combo .caret');b.focus();b.click();
   return {name:b.getAttribute('aria-label'),expanded:b.getAttribute('aria-expanded'),controls:!!document.getElementById(b.getAttribute('aria-controls'))};})()`);
  check(trigger.name&&trigger.expanded==='true'&&trigger.controls,JSON.stringify(trigger));
  await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
  check(await page.evaluate("document.activeElement.matches('#ux-combo .choice')"),'ArrowDown should focus a suggestion');
  await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  check(await page.evaluate("document.activeElement.matches('#ux-combo .caret')&&document.querySelector('#ux-combo .caret').getAttribute('aria-expanded')==='false'"),'Escape should close and restore focus');
  await page.evaluate("document.querySelector('#ux-combo').remove()");
 });
 await test('update URLs reject incomplete addresses without losing the draft',async()=>{
  await go('system');
  const state=await page.evaluate(`(()=>{staged=[];dirty.clear();renderStaged();
   const input=document.querySelector('#sys-update input[type=url]');
   input.value='not-an-address';input.dispatchEvent(new Event('input',{bubbles:true}));
   document.querySelector('#sys-update .maskfoot .primary').click();
   const rejected=staged.length===0&&input.getAttribute('aria-invalid')==='true'&&document.activeElement===input;
   input.value='https:'+'//updates.example.com/community';input.dispatchEvent(new Event('input',{bubbles:true}));
   document.querySelector('#sys-update .maskfoot .primary').click();
   const accepted=stagedCommands().some(c=>c.includes('updates.example.com/community'))&&input.getAttribute('aria-invalid')==='false';
   staged=[];dirty.clear();renderStaged();return{rejected,accepted};})()`);
  check(state.rejected&&state.accepted,JSON.stringify(state));
 });
 await test('rule dialogs retain port ranges after visiting an unrelated number form',async()=>{
  await go('routing:bgp');await go('rules');
  const state=await page.evaluate(`(()=>{staged=[];dirty.clear();renderStaged();
   [...document.querySelectorAll('#rulelist button')].find(b=>b.textContent==='Edit').click();
   const widget=editing.widgets[editing.fields.findIndex(f=>f[0]==='port')];
   const input=widget.matches('input')?widget:widget.querySelector('input');
   const type=input.type;widget.value='8000-8100';input.dispatchEvent(new Event('input',{bubbles:true}));
   document.querySelector('#applysave').click();
   const commands=stagedCommands(),closed=!document.querySelector('#editor').open;
   staged=[];dirty.clear();renderStaged();return{type,commands,closed};})()`);
  check(state.type==='text'&&state.closed&&state.commands.some(c=>c.endsWith('port 8000-8100')),JSON.stringify(state));
 });
 await test('failed live commands show honest status, expandable details and a working retry',async()=>{
  await go('routing:ospf');
  const state=await page.evaluate(`(async()=>{const original=text;try{
   text=async()=>{throw Error('synthetic diagnostic: source unavailable');};
   await showInto('show-ospf','/api/v1/show/protocols/ospf');
   const notice=document.querySelector('[data-diagnostic-for="show-ospf"]');
   const details=notice?.querySelector('details');
   const folded=notice?.textContent.includes('Status unavailable')&&!details?.open&&document.querySelector('#show-ospf').classList.contains('hidden');
   details?.querySelector('summary').click();const revealed=details?.open&&details.textContent.includes('synthetic diagnostic');
   text=async()=> 'Recovered protocol state';notice?.querySelector('button').click();
   await new Promise(resolve=>setTimeout(resolve,0));
   const recovered=!document.querySelector('[data-diagnostic-for="show-ospf"]')&&document.querySelector('#show-ospf').textContent==='Recovered protocol state';
   return{folded,revealed,recovered};
  }finally{text=original;await showInto('show-ospf','/api/v1/show/protocols/ospf');}})()`);
  check(Object.values(state).every(Boolean),JSON.stringify(state));
 });
 await test('new prefix-list and route-map names have real labels and usable examples',async()=>{
  for(const [key,id] of [['routepolicy:prefix','plnew'],['routepolicy:maps','rmnew']]){
   await go(key);
   const state=await page.evaluate(`(()=>{const n=document.getElementById(${JSON.stringify(id)});n.labels?.[0]?.click();
    return {label:n.labels?.[0]?.textContent,focused:document.activeElement===n,placeholder:n.placeholder};})()`);
   check(state.label&&state.focused&&state.placeholder&&!state.placeholder.startsWith('or '),JSON.stringify(state));
  }
 });
 await test('policy sequences are bounded numbers and route/peer identifiers explain their format',async()=>{
  for(const [key,toggle,id] of [['routepolicy:prefix','togglepl','addplpanel'],['routepolicy:maps','togglerm','addrmpanel']]){
   await go(key);
   const state=await page.evaluate(`(()=>{const toggle=document.getElementById(${JSON.stringify(toggle)});
    if(toggle.textContent!=='Cancel')toggle.click();
    const box=document.getElementById(${JSON.stringify(id)}),input=box.querySelector('input');
    input.value='4294967296';input.dispatchEvent(new Event('input',{bubbles:true}));
    return{type:input.type,min:input.min,max:input.max,label:input.getAttribute('aria-label'),invalid:input.getAttribute('aria-invalid')};})()`);
   check(state.type==='number'&&state.min==='0'&&state.max==='4294967295'&&state.label==='Sequence'&&state.invalid==='true',JSON.stringify(state));
  }
  for(const [key,toggle,id,label] of [['routing:static','toggleroute','addroutepanel','Destination prefix'],['routing:bgp','togglebgp','addbgppanel','Neighbour IP address']]){
   await go(key);
   const state=await page.evaluate(`(async()=>{document.getElementById(${JSON.stringify(toggle)}).click();await new Promise(resolve=>setTimeout(resolve,50));
    const input=document.getElementById(${JSON.stringify(id)}).querySelector('input');return{label:input.getAttribute('aria-label'),placeholder:input.placeholder};})()`);
   check(state.label===label&&state.placeholder.startsWith('e.g. '),JSON.stringify(state));
  }
 });
 await test('settings rows align controls even when adjacent helper text wraps',async()=>{
  await go('routing:bgp');
  const rows=await page.evaluate(`(()=>{const grid=document.createElement('div');grid.className='grid';grid.id='ux-layout';
   grid.innerHTML='<label class="field"><span>First field</span><input><span class="hint">A helper that wraps across several lines while explaining a format.</span></label><label class="field"><span>Second field</span><input><span class="hint"></span></label>';
   document.querySelector('#bgpglobal').prepend(grid);return [...grid.querySelectorAll('input')].map(n=>n.getBoundingClientRect().top);})()`);
  check(Math.abs(rows[0]-rows[1])<1,'helper text must not shift adjacent inputs: '+JSON.stringify(rows));
  await page.evaluate("document.querySelector('#ux-layout').remove()");
 });
 await test('HA safety guidance is concise and pairing details stay discoverable on mobile',async()=>{
  await page.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await go('ha');
  const state=await page.evaluate(`(()=>{const root=document.querySelector('#view-ha');
   const intro=[...root.querySelectorAll(':scope > .card p.lede')].filter(n=>n.getClientRects().length);
   const details=root.querySelector('details.pairing-help');details?.querySelector('summary')?.click();
   return {long:intro.filter(n=>n.textContent.trim().length>240).map(n=>n.textContent),
    details:!!details?.open,splitBrain:root.textContent.includes('split-brain'),width:document.documentElement.scrollWidth,viewport:innerWidth};})()`);
  check(!state.long.length&&state.details&&state.splitBrain&&state.width<=state.viewport,JSON.stringify(state));
 });
 await test('no uncaught exceptions or console errors during UX verification',()=>equal(page.thrown,[],'browser errors'));
 const out=process.env.CONSOLE_SCREENSHOTS;
 if(out){mkdirSync(out,{recursive:true});for(const key of ['ha','routing:bgp','routepolicy:prefix']){
  await go(key);writeFileSync(out+'/ux-'+key.replace(':','-')+'-mobile.png',Buffer.from(await page.screenshot(),'base64'));
 }}
}finally{page.close();}
process.exitCode=summary()?1:0;
