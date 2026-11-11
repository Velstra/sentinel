// Real-browser regressions for shared controls and the responsive settings shell.
// Use tests/console/run.sh: all mutations target an isolated --no-apply API.
import {browser,signIn,sleep,test,check,equal,summary} from './harness.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
import {creationTests} from './creation.mjs';
import {updateKeyTests} from './update-key.mjs';
import {emptyPolicyTests} from './empty-policy.mjs';
import {updateUrlTests} from './update-url.mjs';
const page=await browser({width:1440,height:1000});
const go=async key=>{await page.evaluate(`goto(${JSON.stringify(key)})`);await sleep(250);};
try {
 await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
 await creationTests();
 await updateKeyTests();
 await emptyPolicyTests();
 await updateUrlTests();
 await test('staged badge never claims a provisional network change is already clear',async()=>{
  const states=await page.evaluate(`(()=>{
   const oldStaged=staged,oldApplying=applying,rows=[];
   try{
    for(const count of [0,1,2]){
     applying=false;staged=Array.from({length:count},(_,i)=>({label:'QA draft '+i,cmds:['set system hostname draft-'+i]}));renderStaged();
     rows.push({count,badge:document.querySelector('#stagedbadge').textContent,title:document.querySelector('#stagedtitle').textContent});
    }
    applying=true;renderStaged();rows.push({busy:document.querySelector('#stagedbadge').textContent});return rows;
   }finally{staged=oldStaged;applying=oldApplying;renderStaged();}})()`);
  equal(states,[
   {count:0,badge:'no staged changes',title:'0 staged changes'},
   {count:1,badge:'1 staged change',title:'1 staged change'},
   {count:2,badge:'2 staged changes',title:'2 staged changes'},
   {busy:'applying'}
  ],'The batch badge describes local staging, not the independent confirmation transaction');
 });
 await test('IPsec repair form loads while the real operational request is held',async()=>{
  const held=await browser({width:1440,height:1000});
  try{
   await held.goto(process.env.CONSOLE_URL);await signIn(held,process.env.CONSOLE_TOKEN);
   const initial=await held.evaluate(`(()=>{const b=document.querySelector('#toggleipsec');return {disabled:b.disabled,loading:b.hasAttribute('data-config-loading')};})()`);
   check(initial.disabled&&initial.loading,JSON.stringify(initial));
   // Pause the real browser request, never replace an API response or invent
   // daemon state. Configuration still comes from the authenticated real API.
   // This fresh browser is closed below, cancelling only its owned held read.
   await held.send('Fetch.enable',{patterns:[{urlPattern:'*/api/v1/show/vpn/ipsec',requestStage:'Request'}]});
   await held.evaluate('goto("ipsec")');
   let ready=false;
   for(let n=0;n<100&&!ready;n++){
    ready=await held.evaluate(`!!document.querySelector('#addipsecpanel .primary')&&!document.querySelector('#toggleipsec').disabled`);
    if(!ready)await sleep(100);
   }
   check(ready,'The IPsec form is blocked behind the operational daemon read');
   const state=await held.evaluate(`(()=>{
    const b=document.querySelector('#toggleipsec');b.click();
    const box=document.querySelector('#addipsecpanel');
    const local=box.querySelector('[aria-label="Local address"]');
    const combo=local.closest('.combo');combo.querySelector('.caret').click();
    const offered=[...combo.querySelectorAll('.choice')].map(b=>b.textContent);
    const suggestionsOpen=!!combo.querySelector('.menu').getClientRects().length;
    combo.querySelector('.choice').click();
    return {loading:b.hasAttribute('data-config-loading'),diagnosticBusy:document.querySelector('#ipsecshow').getAttribute('aria-busy'),
     offered,suggestionsOpen,selected:local.value,sharedStillDualStack:localAddresses().some(a=>a.includes(':')),
     fields:['Local address','Remote address','Local subnet','Remote subnet','Pre-shared key'].map(name=>{
      const e=box.querySelector('[aria-label="'+name+'"]');return {name,visible:!!e?.getClientRects().length,labelled:!!e?.labels?.length};
     })};})()`);
   check(!state.loading&&state.diagnosticBusy==='true'&&state.fields.every(f=>f.visible&&f.labelled),JSON.stringify(state));
   check(state.suggestionsOpen&&state.offered.includes('10.0.0.1')&&state.offered.every(a=>!a.includes(':'))&&state.selected==='10.0.0.1'&&state.sharedStillDualStack,JSON.stringify(state));
   check(held.requests.some(u=>u.endsWith('/api/v1/show/vpn/ipsec')),'The independent real diagnostic was not requested');
   await held.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
   check(await held.evaluate(`!document.querySelector('#addipsecpanel').getClientRects().length&&document.activeElement.id==='toggleipsec'`),'Cancel/focus recovery failed');
   check(!held.thrown.length,held.thrown.join('\n'));
  }finally{held.close();}
 });
 await test('blur validation cannot move a physically pressed suggestion button before release',async()=>{
  for(const width of [1440,390]){
   const pressed=await browser({width,height:1000});
   try{
    await pressed.goto(process.env.CONSOLE_URL);await signIn(pressed,process.env.CONSOLE_TOKEN);
    await pressed.evaluate('goto("ipsec")');
    let ready=false;
    for(let i=0;i<100&&!ready;i++){
     ready=await pressed.evaluate('!!document.querySelector("#addipsecpanel .primary")&&!document.querySelector("#toggleipsec").disabled');
     if(!ready)await sleep(100);
    }
    check(ready,'Real IPsec form did not become ready');
    const click=async selector=>{
     const point=await pressed.evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});n.scrollIntoView({block:'center'});const r=n.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2};})()`);
     await pressed.send('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',buttons:1,clickCount:1});
     await pressed.send('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',buttons:0,clickCount:1});
    };
    await click('#toggleipsec');
    const point=await pressed.evaluate(`(()=>{const n=document.querySelector('#addipsecpanel .caret');n.scrollIntoView({block:'center'});const r=n.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2};})()`);
    await pressed.send('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',buttons:1,clickCount:1});
    await sleep(400);
    const held=await pressed.evaluate(`(()=>{const n=document.querySelector('#addipsecpanel .caret'),r=n.getBoundingClientRect();return {y:r.top+r.height/2,nameInvalid:document.querySelector('#addipsecpanel [aria-label="Name"]').getAttribute('aria-invalid'),expanded:n.getAttribute('aria-expanded')};})()`);
    check(Math.abs(held.y-point.y)<1&&held.nameInvalid!=='true'&&held.expanded==='false',JSON.stringify({width,point,held}));
    await pressed.send('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',buttons:0,clickCount:1});await sleep(100);
    const completed=await pressed.evaluate(`({invalid:document.querySelector('#addipsecpanel [aria-label="Name"]').getAttribute('aria-invalid'),expanded:document.querySelector('#addipsecpanel .caret').getAttribute('aria-expanded'),staged:stagedCommands().length})`);
    check(completed.invalid==='true'&&completed.expanded==='true'&&!completed.staged,JSON.stringify({width,completed}));
    await pressed.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
    check(await pressed.evaluate(`document.querySelector('#addipsecpanel .caret').getAttribute('aria-expanded')==='false'&&document.activeElement.classList.contains('caret')`),'Keyboard popup dismissal changed');
    check(!pressed.thrown.length&&!pressed.consoleMessages.some(row=>row.level==='error'),pressed.thrown.join('\n'));
   }finally{pressed.close();}
  }
 });
 await test('Dynamic DNS credentials are masked, reveal deliberately, and stage as one exact CLI token',async()=>{
  await go('services:addressing');
  const credential='  test "credential" \\ value  ';
  const result=await page.evaluate(`(()=>{
   staged=[];dirty.clear();renderStaged();
   const root=document.querySelector('#svc-dyndns'),input=root.querySelector('input[type=password]');
   if(!input)return {masked:false};
   const button=input.closest('.secretfield').querySelector('button');
   const masked=input.type==='password',label=input.labels?.[0]?.textContent;
   button.click();const revealed=input.type==='text'&&button.getAttribute('aria-label')==='Hide Password'&&button.getAttribute('aria-pressed')==='true';
   button.click();const hidden=input.type==='password'&&button.getAttribute('aria-label')==='Show Password'&&button.getAttribute('aria-pressed')==='false';
   input.value=${JSON.stringify(credential)};input.dispatchEvent(new Event('input',{bubbles:true}));
   root.querySelector('.maskfoot .primary').click();
   const commands=stagedCommands();staged=[];dirty.clear();renderStaged();
   return {masked,label,revealed,hidden,commands};})()`);
  check(result.masked&&result.label?.includes('Password')&&result.revealed&&result.hidden,JSON.stringify(result));
  check(result.commands.includes('set services dyndns password '+JSON.stringify(credential)),JSON.stringify(result.commands));
 });
 await test('all shared credential fields use the same masking, redaction and safe token encoding',async()=>{
  const state=await page.evaluate(`(()=>{
   const holder=document.createElement('div');document.body.append(holder);
   try{return SECRETS.map(key=>{const f=[key,'Test credential'],value='  test "value"  ';
    const widget=fieldWidget(f,value);holder.append(widget);
    const input=widget.querySelector('input');
    return {key,masked:input?.type==='password',redacted:shown(key,value)==='set',
     exact:fieldLines([f],[widget],'test')[0]==='set test '+key+' '+JSON.stringify(value)};
   });}finally{holder.remove();}})()`);
  check(state.length>=14&&state.every(s=>s.masked&&s.redacted&&s.exact),JSON.stringify(state));
 });
 await test('reverse proxy defaults are HTTP and 443 without leaking the multi-WAN failover default',async()=>{
  await go('services:publishing');
  const state=await page.evaluate(`(()=>{
   document.querySelector('#togglerp').click();
   const panel=document.querySelector('#addrppanel');
   const select=[...panel.querySelectorAll('select')].find(s=>[...s.options].some(o=>o.value==='http'));
   const defaultMode=select?.querySelector('option[value=""]')?.textContent;
   const port=panel.querySelector('input[aria-label="Listen port"]');
   const old=fieldPath;fieldPath='multi-wan';const wan=defaultOf('mode');fieldPath=old;
   return {defaultMode,port:port?.placeholder,wan};})()`);
  check(state.defaultMode?.includes('http')&&!state.defaultMode.includes('failover')&&state.port?.includes('443')&&state.wan==='failover',JSON.stringify(state));
 });
 await test('creation drawers can cancel and Escape without staging or losing the local draft',async()=>{
  for(const width of [1440,390]){
  await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});
  await go('services:publishing');
  const initial=await page.evaluate(`(()=>{
   staged=[];dirty.clear();renderStaged();
   const panel=document.querySelector('#addrppanel');
   if(!panel.getClientRects().length)document.querySelector('#togglerp').click();
   panel.querySelector('input').value='draft-frontend';
   const cancel=[...panel.querySelectorAll('button')].find(n=>n.textContent==='Cancel');
   if(!cancel)return {cancel:false};
   const bounds=cancel.getBoundingClientRect(),hit=document.elementFromPoint(bounds.left+bounds.width/2,bounds.top+bounds.height/2);
   const reachable=cancel===hit||cancel.contains(hit);cancel.click();
   return {cancel:true,reachable,closed:!panel.getClientRects().length,
    focused:document.activeElement.id==='togglerp',expanded:document.querySelector('#togglerp').getAttribute('aria-expanded'),staged:stagedCommands().length};})()`);
  check(initial.cancel&&initial.reachable&&initial.closed&&initial.focused&&initial.expanded==='false'&&!initial.staged,JSON.stringify(initial));
  await page.evaluate(`(()=>{document.querySelector('#togglerp').click();document.querySelector('#addrppanel input').focus();})()`);
  check(await page.evaluate('document.querySelector("#addrppanel input").value==="draft-frontend"'),'Cancel must preserve the unstaged draft');
  await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  const escaped=await page.evaluate(`({closed:!document.querySelector('#addrppanel').getClientRects().length,focused:document.activeElement.id==='togglerp',staged:stagedCommands().length})`);
  check(escaped.closed&&escaped.focused&&!escaped.staged,JSON.stringify(escaped));
  }
  await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
 });
 await test('creation drawer identifiers stay below the real header before and after scrolling',async()=>{
  try{for(const width of [1440,390,320]){
   await page.send('Emulation.setDeviceMetricsOverride',{width,height:844,deviceScaleFactor:1,mobile:width<900});
   for(const theme of ['light','dark']){
    await page.evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)})`);
    await go('services:publishing');
    await page.evaluate(`(()=>{if(!document.querySelector('#addrppanel').getClientRects().length)document.querySelector('#togglerp').click();})()`);await sleep(150);
    for(const scroll of [0,160,0]){
     await page.evaluate(`window.scrollTo(0,${scroll})`);await sleep(150);
     const bounds=await page.evaluate(`(()=>{
      const panel=document.querySelector('#addrppanel'),label=panel.querySelector('label'),input=label.querySelector('input');
      const p=panel.getBoundingClientRect(),l=label.getBoundingClientRect(),i=input.getBoundingClientRect(),bar=document.querySelector('.bar').getBoundingClientRect();
      const hit=document.elementFromPoint(i.left+i.width/2,i.top+i.height/2);
      return {panel:p.top,label:l.top,header:bar.bottom,reachable:hit===input};})()`);
     check(bounds.panel>=bounds.header-1&&bounds.label>=bounds.header&&bounds.reachable,JSON.stringify({width,theme,scroll,...bounds}));
    }
   }
  }}finally{
   await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  }
 });
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
 await test('firewall port lists and ranges reject malformed values inline without losing valid formats',async()=>{
  await go('rules');
  const cap=await page.evaluate('typeof FIREWALL_PORT_RANGE_MAX==="number"?FIREWALL_PORT_RANGE_MAX:1024');
  const invalid=['0','65536','70000','8100-8000',`1-${cap+1}`,'443,70000','1e3','-1','443-','443:8443','8000--8100'];
  const accepted=['1','65535','443,8443','8000-8100',`1-${cap}`,' 443, 8000 - 8100 ', '+443'];
  const result=await page.evaluate(`(()=>{
   staged=[];dirty.clear();renderStaged();
   const panel=document.querySelector('#addrulepanel');
   if(!panel.getClientRects().length)document.querySelector('#togglerule').click();
   const named=label=>panel.querySelector('[aria-label="'+label+'"]');
   named('Name').value='ports-validation';named('From zone').value='wan';
   named('Action').value='reject';named('Protocol').value='tcp';
   named('Protocol').dispatchEvent(new Event('change',{bubbles:true}));
   const input=named('Port'),add=panel.querySelector('.maskfoot .primary');
   const rows=[];
   for(const value of ${JSON.stringify(invalid)}){
    staged=[];renderStaged();input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));add.click();
    const error=document.getElementById(input.getAttribute('aria-errormessage'));
    rows.push({value,blocked:staged.length===0,invalid:input.getAttribute('aria-invalid'),error:error?.textContent,focused:document.activeElement===input,retained:input.value===value});
   }
   return rows;
  })()`);
  for(const row of result)check(row.blocked&&row.invalid==='true'&&row.error&&row.focused&&row.retained,JSON.stringify(row));
  // Each success rebuilds the creation form, just as the actual Add action does.
  for(const value of accepted){
   await go('rules');
   const row=await page.evaluate(`(()=>{
    staged=[];dirty.clear();renderStaged();
    const panel=document.querySelector('#addrulepanel');
    if(!panel.getClientRects().length)document.querySelector('#togglerule').click();
    const named=label=>panel.querySelector('[aria-label="'+label+'"]');
    named('Name').value='ports-validation';named('From zone').value='wan';named('Action').value='reject';
    named('Protocol').value='tcp';named('Protocol').dispatchEvent(new Event('change',{bubbles:true}));
    const input=named('Port');input.value=${JSON.stringify(value)};input.dispatchEvent(new Event('input',{bubbles:true}));
    panel.querySelector('.maskfoot .primary').click();
    const commands=stagedCommands();staged=[];dirty.clear();renderStaged();return {commands};
   })()`);
   check(row.commands.some(command=>command.startsWith('set firewall rule ports-validation port ')),JSON.stringify({value,...row}));
   const verdict=await page.evaluate(`(async()=>{const r=await configure(${JSON.stringify(row.commands)});return r.output;})()`);
   check(!/error:|refused/i.test(verdict||''),JSON.stringify({value,verdict}));
  }
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
 const focusEvidence=async key=>{
  await page.evaluate(`(()=>{
   if(${JSON.stringify(key)}==='services:addressing')document.querySelector('#svc-dyndns').scrollIntoView({block:'center'});
   if(${JSON.stringify(key)}==='services:publishing'){
    const form=document.querySelector('#addrppanel');
    if(!form.getClientRects().length)document.querySelector('#togglerp').click();
    form.scrollIntoView({block:'center'});
   }
  })()`);await sleep(150);
 };
 if(out){mkdirSync(out,{recursive:true});for(const key of ['ha','routing:bgp','routepolicy:prefix','services:addressing','services:publishing']){
  await go(key);await focusEvidence(key);writeFileSync(out+'/ux-'+key.replace(':','-')+'-mobile.png',Buffer.from(await page.screenshot(),'base64'));
 }await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
 for(const key of ['services:addressing','services:publishing']){
  await go(key);await focusEvidence(key);
  writeFileSync(out+'/ux-'+key.replace(':','-')+'-desktop.png',Buffer.from(await page.screenshot(),'base64'));
 }}
}finally{page.close();}
process.exitCode=summary()?1:0;
