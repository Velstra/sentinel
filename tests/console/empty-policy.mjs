// Real blank-parent configuration and physical Chrome interactions. Only the
// run.sh private --no-apply fixture changes; never a DUT or injected response.
import {browser,signIn,signInAs,sleep,test,check,equal} from './harness.mjs';
import {click} from './creation.mjs';
import {readFileSync,mkdirSync,writeFileSync,realpathSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {dirname,join,sep} from 'node:path';
import {tmpdir} from 'node:os';

const policies=[
 {kind:'prefix-list',title:'Prefix lists',toggle:'togglepl',panel:'addplpanel',typed:'plnew',picker:'pllist-pick',noun:'list'},
 {kind:'route-map',title:'Route maps',toggle:'togglerm',panel:'addrmpanel',typed:'rmnew',picker:'rmlist-pick',noun:'map'},
];
function fixtureCLI(commands){
 const result=spawnSync(process.env.CONSOLE_BINARY,['configure','--config',process.env.CONSOLE_CONFIG,'--no-apply'],{
  env:{...process.env,SENTINEL_CONFIG:process.env.CONSOLE_CONFIG},input:[...commands,'commit','save','exit'].join('\n')+'\n',encoding:'utf8',timeout:30000});
 const output=(result.stdout||'')+(result.stderr||'');
 check(result.status===0&&!result.error&&!/^error:/im.test(output)&&output.includes('commit ok'),'Actual private no-apply fixture CLI refused (status '+result.status+')');
}
async function wait(page,expression){
 const end=Date.now()+10000;while(Date.now()<end){if(await page.evaluate(expression))return;await sleep(50);}throw Error('Actual creation state never reached: '+expression);
}
async function key(page,key,code,vk,modifiers=0){for(const type of ['keyDown','keyUp'])await page.send('Input.dispatchKeyEvent',{type,key,code,windowsVirtualKeyCode:vk,modifiers});}
async function fill(page,selector,value){await click(page,selector);await key(page,'a','KeyA',65,2);if(value)await page.send('Input.insertText',{text:value});else await key(page,'Backspace','Backspace',8);}
async function select(page,selector,value){
 const index=await page.evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});if(!n||n.tagName!=='SELECT')throw Error('Native selector absent');return [...n.options].findIndex(o=>o.value===${JSON.stringify(value)}&&!o.disabled);})()`);
 check(index>=0,'Actual native option absent: '+value);await click(page,selector);await key(page,'Home','Home',36);
 for(let n=0;n<index;n++)await key(page,'ArrowDown','ArrowDown',40);await key(page,'Enter','Enter',13);
 check(await page.evaluate(`document.querySelector(${JSON.stringify(selector)}).value===${JSON.stringify(value)}`),'Physical native selection did not reach '+value);
}
async function navigate(page,title){
 if(!await page.evaluate('!!document.querySelector("#palettehint").getClientRects().length'))await click(page,'#navtoggle');
 await click(page,'#palettehint');
 await page.evaluate(`(()=>{const n=[...document.querySelectorAll('#palettelist .palitem')].find(n=>n.querySelector('.palt').textContent===${JSON.stringify(title)});if(!n)throw Error('Actual navigation item absent');n.id='qa-empty-parent-destination';})()`);
 await click(page,'#qa-empty-parent-destination');
}
async function unavailable(page,{toggle,panel,noun}){
 await wait(page,`(()=>{const b=document.getElementById(${JSON.stringify(toggle)});return b.disabled&&!b.hasAttribute('data-config-loading')&&typeof b.onclick!=='function';})()`);
 const observed=await page.evaluate(`(()=>{const b=document.getElementById(${JSON.stringify(toggle)}),p=document.getElementById(${JSON.stringify(panel)});return{disabled:b.disabled,loading:b.hasAttribute('data-config-loading'),busy:b.getAttribute('aria-busy'),handler:typeof b.onclick,controls:b.getAttribute('aria-controls'),expanded:b.getAttribute('aria-expanded'),reason:b.title,hidden:!p.getClientRects().length,children:p.childElementCount,panelHandler:typeof p.onkeydown,description:(b.getAttribute('aria-describedby')||'').split(' ').filter(Boolean).some(id=>document.getElementById(id)?.getClientRects().length&&document.getElementById(id).textContent.trim()),staged:stagedCommands().length};})()`);
 check(observed.disabled&&!observed.loading&&observed.busy!=='true'&&observed.handler!=='function'&&!observed.controls&&!observed.expanded&&observed.reason.toLowerCase().includes(noun)&&observed.hidden&&observed.children===0&&observed.panelHandler!=='function'&&observed.description,JSON.stringify(observed));
 return observed;
}
async function ready(page,o){await wait(page,`!document.getElementById(${JSON.stringify(o.toggle)}).disabled&&typeof document.getElementById(${JSON.stringify(o.toggle)}).onclick==='function'&&!document.getElementById(${JSON.stringify(o.toggle)}).hasAttribute('data-config-loading')`);}
async function fresh(width){
 const page=await browser({width,height:1000});await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});
 await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);check(await page.evaluate('innerWidth')===width,'Actual CSS viewport differs');return page;
}
async function clean(page){
 check(!page.thrown.length&&!page.consoleMessages.some(row=>row.level==='error'),page.thrown.join('\n'));
 check(!page.responses.some(row=>row.url.startsWith(process.env.CONSOLE_URL)&&row.status>=400),'Actual fixture HTTP error');
 check(await page.evaluate('!management.getSnapshot().pending&&stagedCommands().length===0'),'Test left a staged/provisional change');
}
function rule(o,name,seq){return o.kind==='prefix-list'?`set policy prefix-list ${name} rule ${seq} prefix 198.51.100.0/24`:`set policy route-map ${name} rule ${seq} action permit`;}
async function addRule(page,o,seq){
 await click(page,'#'+o.toggle);await wait(page,`!!document.querySelector('#${o.panel} [aria-label="Sequence"]')?.getClientRects().length`);
 await fill(page,'#'+o.panel+' [aria-label="Sequence"]',String(seq));
 if(o.kind==='prefix-list')await fill(page,'#'+o.panel+' [aria-label="Prefix"]','198.51.100.0/24');
 else await select(page,'#'+o.panel+' [aria-label="Action"]','permit');
 const selector='#'+o.panel+' .maskfoot > .primary';
 const point=await page.evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});n.scrollIntoView({block:'center'});const r=n.getBoundingClientRect();return{x:r.left+r.width/2,y:r.top+r.height/2,staged:stagedCommands().length};})()`);
 await page.send('Input.dispatchMouseEvent',{type:'mousePressed',x:point.x,y:point.y,button:'left',buttons:1,clickCount:1});let held;
 try{await sleep(400);held=await page.evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)}),r=n.getBoundingClientRect();return{x:r.left+r.width/2,y:r.top+r.height/2,staged:stagedCommands().length,pointers:validationPointers.size,hint:document.querySelector('#${o.panel} [aria-label="Prefix"]')?.closest('.field')?.querySelector('.hint')?.textContent};})()`);}
 finally{await page.send('Input.dispatchMouseEvent',{type:'mouseReleased',x:point.x,y:point.y,button:'left',buttons:0,clickCount:1});}
 check(Math.abs(held.x-point.x)<1&&Math.abs(held.y-point.y)<1&&held.staged===point.staged&&held.pointers===1,'Hint/feedback moved a physically held Add before release: '+JSON.stringify({before:point,held}));
 await wait(page,`!document.getElementById('${o.panel}').getClientRects().length`);
}
function picture(page,name){const folder=process.env.CONSOLE_SCREENSHOTS||'screenshots';mkdirSync(folder,{recursive:true});return page.screenshot().then(data=>writeFileSync(join(folder,name+'.png'),Buffer.from(data,'base64')));}

export async function emptyPolicyTests(){
 check(process.env.CONSOLE_BINARY&&process.env.CONSOLE_CONFIG,'Use run.sh private no-apply fixture only');
 const config=realpathSync(process.env.CONSOLE_CONFIG),binary=realpathSync(process.env.CONSOLE_BINARY);
 check(config.startsWith(realpathSync(tmpdir())+sep)&&dirname(config)===dirname(binary)&&config.endsWith('/config.toml'),'Only the runner private fixture may be edited');
 const original=readFileSync(config);
 fixtureCLI(['delete policy prefix-list customers','delete policy route-map to-transit']);
 const blank=readFileSync(config);let account=false;
 try{
  for(const width of [1440,390])for(const o of policies){
   await test('blank '+o.kind+' parent readiness, physical creation/selection/discard and disappearance at '+width,async()=>{
    const page=await fresh(width),a='qa-parent-a-'+width,b='qa-parent-b-'+width,persisted='qa-persisted-'+width;let saved=false;
    try{
     await navigate(page,o.title);await wait(page,`!!document.getElementById('${o.typed}').getClientRects().length`);
     await unavailable(page,o);check(await page.evaluate('stagedCommands().length===0'),'Inspecting blank parent staged work');
     await picture(page,'empty-'+o.kind+'-'+width);
     await fill(page,'#'+o.typed,a);await ready(page,o);
     check(await page.evaluate('stagedCommands().length===0'),'Typing a parent must not stage it');
     await click(page,'#'+o.toggle);
     check(await page.evaluate(`document.getElementById('${o.panel}').contains(document.activeElement)&&document.getElementById('${o.toggle}').getAttribute('aria-expanded')==='true'`),'First real New click failed');
     await click(page,'#'+o.panel+' .maskfoot > .primary');
     check(await page.evaluate(`stagedCommands().length===0&&!!document.querySelector('#${o.panel} [aria-invalid="true"]')`),'Empty Add was not refused');
     await click(page,'#'+o.panel+' .maskfoot > button:not(.primary)');
     check(await page.evaluate(`document.activeElement.id==='${o.toggle}'`),'Cancel did not restore trigger focus');
     await click(page,'#'+o.toggle);await key(page,'Escape','Escape',27);
     check(await page.evaluate(`!document.getElementById('${o.panel}').getClientRects().length&&document.activeElement.id==='${o.toggle}'`),'Escape/focus failed');
     await fill(page,'#'+o.typed,'');await unavailable(page,o);
     const readsBefore=page.requests.filter(url=>url.endsWith('/api/v1/show/configuration')).length;
     await fill(page,'#'+o.typed,a);await ready(page,o);await addRule(page,o,10);
     equal(await page.evaluate('stagedCommands()'),[rule(o,a,10)],'Only the actual first rule is staged');
     await fill(page,'#'+o.typed,b);await ready(page,o);await addRule(page,o,10);
     await wait(page,`[...document.getElementById('${o.picker}').options].some(n=>n.value===${JSON.stringify(b)})`);
     await fill(page,'#'+o.typed,'');await select(page,'#'+o.picker,a);await ready(page,o);await addRule(page,o,20);
     equal(await page.evaluate('stagedCommands()'),[rule(o,a,10),rule(o,b,10),rule(o,a,20)],'Actual parent selection changed the wrong context or staged a bare parent');
     equal(page.requests.filter(url=>url.endsWith('/api/v1/show/configuration')).length,readsBefore,'Draft parent/rule actions launched an async read capable of erasing the next form');
     check(readFileSync(config).equals(blank),'Stage wrote private fixture configuration');
     await click(page,'#discard');await click(page,'#refresh');await unavailable(page,o);
     check(await page.evaluate('stagedCommands().length===0'),'Discard/reload staged work');
     fixtureCLI([rule(o,persisted,10)]);saved=true;await click(page,'#refresh');await ready(page,o);await click(page,'#'+o.toggle);
     fixtureCLI(['delete policy '+o.kind+' '+persisted]);saved=false;await click(page,'#refresh');await unavailable(page,o);
     check(readFileSync(config).equals(blank),'Normal fixture parent removal did not restore exact blank state');await clean(page);
    }catch(error){
     await picture(page,'failure-'+o.kind+'-'+width);
     const observed=await page.evaluate(`({typed:document.getElementById('${o.typed}').value,picker:document.getElementById('${o.picker}').value,commands:stagedCommands(),fields:[...document.querySelectorAll('#${o.panel} input,#${o.panel} select')].map(n=>({label:n.getAttribute('aria-label'),value:n.value,invalid:n.getAttribute('aria-invalid')})),errors:[...document.querySelectorAll('#${o.panel} .field-error,#${o.panel} .formerr')].map(n=>n.textContent).filter(Boolean)})`);
     throw Error(error.message+'; actual policy form: '+JSON.stringify(observed));
    }finally{if(saved)fixtureCLI(['delete policy '+o.kind+' '+persisted]);page.close();}
   });
  }
  fixtureCLI(['set system group qa-empty-viewers permission read-only','set system login qa-empty-viewer password FixtureOnly-1698','set system login qa-empty-viewer group qa-empty-viewers']);account=true;
  for(const width of [1440,390])await test('real read-only parent redraw and admin permission recovery preserve prerequisite gates at '+width,async()=>{
   const page=await browser({width,height:1000});
   try{
    await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});await page.goto(process.env.CONSOLE_URL);
    check((await signInAs(page,'qa-empty-viewer','FixtureOnly-1698')).inside,'Real fixture read-only login failed');
    for(const o of policies){
     await navigate(page,o.title);await unavailable(page,o);await fill(page,'#'+o.typed,'qa-readonly-'+width);
     await wait(page,`typeof document.getElementById('${o.toggle}').onclick==='function'`);
     const state=await page.evaluate(`(()=>{const b=document.getElementById('${o.toggle}');return{disabled:b.disabled,reason:b.title,staged:stagedCommands().length};})()`);
     check(state.disabled&&/read the configuration/i.test(state.reason)&&state.staged===0,JSON.stringify(state));
     // A genuine pointer activation on the disabled native button must not
     // invoke its handler. Never force onclick or change permission variables.
     const p=await page.evaluate(`(()=>{const n=document.getElementById('${o.toggle}');n.scrollIntoView({block:'center'});const r=n.getBoundingClientRect();return{x:r.left+r.width/2,y:r.top+r.height/2};})()`);
     for(const type of ['mousePressed','mouseReleased'])await page.send('Input.dispatchMouseEvent',{type,...p,button:'left',clickCount:1});
     check(await page.evaluate(`!document.getElementById('${o.panel}').getClientRects().length&&stagedCommands().length===0`),'Read-only New opened/staged work');
     await fill(page,'#'+o.typed,'');await unavailable(page,o);
    }
    if(!await page.evaluate('!!document.querySelector("#signout").getClientRects().length'))await click(page,'#navtoggle');await click(page,'#signout');await signIn(page,process.env.CONSOLE_TOKEN);
    for(const o of policies){await navigate(page,o.title);await unavailable(page,o);await fill(page,'#'+o.typed,'qa-admin-'+width);await ready(page,o);await click(page,'#'+o.toggle);await click(page,'#'+o.panel+' .maskfoot > button:not(.primary)');await fill(page,'#'+o.typed,'');await unavailable(page,o);}
    await clean(page);
   }finally{page.close();}
  });
  fixtureCLI(['delete system login qa-empty-viewer','delete system group qa-empty-viewers']);account=false;
  for(const width of [1440,390])for(const o of [
   {title:'WireGuard',toggle:'togglewgpeer',panel:'addwgpeerpanel',noun:'interface',remove:['delete vpn wireguard wg0','delete interface wg0'],restore:['set interface wg0 type wireguard','set vpn wireguard wg0 listen-port 51820','set vpn wireguard wg0 private-key AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=']},
   {title:'DHCP',toggle:'togglemap',panel:'addmappanel',noun:'server',remove:['delete interface eth0 dhcp-server'],restore:['set interface eth0 dhcp-server enable']},
  ])await test('shared '+o.title+' prerequisite disappearance and rebind at '+width,async()=>{
   fixtureCLI(o.remove);const page=await fresh(width);let removed=true;
   try{await navigate(page,o.title);await unavailable(page,o);fixtureCLI(o.restore);removed=false;await click(page,'#refresh');await ready(page,o);await click(page,'#'+o.toggle);
    check(await page.evaluate(`!!document.getElementById('${o.panel}').getClientRects().length&&stagedCommands().length===0`),'Shared prerequisite did not rebind to a genuine New action');
    fixtureCLI(o.remove);removed=true;await click(page,'#refresh');await unavailable(page,o);await clean(page);
   }finally{if(removed)fixtureCLI(o.restore);page.close();}
  });
 }finally{
  if(account)fixtureCLI(['delete system login qa-empty-viewer','delete system group qa-empty-viewers']);
  fixtureCLI(['set policy prefix-list customers rule 10 prefix 10.0.0.0/8','set policy route-map to-transit rule 10 action permit']);
  check(readFileSync(config).equals(original),'Private fixture was not restored by the normal CLI');
 }
}
