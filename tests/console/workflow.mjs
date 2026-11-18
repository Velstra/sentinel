// Everyday-workflow regressions: the change dock, actionable empty lists,
// finding a setting by name, the page index and the first-steps list.
// Real Chromium against the disposable --no-apply API from run.sh. These prove
// the console's own behaviour; they certify nothing about a live appliance.
import {browser,signIn,sleep,test,check,equal} from './harness.mjs';
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {click} from './creation.mjs';
import {collectSettings} from './settings-index.mjs';

export async function workflowTests(){
 for(const width of [1440,390]){
  const page=await browser({width,height:1000});
  const go=async key=>{await page.evaluate(`(async()=>{const [v,t]=${JSON.stringify(key)}.split(':');view=v;if(t)tabs[v]=t;panel=null;buildNav();await refresh();})()`);await sleep(150);};
  try{
   await page.send('Emulation.setDeviceMetricsOverride',{width,height:1000,deviceScaleFactor:1,mobile:width<900});
   await page.goto(process.env.CONSOLE_URL);await signIn(page,process.env.CONSOLE_TOKEN);
   check(await page.evaluate('innerWidth')===width,'Workflow viewport differs from its receipt');

   await test('change dock stays on screen, reviews real commands and masks credentials at '+width,async()=>{
    await go('rules');
    const state=await page.evaluate(`(()=>{
     staged=[];renderStaged();
     const resting=$("stagedcard").classList.contains("hidden")&&!$("app").hasAttribute("data-staged");
     stage("Firewall rule qa-ssh",["set firewall rule qa-ssh from lan","set firewall rule qa-ssh action accept"]);
     // The protected line comes from the same owner every secret field uses.
     const secret=fieldLines([["private-key","Private key",null,null,"secret"]],[{value:"QA-SECRET-VALUE-0001"}],"vpn wireguard wg0",{});
     stage("WireGuard wg0",secret);
     const card=$("stagedcard"),r=card.getBoundingClientRect();
     const collapsed={hidden:card.classList.contains("hidden"),listHidden:$("stagedlist").classList.contains("hidden"),
      expanded:$("stagedreview").getAttribute("aria-expanded"),title:$("stagedtitle").textContent,latest:$("stagedlatest").textContent,
      fixed:getComputedStyle(card).position,inView:r.top>=0&&r.bottom<=innerHeight+1&&r.left>=0&&r.right<=innerWidth+1,room:$("app").hasAttribute("data-staged")};
     $("stagedreview").click();
     const text=$("stagedlist").textContent;
     const buttons=[...card.querySelectorAll("button")].filter(b=>b.getClientRects().length).map(b=>{const q=b.getBoundingClientRect();return q.left>=0&&q.right<=innerWidth+1;});
     const review={open:!$("stagedlist").classList.contains("hidden"),expanded:$("stagedreview").getAttribute("aria-expanded"),
      commands:text.includes("set firewall rule qa-ssh from lan")&&text.includes("set firewall rule qa-ssh action accept"),
      leaked:text.includes("QA-SECRET-VALUE-0001"),masked:text.includes("set vpn wireguard wg0 private-key ••••••"),
      sent:secret[0].includes("QA-SECRET-VALUE-0001"),buttonsInView:buttons.every(Boolean),names:[...$("stagedlist").querySelectorAll("button")].map(b=>b.getAttribute("aria-label"))};
     $("stagedlist").querySelector("button").click();
     const afterRemove={count:staged.length,title:$("stagedtitle").textContent,stillOpen:!$("stagedlist").classList.contains("hidden")};
     return{resting,collapsed,review,afterRemove};})()`);
    check(state.resting,'the dock was offered with nothing staged');
    equal(state.collapsed,{hidden:false,listHidden:true,expanded:'false',title:'2 staged changes',
     latest:'Last: WireGuard wg0 — nothing reaches the appliance until you apply.',fixed:'fixed',inView:true,room:true},'collapsed dock');
    equal(state.review,{open:true,expanded:'true',commands:true,leaked:false,masked:true,sent:true,buttonsInView:true,
     names:['Remove staged change: Firewall rule qa-ssh','Remove staged change: WireGuard wg0']},'review');
    equal(state.afterRemove,{count:1,title:'1 staged change',stillOpen:true},'removing one change');
    // A physical press: the helper refuses an occluded or off-screen control.
    await click(page,'#discard');
    equal(await page.evaluate('({n:staged.length,hidden:$("stagedcard").classList.contains("hidden"),room:$("app").hasAttribute("data-staged"),masks:reviewMasks.size})'),
     {n:0,hidden:true,room:false,masks:0},'Discard did not clear the dock');
   });

   await test('the dock never covers the last control of a page at '+width,async()=>{
    await go('system');
    await page.evaluate('stage("QA draft",["set system hostname qa-dock"])');
    const last=await page.evaluate(`(()=>{const v=$("view-system");const all=[...v.querySelectorAll("button,input,select,textarea")].filter(n=>n.getClientRects().length&&!n.disabled);
     const n=all[all.length-1];n.scrollIntoView({block:"center"});const r=n.getBoundingClientRect(),d=$("stagedcard").getBoundingClientRect();
     const hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);return{clear:r.bottom<=d.top||r.top>=d.bottom,reachable:hit===n||n.contains(hit)||(hit&&hit.contains(n))};})()`);
    await page.evaluate('staged=[];renderStaged()');
    equal(last,{clear:true,reachable:true},'the staged dock covered the last control');
   });

   await test('the answer leads with the verdict and says each advisory once at '+width,async()=>{
    await go('rules');
    // The dialog itself, fed a reply shaped like the appliance's: two rules
    // with one sentence, a third with another, one without a named object,
    // a repeat, and enough distinct ones to outgrow a phone. The batch
    // addresses rule b; it also carries the word "a", which is not rule a.
    const shown=await page.evaluate(`(()=>{
     const say=s=>"warning: "+s;
     const many=Array.from({length:12},(_,i)=>say('zone "z'+i+'": advisory number '+i+' is a sentence long enough to wrap on a phone'));
     showResult({ok:true,output:["validation ok; nothing applied",say('rule "a": X stays put'),say('rule "b": X stays put'),say('rule "c": Y differs'),
      say('services dns: no name'),say('rule "a": X stays put'),...many].join("\\n")},false,null,["set firewall rule b port 1","set services a port 22"]);
     const rows=[...document.querySelectorAll("#resultout .change")].map(r=>({dot:r.querySelector(".dot").className,subject:r.querySelector(".lbl")?.textContent||"",
      text:(r.querySelector(".what span:last-child")||r.querySelector(".what")).textContent}));
     const d=$("result"),q=d.getBoundingClientRect();
     const out={title:$("resulttitle").textContent,rows:rows.slice(0,5),count:rows.length,
      inView:q.top>=0&&q.bottom<=innerHeight+1&&q.left>=0&&q.right<=innerWidth+1,wide:document.documentElement.scrollWidth>innerWidth,
      clipped:[...d.querySelectorAll(".what")].some(n=>n.scrollWidth>n.clientWidth+1)};
     d.close();return out;})()`);
    equal(shown,{title:'This would be accepted',rows:[
      {dot:'dot up',subject:'',text:'Checked, and nothing was changed — the changes are still staged.'},
      {dot:'dot up',subject:'',text:'Press Apply and save in the bar below when you are ready.'},
      {dot:'dot warn',subject:'Rules b, a',text:'X stays put'},
      {dot:'dot warn',subject:'Rule c',text:'Y differs'},
      {dot:'dot warn',subject:'',text:'services dns: no name'}],count:17,inView:true,wide:false,clipped:false},'merged answer');
    // And through the real path: an accept rule aimed at a zone draws the
    // appliance's own advisory, which must name it first and say it once.
    // The dialog is emptied first, so only this validation's answer is read.
    await page.evaluate(`staged=[];renderStaged();$("resultout").textContent="";stage("Firewall rule wf-advice",["set firewall rule wf-advice from wan","set firewall rule wf-advice to lan",
     "set firewall rule wf-advice action accept","set firewall rule wf-advice proto tcp","set firewall rule wf-advice port 23"])`);
    await click(page,'#validate');
    for(let i=0;i<40&&!await page.evaluate('$("result").open&&$("resultout").childElementCount>0');i++)await sleep(250);
    const real=await page.evaluate(`(()=>{const rows=[...document.querySelectorAll("#resultout .change")];
     const advice=rows.filter(r=>r.classList.contains("advice")).map(r=>({subject:r.querySelector(".lbl")?.textContent||"",text:r.querySelector(".what span:last-child").textContent}));
     const out={title:$("resulttitle").textContent,first:rows[0]?.querySelector(".dot").className,advice,staged:staged.length};
     $("result").close();staged=[];renderStaged();return out;})()`);
    equal({title:real.title,first:real.first,staged:real.staged},{title:'This would be accepted',first:'dot up',staged:1},'validated batch');
    const own=real.advice.filter(a=>/\bwf-advice\b/.test(a.subject));
    check(own.length===1&&/^Rules? wf-advice\b/.test(own[0].subject)&&real.advice[0]===own[0],
     'the staged rule\'s advisory is not named first, once: '+JSON.stringify(real.advice));
    check(new Set(real.advice.map(a=>a.text)).size===real.advice.length,'one sentence was printed more than once: '+JSON.stringify(real.advice));
   });

   await test('destination-zone deny refuses without saving and accepts an explicit-destination retry at '+width,async()=>{
    await go('rules');
    const name='wf-deny-'+width,label='Firewall rule '+name;
    const commands=['from wan','to lan','action reject','proto tcp','port 23'].map(s=>'set firewall rule '+name+' '+s);
    const original=readFileSync(process.env.CONSOLE_CONFIG);
    const baseline=await page.evaluate('(async()=>await (await api("/api/v1/config")).json())()');
    await page.evaluate(`(()=>{
     staged=[];dirty.clear();renderStaged();stage(${JSON.stringify(label)},${JSON.stringify(commands)});
     window.destinationRequests=[];const original=window.fetch;
     window.restoreDestinationFetch=()=>{window.fetch=original;};
     window.fetch=async(...args)=>{const response=await original(...args);
      if(String(args[0]).includes('/api/v1/configure'))window.destinationRequests.push({status:response.status,body:args[1]?.body});
      return response;};
    })()`);
    const perform=async action=>{
     await page.evaluate('if($("result").open)$("result").close();$("resultout").textContent="";window.destinationRequests=[]');
     await click(page,'#'+action);
     for(let i=0;i<80&&!await page.evaluate('$("result").open&&!applying&&$("resultout").childElementCount>0');i++)await sleep(100);
     return page.evaluate(`(()=>{const d=$("result"),r=d.getBoundingClientRect();return{
      open:d.open,title:$("resulttitle").textContent,text:$("resultout").textContent,
      staged:staged.map(e=>({label:e.label,cmds:e.cmds})),requests:window.destinationRequests,
      inView:r.top>=0&&r.bottom<=innerHeight+1&&r.left>=0&&r.right<=innerWidth+1,
      clipped:[...d.querySelectorAll(".what")].some(n=>n.scrollWidth>n.clientWidth+1)};})()`);
    };
    try{
     for(const action of ['validate','applystaged']){
      const result=await perform(action);
      check(result.open&&result.inView&&!result.clipped,'Refusal dialog is missing or clipped: '+JSON.stringify(result));
      equal(result.title,action==='validate'?'This would be refused':'Not applied','Destination-zone refusal verdict');
      check(result.text.includes('destination-zone admission refused')&&result.text.includes(name)&&result.text.includes('explicit destination'),
       'The actual admission diagnostic was lost: '+result.text);
      equal(result.staged,[{label,cmds:commands}],'Admission refusal discarded or changed the staged batch');
      equal(result.requests.length,1,'A destination-zone refusal replayed commands');
      equal(result.requests[0].status,400,'Expected actual HTTP 400');
      const sent=action==='applystaged'?[...commands,'commit','save']:commands;
      equal(result.requests[0].body.trim(),sent.join('\n'),'The refused batch changed');
      check(readFileSync(process.env.CONSOLE_CONFIG).equals(original),'Refusal changed the saved configuration');
      if(process.env.CONSOLE_SCREENSHOTS){
       mkdirSync(process.env.CONSOLE_SCREENSHOTS,{recursive:true});
       writeFileSync(process.env.CONSOLE_SCREENSHOTS+'/destination-zone-'+action+'-'+width+'.png',Buffer.from(await page.screenshot(),'base64'));
      }
     }
     // Keep the user's original batch, then remove ambiguous egress intent and
     // declare precisely the intended network in the same atomic candidate.
     const corrected=[...commands,'delete firewall rule '+name+' to','set firewall rule '+name+' destination 203.0.113.0/24'];
     await page.evaluate(`staged=[];renderStaged();stage(${JSON.stringify(label)},${JSON.stringify(corrected)})`);
     const reviewed=await perform('validate');
     equal(reviewed.title,'This would be accepted','Explicit destination review');
     equal(reviewed.requests.map(r=>r.status),[200],'Explicit destination review HTTP status');
     equal(reviewed.staged,[{label,cmds:corrected}],'Successful review discarded the corrected batch');
     check(readFileSync(process.env.CONSOLE_CONFIG).equals(original),'Review persisted the corrected candidate');
     const applied=await perform('applystaged');
     equal(applied.requests.map(r=>r.status),[200],'Explicit destination apply HTTP status');
     equal(applied.staged,[],'Successful correction remained staged');
     const saved=await page.evaluate(`(async()=>{const c=await(await api('/api/v1/config')).json();return c.rule.find(r=>r.name===${JSON.stringify(name)});})()`);
     check(saved&&saved.action==='reject'&&saved.destination==='203.0.113.0/24'&&!saved.to,'The corrected rule was not saved precisely: '+JSON.stringify(saved));
     check(!readFileSync(process.env.CONSOLE_CONFIG).equals(original),'Successful correction did not persist');
    }finally{
     await page.evaluate(`(async()=>{restoreDestinationFetch();if($("result").open)$("result").close();staged=[];renderStaged();
      const c=await(await api('/api/v1/config')).json();if(c.rule.some(r=>r.name===${JSON.stringify(name)})){
       const r=await configure(${JSON.stringify(['delete firewall rule '+name,'commit','save'])});if(!r.ok)throw new Error('Destination-zone test cleanup failed');}
      await refresh();})()`);
     equal(await page.evaluate('(async()=>await(await api("/api/v1/config")).json())()'),baseline,'Destination-zone test did not restore the original configuration');
    }
   });

   await test('an empty list explains itself and opens its own creation form at '+width,async()=>{
    await go('nat');
    const before=await page.evaluate(`(()=>{const box=$("snatlist").querySelector(".emptystate");return box&&{text:box.querySelector(".empty").textContent,hint:!!box.querySelector(".emptyhint")?.textContent,
     action:box.querySelector("button")?.textContent,panelHidden:$("addsnatpanel").classList.contains("hidden")};})()`);
    equal(before,{text:'No source NAT configured.',hint:true,action:'Add a source rule',panelHidden:true},'source NAT empty state');
    await click(page,'#snatlist .emptystate button');await sleep(150);
    const after=await page.evaluate(`({open:!$("addsnatpanel").classList.contains("hidden"),expanded:$("togglesnat").getAttribute("aria-expanded"),
     focusInside:$("addsnatpanel").contains(document.activeElement),staged:staged.length})`);
    equal(after,{open:true,expanded:'true',focusInside:true,staged:0},'the empty-state action did not open the creation form');
    // The drawer owns the foot of the window; the dock must not sit on its Add.
    const yielded=await page.evaluate(`(()=>{stage("QA draft",["set system hostname qa-drawer"]);
     const during=!$("stagedcard").getClientRects().length,badge=$("stagedbadge").textContent;
     const add=$("addsnatpanel").querySelector(".maskfoot > .primary"),r=add.getBoundingClientRect(),hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
     return{during,badge,addReachable:hit===add||add.contains(hit)};})()`);
    equal(yielded,{during:true,badge:'1 staged change',addReachable:true},'the dock sat on an open creation drawer');
    await page.evaluate('$("togglesnat").click()');
    check(await page.evaluate('$("stagedcard").getClientRects().length>0'),'the dock did not return when the drawer closed');
    await page.evaluate('staged=[];renderStaged();$("togglesnat").click()');
    // Pressed again it keeps the form open rather than toggling it shut.
    await page.evaluate('$("snatlist").querySelector(".emptystate button").click()');
    check(await page.evaluate('!$("addsnatpanel").classList.contains("hidden")'),'a second press closed the form');
    await page.evaluate('$("togglesnat").click()');
   });

   await test('firewall rules read as plain columns with service names at '+width,async()=>{
    await go('rules');
    const board=await page.evaluate(`({heads:[...$("rulelist").querySelectorAll("thead th")].map(n=>n.textContent),
     web:[...$("rulelist").querySelectorAll("tbody tr")].find(tr=>tr.textContent.includes("web-in"))?.children[3].textContent,
     policyLabel:$("defaultpolicy").closest("label").querySelector("span").textContent})`);
    equal(board.heads,['#','Action','Name','Traffic','Schedule','In use','Notes',''],'rule column heads');
    check(/tcp\/443/.test(board.web)&&/https/.test(board.web),'the rule did not name its service: '+board.web);
    equal(board.policyLabel,'When no rule matches','default policy label');
    const filtered=await page.evaluate(`(()=>{const body=el("tbody",{},[["alpha","tcp/22"],["beta","udp/53"],["gamma","tcp/443"]].map(([a,b])=>el("tr",{},[el("td",{text:a}),el("td",{text:b})])));
     const box=tableFilter(body,"rule",3),input=box.querySelector("input");input.value="tcp";input.dispatchEvent(new Event("input"));
     const some={rows:[...body.children].map(tr=>tr.classList.contains("hidden")),tally:box.querySelector("[role=status]").textContent,label:input.getAttribute("aria-label")};
     input.value="";input.dispatchEvent(new Event("input"));
     return{some,all:[...body.children].every(tr=>!tr.classList.contains("hidden")),tally:box.querySelector("[role=status]").textContent};})()`);
    equal(filtered,{some:{rows:[false,true,false],tally:'2 of 3 rules',label:'Filter rules'},all:true,tally:'3 rules'},'rule filter');
   });

   await test('the interface list says whether each configured link is really there at '+width,async()=>{
    await go('interfaces');
    const link=await page.evaluate(`(()=>{const heads=[...$("ifacelist").querySelectorAll("thead th")].map(n=>n.textContent);
     // Feed the same parser a known reading: the cell must follow it.
     const states=new Map(parseLinks("eth0 UP 10.0.0.1/24\\neth1 DOWN\\n").map(l=>[l.name,l.state]));
     return{heads,parsed:[...states]};})()`);
    check(link.heads.includes('Link'),'no live link column: '+JSON.stringify(link.heads));
    equal(link.parsed,[['eth0','UP'],['eth1','DOWN']],'link parser');
   });

   await test('a setting is found by name and its field is shown at '+width,async()=>{
    const palette=await page.evaluate(`(()=>{openPalette();$("paletteq").value="mtu";renderPalette();
     const rows=[...document.querySelectorAll("#palettelist .palitem.setting")].map(n=>({t:n.querySelector(".palt").textContent,p:n.querySelector(".palp").textContent,g:n.querySelector(".palg").textContent}));
     const head=document.querySelector("#palettelist .palhead")?.textContent;closePalette();return{rows,head};})()`);
    check(palette.head==='Settings','settings were not introduced by their own heading');
    check(palette.rows.some(r=>r.t==='MTU'&&r.p==='interface <name> mtu'&&r.g==='Network / Interfaces'),'the palette did not find the interface MTU: '+JSON.stringify(palette.rows));
    // Pages still come first, so Enter on a page name keeps meaning that page.
    const order=await page.evaluate(`(()=>{openPalette();$("paletteq").value="zone";renderPalette();
     const kinds=[...document.querySelectorAll("#palettelist .palitem")].map(n=>n.classList.contains("setting"));closePalette();return kinds;})()`);
    check(order.length>1&&order[0]===false&&order.indexOf(true)>0&&!order.slice(order.indexOf(true)).includes(false),'pages and settings are interleaved: '+JSON.stringify(order));
    if(width<900&&!await page.evaluate('!!$("navsearch").getClientRects().length'))await click(page,'#navtoggle');
    await page.evaluate('$("navsearch").value="hostname";$("navsearch").dispatchEvent(new Event("input",{bubbles:true}))');
    const hits=await page.evaluate(`[...document.querySelectorAll("#matches .navitem.setting")].map(n=>n.querySelector(".st").textContent+" @ "+n.querySelector(".sp").textContent)`);
    check(hits.includes('Hostname @ System / System'),'the rail search did not offer the system hostname: '+JSON.stringify(hits));
    await page.evaluate(`[...document.querySelectorAll("#matches .navitem.setting")].find(n=>n.querySelector(".sp").textContent==="System / System"&&n.querySelector(".st").textContent==="Hostname").click()`);
    let found=null;
    for(let i=0;i<40&&!found;i++){await sleep(100);found=await page.evaluate(`(()=>{const f=document.querySelector("#view-system .field.found");if(!f)return null;const r=f.getBoundingClientRect();
     return{view,label:f.firstElementChild.firstChild.textContent.trim(),focused:f.contains(document.activeElement),inView:r.top>=0&&r.bottom<=innerHeight};})()`);}
    equal(found,{view:'system',label:'Hostname',focused:true,inView:true},'the found setting was not revealed');
    await page.evaluate('$("navsearch").value="";$("navsearch").dispatchEvent(new Event("input",{bubbles:true}))');
    // A setting folded behind "More settings" is unfolded, not reported missing.
    await page.evaluate(`gotoSetting(SETTINGS.find(e=>e[0]==="Locale"&&e[1]==="system"))`);
    let folded=null;
    for(let i=0;i<40&&!folded;i++){await sleep(100);folded=await page.evaluate(`(()=>{const f=document.querySelector("#view-system .field.found");return f&&{label:f.firstElementChild.firstChild.textContent.trim(),shown:f.getClientRects().length>0,banner:$("banner").textContent};})()`);}
    equal(folded,{label:'Locale',shown:true,banner:''},'a folded setting was not unfolded');
    // A setting that only exists inside an object's form says where to look.
    await page.evaluate(`gotoSetting(SETTINGS.find(e=>e[0]==="Remote AS"&&e[1]==="routing:bgp"))`);await sleep(600);
    const note=await page.evaluate('({view:viewKey(),banner:$("banner").textContent})');
    check(note.view==='routing:bgp'&&/Remote AS/.test(note.banner)&&/New, or Edit/.test(note.banner),'no guidance for a per-object setting: '+JSON.stringify(note));
    await page.evaluate('banner("")');
    equal(await page.evaluate(`({none:settingHits("zzzz-no-such",5).length,short:settingHits("m",5).length,bounded:settingHits("address",3).length})`),{none:0,short:0,bounded:3},'setting search bounds');
   });

   await test('long pages list their sections; the dashboard does not at '+width,async()=>{
    await go('system');
    const index=await page.evaluate(`({hidden:$("pageindex").classList.contains("hidden"),links:[...$("pageindex").querySelectorAll("a")].map(a=>a.textContent),
     heads:[...$("view-system").querySelectorAll("h3")].filter(h=>h.checkVisibility()).map(h=>h.textContent.trim())})`);
    check(!index.hidden&&index.links.length>=4,'the System page has no section index');
    equal(index.links,index.heads,'the index is not the page\'s own headings');
    const jumped=await page.evaluate(`(()=>{const a=[...$("pageindex").querySelectorAll("a")].find(n=>n.textContent==="Update channel");a.click();
     const h=[...$("view-system").querySelectorAll("h3")].find(n=>n.textContent.trim()==="Update channel"),r=h.getBoundingClientRect(),bar=document.querySelector(".bar").getBoundingClientRect();
     return{focused:document.activeElement===h,below:r.top>=bar.bottom-1,near:r.top<innerHeight/2};})()`);
    equal(jumped,{focused:true,below:true,near:true},'the section link did not bring its heading into view');
    await go('dashboard');
    check(await page.evaluate('$("pageindex").classList.contains("hidden")'),'the dashboard grew a section index');
    await go('rules');
    check(await page.evaluate('$("pageindex").classList.contains("hidden")'),'a short page grew a section index');
   });

   await test('first steps are facts about the configuration at '+width,async()=>{
    const facts=await page.evaluate(`(()=>{const leaf=(p,v)=>({path:p.split(" "),value:v||""});
     const flags=ls=>setupFrom(ls).map(s=>s.done);
     return{empty:flags([]),
      zoned:flags([leaf("interface eth0 zone","lan"),leaf("interface eth1 address","10.0.0.1/24")]),
      bridged:flags([leaf("interface br0 zone","lan"),leaf("interface br0 member","eth2,eth3"),leaf("interface eth2 description","port"),leaf("interface eth3 description","port")]),
      full:flags([leaf("system login ops group","admins"),leaf("interface eth0 zone","lan"),leaf("nat source out zone","wan"),leaf("services ntp server","pool"),leaf("update url","u")]),
      required:setupFrom([]).map(s=>s.required)};})()`);
    equal(facts,{empty:[false,false,false,false,false],zoned:[false,false,false,false,false],bridged:[false,true,false,false,false],
     full:[true,true,true,true,true],required:[true,true,false,false,false]},'step facts');
    await go('dashboard');
    const card=await page.evaluate(`(async()=>{await buildSearchIndex();
     const seeded={hidden:$("setupcard").classList.contains("hidden"),open:$("setupcard").open,title:$("setuptitle").textContent,rows:$("setuplist").children.length,
      first:$("setuplist").querySelector("button")?.textContent};
     const keep=setupSteps;
     setupSteps=keep.map(s=>({...s,done:s.required?true:s.done}));renderSetup();
     const recommended={hidden:$("setupcard").classList.contains("hidden"),open:$("setupcard").open,title:$("setuptitle").textContent};
     setupSteps=keep.map(s=>({...s,done:true}));renderSetup();
     const complete=$("setupcard").classList.contains("hidden");
     setupSteps=keep;renderSetup();return{seeded,recommended,complete};})()`);
    equal(card.seeded,{hidden:false,open:true,title:'Finish setting up',rows:5,first:'Open Administrators'},'seeded appliance');
    equal(card.recommended,{hidden:false,open:false,title:'Recommended next steps'},'only recommendations left');
    check(card.complete,'a finished setup still showed its list');
    await click(page,'#setupcard summary');await sleep(50);
    await page.evaluate('$("setuplist").querySelector("button").click()');await sleep(400);
    equal(await page.evaluate('view'),'users','a step did not lead to its page');
   });

   await test('fields explain themselves in the CLI\'s words, once, at '+width,async()=>{
    await go('ha');
    const ha=await page.evaluate(`(()=>{const box=$("haform"),fields=[...box.querySelectorAll(".field")];
     const of=key=>fields[HA.findIndex(f=>f[0]===key)],hint=key=>of(key).querySelector(".hint");
     return{priority:hint("priority").textContent,priorityProse:hint("priority").classList.contains("help"),
      mode:hint("mode").textContent,modeProse:hint("mode").classList.contains("help"),
      echo:hint("sync-interface").textContent,cli:FIELD_HELP["system ha sync-interface"],
      wild:fieldHelp("mtu","interface eth0"),wild2:fieldHelp("remote-as","protocols bgp neighbor 192.0.2.1"),none:fieldHelp("no-such-field","system ha")};})()`);
    check(/defaults to 200/.test(ha.priority)&&!ha.priorityProse,'a default no longer leads an empty field: '+ha.priority);
    check(/witness/.test(ha.mode)&&/two-node/.test(ha.mode)&&ha.modeProse,'the election mode is unexplained: '+ha.mode);
    equal({echo:ha.echo,cli:ha.cli},{echo:'',cli:'dedicated control interface'},'help that repeats its label');
    check(ha.wild&&ha.wild2&&ha.none==='','wildcard lookup: '+JSON.stringify(ha));
    // Typing does not take the explanation away where nothing else can be said.
    const typed=await page.evaluate(`(async()=>{const f=[...$("hawitnessform").querySelectorAll(".field")][HA_WITNESS.findIndex(f=>f[0]==="member")]||null;
     const g=[...$("configsyncform").querySelectorAll(".field")][CONFIG_SYNC.findIndex(f=>f[0]==="peer-fingerprint")],i=g.querySelector("input"),before=g.querySelector(".hint").textContent;
     i.value="abc";i.dispatchEvent(new Event("change"));const during=g.querySelector(".hint").textContent;i.value="";i.dispatchEvent(new Event("change"));dirty.clear();
     return{before,during,member:!!f};})()`);
    check(typed.before&&typed.during===typed.before,'help vanished while typing: '+JSON.stringify(typed));
    await go('routing:filters');
    equal(await page.evaluate(`[...$("redistfilters").querySelectorAll(".hint")].filter(h=>h.textContent.trim()).length`),0,'a matrix cell grew a sentence');
   });

   await test('long forms lead with what matters and fold the rest at '+width,async()=>{
    await go('ha');
    const shown=()=>page.evaluate(`[...$("haform").querySelectorAll(".field")].map((f,i)=>f.getClientRects().length?HA[i][0]:null).filter(Boolean)`);
    equal(await shown(),['mode','enabled','witness','sync-interface','node','priority'],'witness-mode essentials');
    await page.evaluate(`(()=>{const s=[...$("haform").querySelectorAll(".field")][HA.findIndex(f=>f[0]==="mode")].querySelector("select");s.value="two-node";s.dispatchEvent(new Event("change",{bubbles:true}));})()`);
    equal(await shown(),['mode','enabled','sync-interface','node','priority','heartbeat-listen','heartbeat-peer'],'two-node essentials');
    await page.evaluate(`[...$("haform").querySelectorAll("button")].find(b=>b.textContent==="More settings").click()`);
    const all=await shown();
    check(all.includes('peer-timeout-ms')&&all.includes('lease-ms')&&!all.includes('witness')&&all.length===15,'More settings did not reveal the two-node mask: '+JSON.stringify(all));
    await page.evaluate(`(()=>{const s=[...$("haform").querySelectorAll(".field")][HA.findIndex(f=>f[0]==="mode")].querySelector("select");s.value="";s.dispatchEvent(new Event("change",{bubbles:true}));dirty.clear();})()`);
    // A run of fields with no groups folds too, and never hides what is set.
    const flat=await page.evaluate(`(()=>{const fields=[["a","Alpha"],["b","Beta"],["c","Gamma"],["d","Delta"],["e","Epsilon"],["f","Zeta"],["g","Eta"],["h","Theta"]];
     const lead=defaultShape(fields,null,null,false).essential,short=defaultShape(fields.slice(0,6),null,null,false),required=defaultShape(fields,null,"h",true).essential;
     const grouped=defaultShape([["act","Action"],["#","What it matches"],["m1","One"],["m2","Two"],["#","What it changes"],["s1","Set"]],null,null,true).essential;
     const settings=defaultShape([["act","Action"],["#","What it matches"],["m1","One"]],null,null,false).essential;
     const keep={essential:["x"]};
     const built=fieldGrid(fields,{g:"kept"},null,defaultShape(fields,null,null,false));document.body.append(built.grid);
     const visible=[...built.grid.querySelectorAll(".field")].filter(f=>f.getClientRects().length).map(f=>f.firstChild.textContent);built.grid.remove();
     return{lead,short,required,grouped,settings,same:defaultShape(fields,keep,null,false)===keep,visible,more:!!built.more};})()`);
    equal(flat,{lead:['a','b','c','d'],short:null,required:['a','b','c','d','h'],grouped:['act','m1','m2'],settings:['act'],same:true,
     visible:['Alpha','Beta','Gamma','Delta','Eta'],more:true},'default folding');
    await go('routepolicy:maps');
    const rm=await page.evaluate(`(()=>{$("togglerm").click();const p=$("addrmpanel"),v=[...p.querySelectorAll(".field")].filter(f=>f.getClientRects().length).length,
     all=p.querySelectorAll(".field").length,more=[...p.querySelectorAll("button")].some(b=>b.textContent==="More settings");$("togglerm").click();return{v,all,more};})()`);
    check(rm.more&&rm.v<=8&&rm.all>=15,'the route-map rule form still opens as a wall of fields: '+JSON.stringify(rm));
   });

   await test('a section opens with one sentence; warnings stay in sight at '+width,async()=>{
    await go('ha');
    const ha=await page.evaluate(`(()=>{const v=$("view-ha"),more=[...v.querySelectorAll("details.ledemore")];
     const warn=[...v.querySelectorAll("p.lede")].find(p=>p.textContent.includes("split-brain"));
     return{folded:more.length,closed:more.every(d=>!d.open),warnVisible:!!warn&&warn.getClientRects().length>0&&!warn.closest("details"),
      long:[...v.querySelectorAll("p.lede")].filter(p=>p.getClientRects().length&&p.textContent.trim().length>140&&!p.textContent.includes("split-brain")).map(p=>p.textContent.trim().slice(0,40))};})()`);
    check(ha.folded>=2&&ha.closed&&ha.warnVisible,'HA explanations: '+JSON.stringify(ha));
    equal(ha.long,[],'a section still opens with a paragraph');
    const opened=await page.evaluate(`(()=>{const d=$("view-ha").querySelector("details.ledemore");d.querySelector("summary").click();const r={open:d.open,text:d.querySelector("p").textContent.trim().length>20};d.open=false;return r;})()`);
    equal(opened,{open:true,text:true},'Details did not open');
   });

   await test('the dashboard is one screen of measurements with real system vitals at '+width,async()=>{
    await go('dashboard');
    // Processor use needs two samples; wait for the stream to deliver them.
    let vitals=null;
    for(let i=0;i<60&&!vitals;i++){await sleep(500);vitals=await page.evaluate(`(()=>{const f=management.getSnapshot().frame;return f&&f.system&&f.system.cpu_percent!==null&&f.sequence>1?f.system:null;})()`);}
    check(vitals,'the telemetry stream never carried measured system vitals');
    check(vitals.memory.total_bytes>0&&vitals.uptime_seconds>0&&vitals.filesystems.length>0&&vitals.cpu_percent>=0&&vitals.cpu_percent<=100,'implausible vitals: '+JSON.stringify(vitals));
    const view=await page.evaluate(`(()=>{const root=document.querySelector('#react-dashboard [data-react-view=dashboard]');const vis=n=>n.getClientRects().length>0;
     const meter=n=>root.querySelector('[role=meter][aria-label="'+n+'"]');
     return{tiles:[...root.querySelectorAll('.overview-metric')].filter(vis).length,healthCard:!!root.querySelector('.dash-status .management-panel'),
      healthActions:[...root.querySelectorAll('.health-bar button')].map(b=>b.textContent),
      cpu:meter('Processor use').getAttribute('aria-valuenow'),memory:meter('Memory use').getAttribute('aria-valuenow'),
      scope:root.querySelector('#traffic-scope').getAttribute('aria-label'),periods:[...root.querySelectorAll('.range button')].map(b=>b.textContent),
      panels:[...root.querySelectorAll('.dash-grid .management-panel h3')].map(h=>h.textContent),
      fits:document.documentElement.scrollWidth<=innerWidth,units:root.querySelector('.overview-metric strong').textContent.includes('bit/s')};})()`);
    check(view.tiles===6&&!view.healthCard&&view.fits&&view.units,'dashboard shape: '+JSON.stringify(view));
    equal(view.healthActions,['Retry health check','Open system health','Configure NTP'],'health line actions');
    check(view.cpu!==null&&view.memory!==null,'vitals were not drawn: '+JSON.stringify(view));
    equal(view.periods,['Live','1 h','24 h'],'chart periods');
    for(const panel of ['Traffic','System','Firewall','Hosts','Routing','VPN'])check(view.panels.includes(panel),'missing panel '+panel+': '+JSON.stringify(view.panels));
    // The recorded period asks the appliance for its stored series, once.
    const before=page.requests.filter(u=>u.includes('/api/v1/metrics')).length;
    await page.evaluate(`[...document.querySelectorAll('#react-dashboard .range button')].find(b=>b.textContent==='1 h').click()`);await sleep(600);
    check(page.requests.filter(u=>u.includes('/api/v1/metrics')).length>before,'the 1 h period did not read stored history');
    check(await page.evaluate(`document.querySelector('#react-dashboard .range button.selected').textContent==='1 h'`),'the period did not change');
    await page.evaluate(`[...document.querySelectorAll('#react-dashboard .range button')].find(b=>b.textContent==='Live').click()`);
   });

   if(width===1440){
    await test('the embedded settings catalogue is what the console builds',async()=>{
     const embedded=await page.evaluate('SETTINGS');
     const fresh=await collectSettings(page);
     check(embedded.length>=300,'the catalogue is missing or nearly empty: '+embedded.length);
     const key=e=>e.join(' | ');
     const have=new Set(embedded.map(key)),want=new Set(fresh.map(key));
     const missing=[...want].filter(k=>!have.has(k)).slice(0,8),stale=[...have].filter(k=>!want.has(k)).slice(0,8);
     equal({missing,stale},{missing:[],stale:[]},'src/settings-index.json is stale — regenerate it with tests/console/settings-index.mjs');
     const places=new Set(await page.evaluate('paletteItems().map((_,i)=>i).length?SECTIONS.flatMap(g=>g.items.map(i=>i.tab?i.v+":"+i.tab:i.v)):[]'));
     check(embedded.every(e=>places.has(e[1])),'a catalogued setting points at a page that does not exist');
    });
   }
   await test('workflow checks raised no JavaScript errors at '+width,()=>{equal(page.thrown,[],'browser JavaScript errors');});
  }finally{page.close();}
 }
}
