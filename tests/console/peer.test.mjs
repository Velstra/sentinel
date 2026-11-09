// Real browser -> local API -> pinned TLS peer API. All configuration and
// certificates are disposable test fixtures; neither server applies networking.
import { browser, signIn, sleep, test, check, summary } from './harness.mjs';
import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, renameSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

if (!process.env.CONSOLE_BINARY || !process.env.CONSOLE_CONFIG) throw Error('Run with tests/console/run.sh');
const probe = createServer();
await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
const port = probe.address().port;
await new Promise(resolve => probe.close(resolve));
const member = `127.0.0.1:${port}`;
const work = mkdtempSync(join(tmpdir(), 'sentinel-peer-console-'));
const config = process.env.CONSOLE_CONFIG;
const original = readFileSync(config, 'utf8');
const replaceLocal = contents => {
  writeFileSync(config + '.peer-test', contents, {mode:0o600});
  renameSync(config + '.peer-test', config);
};
writeFileSync(join(work,'peer.toml'), '[system]\nhostname="peer-console-test"\n[services.ntp]\nupstream=["192.0.2.123"]\n', {mode:0o600});
writeFileSync(join(work,'token'), process.env.CONSOLE_TOKEN, {mode:0o600});
const peer = spawn(process.env.CONSOLE_BINARY, ['api','--listen',member,'--config',join(work,'peer.toml'),'--token-file',join(work,'token'),'--no-apply'], {stdio:['ignore','pipe','pipe']});
// Drain diagnostics without retaining any configuration/credentials in evidence.
peer.stdout.resume(); peer.stderr.resume();
let page;
try {
  let ready = false;
  for (let i=0;i<80;i++) {
    if (peer.exitCode !== null) throw Error('Peer API exited during startup');
    try { execFileSync('curl',['--disable','--silent','--fail','--insecure','--max-time','1',`https://${member}/api/v1/health`], {stdio:'ignore'}); ready = true; break; } catch {}
    await sleep(100);
  }
  check(ready, 'TLS peer did not start');
  const cert = new X509Certificate(readFileSync(join(work,'web-tls','cert.pem')));
  const pin = createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
  const paired = original + `\n[system.config-sync]\npeer=[${JSON.stringify(member)}]\nsecret=${JSON.stringify(process.env.CONSOLE_TOKEN)}\npeer-fingerprint=${JSON.stringify(pin)}\n`;
  replaceLocal(paired);
  page = await browser({width:1440,height:1000});
  await page.goto(process.env.CONSOLE_URL); await signIn(page, process.env.CONSOLE_TOKEN);
  await test('peer dashboard and system health use the real pinned remote API', async () => {
    await page.evaluate(`target=${JSON.stringify(member)};goto('dashboard');`);
    for(let i=0;i<100;i++) {
      if(await page.evaluate('!!management.getSnapshot().frame && management.getSnapshot().health?.clock.ntp_servers?.[0] === "192.0.2.123"')) break;
      await sleep(100);
    }
    const result = await page.evaluate(`(() => {
      const s=management.getSnapshot();return {
        selected:s.member===${JSON.stringify(member)},live:s.connected&&!!s.frame,
        health:s.health?.clock.ntp_servers?.[0]==='192.0.2.123',
        oldWarning:document.querySelector('#react-dashboard').textContent.includes('Live telemetry belongs to this appliance'),
        detailsHidden:document.querySelector('.dashboard-details').hidden,
        localEditorHidden:!document.querySelector('#toml-candidate'),
        ntpDisabled:[...document.querySelectorAll('#react-dashboard button')].find(b=>b.textContent.includes('Configure NTP'))?.disabled
      };
    })()`);
    check(result.selected&&result.live&&result.health&&!result.oldWarning&&result.detailsHidden&&result.localEditorHidden&&result.ntpDisabled, 'Incorrect member boundary: '+JSON.stringify(result));
  });
  await test('peer observations keep responsive themes, keyboard retry and explicit local history', async () => {
    await page.evaluate('goto("history")'); await sleep(150);
    check(await page.evaluate('document.querySelector("#historycharts").textContent.includes("Historical metrics are stored locally")'), 'Local history mislabeled as peer history');
    await page.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});
    await page.send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
    for(const theme of ['light','dark']) {
      await page.evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)});goto('system');`);
      await sleep(200);
      const layout=await page.evaluate(`({fits:document.documentElement.scrollWidth<=innerWidth,ntp:document.querySelector('#react-system-health').textContent.includes('192.0.2.123')})`);
      check(layout.fits&&layout.ntp,'Peer health layout/context failed: '+JSON.stringify(layout));
      await page.evaluate(`[...document.querySelectorAll('#react-system-health button')].find(b=>b.textContent.includes('Retry health check')).focus()`);
      await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
      await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
      const out=process.env.CONSOLE_SCREENSHOTS;
      if(out) { mkdirSync(out,{recursive:true}); writeFileSync(join(out,`peer-health-${theme}-narrow.png`),Buffer.from(await page.screenshot(),'base64')); }
    }
  });
  await test('peer legacy forms refuse staging and gate writes after asynchronous redraws', async () => {
    try {
      await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
      await page.evaluate('target="";goto("system")'); await sleep(250);
      await page.evaluate('stage("Retained local draft",["set system hostname retained-local-draft"])');
      await page.evaluate(`target=${JSON.stringify(member)};goto('system')`); await sleep(300);
      const system=await page.evaluate(`(()=>{
        const before=stagedCommands();stage('Refused peer draft',['set system hostname wrong-member']);
        const stageButton=document.querySelector('#sys-ident .maskfoot .primary');
        return {hostname:document.querySelector('#sys-ident [aria-label="Hostname"]')?.value,
          disabled:stageButton?.disabled,reason:document.querySelector('#write-boundary')?.textContent,
          apply:document.querySelector('#applystaged').disabled,
          refused:JSON.stringify(before)===JSON.stringify(stagedCommands()),before,
          editorAbsent:!document.querySelector('#toml-candidate')};})()`);
      check(system.hostname==='peer-console-test'&&system.disabled&&system.apply&&system.refused&&system.editorAbsent&&/select this appliance/i.test(system.reason||''),JSON.stringify(system));
      await page.evaluate('goto("rules")'); await sleep(300);
      const rules=await page.evaluate(`({newDisabled:document.querySelector('#togglerule').disabled,
        policyDisabled:document.querySelector('#defaultpolicy').disabled,
        enabled:[...document.querySelectorAll('#view-rules button')].filter(n=>/^(new|add|stage|edit|delete)/i.test(n.textContent.trim())&&!n.disabled).map(n=>n.textContent)})`);
      check(rules.newDisabled&&rules.policyDisabled&&!rules.enabled.length,JSON.stringify(rules));
      await page.evaluate('target="";goto("system")');await sleep(300);
      const local=await page.evaluate(`({enabled:!document.querySelector('#sys-ident .maskfoot .primary').disabled,
        hostname:document.querySelector('#sys-ident [aria-label="Hostname"]')?.value,
        draft:stagedCommands(),hidden:document.querySelector('#write-boundary')?.classList.contains('hidden')})`);
      check(local.enabled&&local.hostname==='console-test'&&local.hidden&&JSON.stringify(local.draft)===JSON.stringify(system.before),JSON.stringify(local));
    } finally {
      await page.evaluate('target="";staged=[];dirty.clear();renderStaged();goto("dashboard")');await sleep(100);
    }
  });
  await test('write-context gates preserve unrelated disabled controls and readable navigation', async () => {
    const result=await page.evaluate(`(async()=>{
      const main=document.querySelector('main'),disabled=document.createElement('button'),enabled=document.createElement('button');
      disabled.textContent='Stage unavailable prerequisite';disabled.disabled=true;
      enabled.textContent='Stage available action';enabled.title='Original title';
      enabled.setAttribute('aria-describedby','crumb');main.append(disabled,enabled);
      try {
        target=${JSON.stringify(member)};gateWrites();await new Promise(resolve=>setTimeout(resolve,0));
        const gated=enabled.disabled&&disabled.disabled&&!document.querySelector('#refresh').disabled;
        const late=document.createElement('button');late.textContent='Stage late async action';main.append(late);
        await new Promise(resolve=>setTimeout(resolve,0));const lateGated=late.disabled;
        target='';gateWrites();const restored=!enabled.disabled&&disabled.disabled&&!late.disabled&&enabled.title==='Original title'&&enabled.getAttribute('aria-describedby')==='crumb';late.remove();
        return {gated,lateGated,restored};
      } finally {disabled.remove();enabled.remove();target='';gateWrites();}
    })()`);
    check(result.gated&&result.lateGated&&result.restored,JSON.stringify(result));
  });
  await test('configuration delivery, pending, conflict and unknown stay separate from peer reachability', async () => {
    // Deterministic GET fixtures exercise presentation only. Native outbox and
    // conflict behavior have separate real two-node tests; this is no substitute.
    const result=await page.evaluate(`(async()=>{
      const original=api,rows=[];
      try {
        for(const [sync,expected] of [['in-sync','Delivered'],['pending','Pending delivery'],['conflict','Conflict'],[null,'Unknown'],['unexpected','Unknown'],['constructor','Unknown']]){
         for(const reachable of [true,false]){
          api=async(path,...args)=>path==='/api/v1/stack'?new Response(JSON.stringify({members:[
            {name:'self',hostname:'local-fixture',reachable:true},
            {name:'peer-fixture',hostname:'peer-fixture',reachable,sync}
          ]}),{headers:{'Content-Type':'application/json'}}):original(path,...args);
          await refreshStack();await refreshCluster();
          const stack=document.querySelector('#stacktable').textContent,rail=document.querySelector('#clusterlist').textContent;
          const cells=[...document.querySelectorAll('#stacktable tr')].find(row=>row.cells[0]?.textContent==='peer-fixture')?.cells;
          rows.push({sync,expected,stack:stack.includes(expected),rail:rail.includes(expected),actualReachability:cells?.[2]?.textContent===(reachable?'reachable':'unreachable')});
         }
        }
        return rows;
      } finally {api=original;await refreshStack();await refreshCluster();}
    })()`);
    check(result.length===12&&result.every(r=>r.stack&&r.rail&&r.actualReachability),JSON.stringify(result));
  });
  await test('member names and full delivery labels stay readable inside the selectable rail', async () => {
    // Presentation-only geometry regression from the actual native1225 pending
    // screenshot. Durable delivery and conflict behavior have separate live tests.
    const rows=[];
    try {
      await page.evaluate(`(async()=>{
        await refreshCluster();window.qaRailLayoutOriginal=api;
        window.qaRailLayout={sync:'pending',hostname:'qa-fw-a'};
        api=async(path,...args)=>path==='/api/v1/stack'?new Response(JSON.stringify({members:[
          {name:'self',hostname:'qa-fw-b',reachable:true},
          {name:${JSON.stringify(member)},hostname:window.qaRailLayout.hostname,reachable:true,sync:window.qaRailLayout.sync}
        ]}),{headers:{'Content-Type':'application/json'}}):window.qaRailLayoutOriginal(path,...args);
        target='';goto('stack');await refreshCluster();
      })()`);
      for(const width of [1440,390,320]) {
        await page.send('Emulation.setDeviceMetricsOverride',{width,height:920,deviceScaleFactor:1,mobile:width<900});
        for(const theme of ['light','dark']) {
          await page.evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)})`);
          for(const hostname of ['qa-fw-a','edge-firewall-member-with-long-name.internal.example']) {
            for(const sync of ['in-sync','pending','conflict',null]) {
              const row=await page.evaluate(`(async()=>{
                Object.assign(window.qaRailLayout,${JSON.stringify({hostname,sync})});await refreshCluster();
                const menu=document.querySelector('#navtoggle');
                if(menu.getClientRects().length&&menu.getAttribute('aria-expanded')==='false')menu.click();
                await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
                const button=[...document.querySelectorAll('#clusterlist button')].find(n=>n.querySelector('.role')?.textContent==='peer');
                button.scrollIntoView({block:'center'});
                const name=button.querySelector('.member-name'),state=button.querySelector('.member-state'),badge=state.querySelector('.pill');
                const b=button.getBoundingClientRect(),n=name.getBoundingClientRect(),s=state.getBoundingClientRect(),label=badge.getBoundingClientRect();
                const range=document.createRange();range.selectNodeContents(name);
                const overlap=n.left<s.right&&n.right>s.left&&n.top<s.bottom&&n.bottom>s.top;
                return {width:innerWidth,theme:document.documentElement.dataset.theme,hostname:name.textContent,sync:window.qaRailLayout.sync,
                  name_width:n.width,button_width:b.width,name_lines:range.getClientRects().length,
                  readable:name.textContent==='qa-fw-a'?range.getClientRects().length===1:n.width>=Math.min(96,b.width*.6),
                  contained:n.left>=b.left&&n.right<=b.right&&n.top>=b.top&&n.bottom<=b.bottom&&label.left>=b.left&&label.right<=b.right&&label.top>=b.top&&label.bottom<=b.bottom,
                  overlap,visible:!!button.getClientRects().length,document_fits:document.documentElement.scrollWidth<=innerWidth};
              })()`);
              rows.push(row);
              if(process.env.CONSOLE_SCREENSHOTS&&hostname==='qa-fw-a'&&sync==='pending') {
                mkdirSync(process.env.CONSOLE_SCREENSHOTS,{recursive:true});
                writeFileSync(join(process.env.CONSOLE_SCREENSHOTS,`member-pending-${theme}-${width}.png`),Buffer.from(await page.screenshot(),'base64'));
              }
            }
          }
        }
      }
      check(rows.length===48&&rows.every(row=>row.readable&&row.contained&&!row.overlap&&row.visible&&row.document_fits),JSON.stringify(rows.filter(row=>!row.readable||!row.contained||row.overlap||!row.visible||!row.document_fits)));
      await page.evaluate(`document.querySelectorAll('#clusterlist button')[1].focus()`);
      await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
      await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
      check(await page.evaluate(`target===${JSON.stringify(member)}`),'Member selection lost native keyboard activation');
    } finally {
      await page.evaluate(`api=window.qaRailLayoutOriginal;delete window.qaRailLayoutOriginal;delete window.qaRailLayout;target='';goto('dashboard')`);
      await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
      await page.evaluate('refreshCluster()');
    }
  });
  await test('the offered Refresh keeps Stack and the member rail on one delivery snapshot', async () => {
    // Presentation fixtures reproduce the native1199 failure. Native durable
    // queue/conflict behavior is independently exercised on real QA appliances.
    const result=await page.evaluate(`(async()=>{
      const original=api,rows=[];let phase='in-sync',calls=0;
      try {
        api=async(path,...args)=>{
          if(path!=='/api/v1/stack')return original(path,...args);
          calls++;if(phase==='unavailable')throw Error('Member snapshot fixture unavailable');
          return new Response(JSON.stringify({members:[
            {name:'self',hostname:'local-fixture',reachable:true},
            {name:'peer-fixture',hostname:'peer-fixture',reachable:true,sync:phase}
          ]}),{headers:{'Content-Type':'application/json'}});
        };
        target='';view='stack';panel=null;await refreshStack();await refreshCluster();
        for(const [next,label] of [['pending','Pending delivery'],['conflict','Conflict'],['in-sync','Delivered'],['unavailable',null]]){
          phase=next;calls=0;document.querySelector('#refresh').click();
          for(let i=0;i<80;i++){
            const table=document.querySelector('#stacktable').textContent;
            if(label?table.includes(label):table.includes('Member snapshot fixture unavailable'))break;
            await new Promise(resolve=>setTimeout(resolve,25));
          }
          const table=document.querySelector('#stacktable').textContent,rail=document.querySelector('#clusterlist').textContent;
          rows.push({phase,calls,table:label?table.includes(label):table.includes('Member snapshot fixture unavailable'),
            rail:label?rail.includes(label):!rail.includes('Delivered')&&!document.querySelector('#cluster-sync-note').classList.contains('hidden'),
            coherentNotices:document.querySelector('#stack-sync-note').classList.contains('hidden')===document.querySelector('#cluster-sync-note').classList.contains('hidden')});
        }
        return rows;
      } finally {api=original;await refreshStack();await refreshCluster();}
    })()`);
    check(result.length===4&&result.every(row=>row.calls===1&&row.table&&row.rail&&row.coherentNotices),JSON.stringify(result));
  });
  await test('late member reads cannot repopulate the console after actual sign-out', async () => {
    try {
      await page.evaluate(`(()=>{
        const original=api;window.qaMemberOriginalAPI=original;
        api=async(path,...args)=>path==='/api/v1/stack'?new Promise(resolve=>{
          window.qaReleaseMemberSnapshot=()=>resolve(new Response(JSON.stringify({members:[
            {name:'self',hostname:'late-private-member-fixture',reachable:true}
          ]}),{headers:{'Content-Type':'application/json'}}));
        }):original(path,...args);
        window.qaPendingMemberRead=refreshCluster();
      })()`);
      check(await page.evaluate('typeof window.qaReleaseMemberSnapshot==="function"'),'Delayed request did not start');
      await page.evaluate('document.querySelector("#signout").click();window.qaReleaseMemberSnapshot()');
      await page.evaluate('window.qaPendingMemberRead');
      const result=await page.evaluate('({signedOut:!token,rail:document.querySelector("#clusterlist").textContent,table:document.querySelector("#stacktable").textContent})');
      check(result.signedOut&&!result.rail.trim()&&!result.table.trim(),JSON.stringify(result));
    } finally {
      await page.evaluate('api=window.qaMemberOriginalAPI;delete window.qaMemberOriginalAPI;delete window.qaReleaseMemberSnapshot;delete window.qaPendingMemberRead');
      await signIn(page,process.env.CONSOLE_TOKEN);
    }
  });
  await test('peer write boundaries and configuration conflict feedback fit both themes and narrow screens', async () => {
    try {
      for(const width of [1440,390]) {
        await page.send('Emulation.setDeviceMetricsOverride',{width,height:844,deviceScaleFactor:1,mobile:width<900});
        for(const theme of ['light','dark']) {
          await page.evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)});target=${JSON.stringify(member)};goto('system')`);
          await sleep(250);
          const boundary=await page.evaluate(`({fits:document.documentElement.scrollWidth<=innerWidth,
            explained:!!document.querySelector('#write-boundary').getClientRects().length,
            disabled:document.querySelector('#sys-ident .maskfoot .primary').disabled})`);
          check(boundary.fits&&boundary.explained&&boundary.disabled,JSON.stringify({width,theme,...boundary}));
          if(process.env.CONSOLE_SCREENSHOTS) {
            const out=process.env.CONSOLE_SCREENSHOTS;mkdirSync(out,{recursive:true});
            await page.evaluate('window.scrollTo(0,0)');
            writeFileSync(join(out,`peer-write-boundary-${theme}-${width}.png`),Buffer.from(await page.screenshot(),'base64'));
          }
          const conflict=await page.evaluate(`(async()=>{
            const original=api;
            try {
              api=async(path,...args)=>path==='/api/v1/stack'?new Response(JSON.stringify({members:[
                {name:'self',hostname:'local-fixture',reachable:true},
                {name:${JSON.stringify(member)},hostname:'peer-with-a-long-appliance-hostname',reachable:true,sync:'conflict'}
              ]}),{headers:{'Content-Type':'application/json'}}):original(path,...args);
              view='stack';panel=null;await refresh();await refreshCluster();
              return {fits:document.documentElement.scrollWidth<=innerWidth,table:document.querySelector('#stacktable').textContent.includes('Conflict'),
                recovery:document.querySelector('#cluster-sync-note').textContent.includes('Compare member configurations')};
            } finally {api=original;}
          })()`);
          check(conflict.fits&&conflict.table&&conflict.recovery,JSON.stringify({width,theme,...conflict}));
          if(process.env.CONSOLE_SCREENSHOTS)writeFileSync(join(process.env.CONSOLE_SCREENSHOTS,`configuration-conflict-${theme}-${width}.png`),Buffer.from(await page.screenshot(),'base64'));
        }
      }
    } finally {
      await page.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
      await page.evaluate(`document.documentElement.setAttribute('data-theme','light');target=${JSON.stringify(member)};goto('system')`);await sleep(150);
    }
  });
  await test('a TLS pin mismatch stays unavailable without logging out the local operator', async () => {
    await page.evaluate(`target=${JSON.stringify(member)};goto('system')`);await sleep(200);
    for(let i=0;i<50&&await page.evaluate('management.getSnapshot().healthBusy');i++) await sleep(100);
    check(await page.evaluate('!management.getSnapshot().healthBusy'), 'Previous health request did not complete');
    replaceLocal(paired.replace(pin,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='));
    await page.evaluate('management.refreshHealth()');
    for(let i=0;i<50&&!await page.evaluate('!!management.getSnapshot().healthError');i++) await sleep(100);
    const result=await page.evaluate('({signedIn:!!token,error:management.getSnapshot().healthError,unknown:document.querySelector("#react-system-health").textContent.includes("Unknown · stale")})');
    check(result.signedIn&&result.error&&result.unknown,'Peer TLS failure affected local session or looked healthy: '+JSON.stringify(result));
    replaceLocal(paired);
    await page.evaluate('management.refreshHealth()');
    for(let i=0;i<50&&await page.evaluate('!!management.getSnapshot().healthError');i++) await sleep(100);
    check(await page.evaluate('!management.getSnapshot().healthError'), 'Peer health did not recover');
    await page.evaluate('target="";goto("dashboard")');
    await sleep(100);
    check(await page.evaluate('management.getSnapshot().member===""&&!document.querySelector(".dashboard-details").hidden'), 'Local member did not restore');
  });
  await test('the browser stays on the local origin without uncaught errors', () => {
    const origin = new URL(process.env.CONSOLE_URL).origin;
    check(page.requests.filter(url=>/^https?:/.test(url)).every(url=>new URL(url).origin===origin), 'Browser connected directly to peer');
    check(!page.thrown.length,page.thrown.join('\n'));
  });
  process.exitCode=summary()?1:0;
} finally {
  replaceLocal(original);
  if(page) await page.close();
  if(peer.exitCode===null) { peer.kill('SIGTERM'); await new Promise(resolve=>peer.once('exit',resolve)); }
  rmSync(work,{recursive:true,force:true});
}
