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
  await test('a TLS pin mismatch stays unavailable without logging out the local operator', async () => {
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
