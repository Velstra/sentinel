// Real browser/API health observation plus explicitly synthetic degraded UI
// states. This suite never writes configuration or resets host services/TPM.
import { browser, signIn, sleep, test, check, summary } from './harness.mjs';
import { mkdirSync, writeFileSync } from 'node:fs';

const page = await browser({width: 1440, height: 1000});
try {
  await page.goto(process.env.CONSOLE_URL);
  await signIn(page, process.env.CONSOLE_TOKEN);
  await page.evaluate('management.refreshHealth()');
  await test('system health reads the authenticated API and owns both console surfaces', async () => {
    const facts = await page.evaluate(`(async () => {
      const response = await api('/api/v1/system/health');
      const actual = await response.json();
      goto('system'); await new Promise(resolve => setTimeout(resolve, 150));
      return {
        actualShape: !!actual.clock && !!actual.systemd && !!actual.tpm && !!actual.network,
        received: !!management.getSnapshot().health,
        clock: document.querySelector('#react-system-health').textContent.includes('Appliance clock (UTC)'),
        beforeIdentity: !!document.querySelector('#react-system-health').nextElementSibling.querySelector('#sys-ident'),
        overview: document.querySelector('#react-dashboard').textContent.includes('Open system health')
      };
    })()`);
    check(Object.values(facts).every(Boolean), 'system health is not backed by the real API/mounts: '+JSON.stringify(facts));
  });
  await test('configure NTP opens the existing staged form without changing configuration', async () => {
    const result = await page.evaluate(`(async () => {
      const before = await (await api('/api/v1/config')).text();
      document.querySelector('#react-system-health button:last-of-type').click();
      await new Promise(resolve => setTimeout(resolve, 200));
      const after = await (await api('/api/v1/config')).text();
      return {
        destination: view === 'services' && tabs.services === 'resolution',
        form: document.querySelector('#svc-ntp').getClientRects().length > 0,
        copy: document.querySelector('#view-services').textContent.includes('serve-on') && document.querySelector('#view-services').textContent.includes('not required for clock synchronisation'),
        unchanged: before === after,
      };
    })()`);
    check(Object.values(result).every(Boolean), 'NTP navigation diverged from the canonical form: '+JSON.stringify(result));
  });
  await test('synthetic TPM/clock/default-route warnings, failure and malformed replies never appear healthy', async () => {
    const result = await page.evaluate(`(async () => {
      goto('system'); await new Promise(resolve => setTimeout(resolve, 100));
      const original = api;
      try {
        const baseline = management.getSnapshot().health;
        const degraded = structuredClone(baseline);
        degraded.status = 'warning'; degraded.clock.synchronised = false;
        degraded.network.default_route = false;
        degraded.tpm.status = 'warning'; degraded.tpm.present = true;
        degraded.issues = [
          {code:'clock-unsynchronised',severity:'warning',message:'The system clock is not synchronised.',action:'Configure reachable NTP upstreams.'},
          {code:'network.no_default_route',severity:'warning',message:'No IPv4/IPv6 default route; external time servers may be unreachable.',action:'Configure a gateway or reachable local NTP.'},
          {code:'tpm-setup-failed',severity:'warning',message:'TPM initialisation failed.',action:'Inspect systemd-tpm2-setup.service. Do not clear or reset the TPM.'}
        ];
        api = (path,...args) => path === '/api/v1/system/health' ? Promise.resolve(new Response(JSON.stringify(degraded))) : original(path,...args);
        await management.refreshHealth(); await new Promise(resolve => setTimeout(resolve, 30));
        const card = document.querySelector('#react-system-health');
        const warning = card.textContent.includes('Needs attention') && card.textContent.includes('Do not clear or reset the TPM') && card.textContent.includes('No IPv4/IPv6 default route');
        api = (path,...args) => path === '/api/v1/system/health' ? Promise.reject(new Error('synthetic-private-error')) : original(path,...args);
        await management.refreshHealth(); await new Promise(resolve => setTimeout(resolve, 30));
        const failed = card.textContent.includes('Unknown · stale') && card.textContent.includes('Retry health check') && !card.textContent.includes('synthetic-private-error');
        api = (path,...args) => path === '/api/v1/system/health' ? Promise.resolve(new Response('{"status":"ok"}')) : original(path,...args);
        await management.refreshHealth(); await new Promise(resolve => setTimeout(resolve, 30));
        const malformed = card.textContent.includes('Unknown · stale') && !card.querySelector('.pill.ok');
        const localTarget = target; target = 'synthetic-peer'; renderLive(); await new Promise(resolve => setTimeout(resolve, 30));
        const peer = !card.textContent.includes('TPM initialisation failed') && !card.querySelector('.pill.ok') && [...card.querySelectorAll('button')].find(b => b.textContent.includes('Configure NTP'))?.disabled;
        target = localTarget; renderLive();
        return {warning, failed, malformed, peer};
      } finally {
        api = original;
        // Peer restoration starts a request before returning. A zero-delay
        // timer does not guarantee its synthetic Response.json() has settled;
        // wait for the bounded in-flight request before the real refresh.
        for (let i=0; i<150 && management.getSnapshot().healthBusy; i++)
          await new Promise(resolve => setTimeout(resolve, 100));
        if (management.getSnapshot().healthBusy) throw Error('Synthetic health request did not settle');
        await management.refreshHealth();
        const recovered = management.getSnapshot();
        if (!recovered.health || recovered.healthError) throw Error('Real health observations did not recover after synthetic states');
        await new Promise(resolve => setTimeout(resolve, 30));
        if (!document.querySelector('#react-system-health').textContent.includes(recovered.health.clock.utc))
          throw Error('Recovered appliance clock is not rendered');
      }
    })()`);
    check(Object.values(result).every(Boolean), 'degraded health UI did not preserve honest boundaries: '+JSON.stringify(result));
  });
  await test('health diagnostics preserve keyboard operation, both themes and a narrow viewport', async () => {
    const out = process.env.CONSOLE_SCREENSHOTS;
    if (out) mkdirSync(out, {recursive: true});
    await page.send('Emulation.setDeviceMetricsOverride', {width:390,height:844,deviceScaleFactor:1,mobile:false});
    await page.send('Emulation.setEmulatedMedia', {features:[{name:'prefers-reduced-motion',value:'reduce'}]});
    for (const theme of ['light','dark']) {
      await page.evaluate(`(async()=>{document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)});goto('system');await new Promise(resolve=>setTimeout(resolve,100));})()`);
      const layout = await page.evaluate(`(() => {
        const card = document.querySelector('#react-system-health');
        return {width:document.documentElement.scrollWidth,viewport:innerWidth,buttons:[...card.querySelectorAll('button')].every(button=>{const box=button.getBoundingClientRect();return box.width>0&&box.left>=0&&box.right<=innerWidth;})};
      })()`);
      check(layout.width<=layout.viewport && layout.buttons, 'narrow health controls clipped: '+JSON.stringify(layout));
      if(out)writeFileSync(out+'/system-health-'+theme+'-narrow.png',Buffer.from(await page.screenshot(),'base64'));
    }
    await page.evaluate("document.querySelector('#react-system-health button').focus()");
    await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
    await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
    await sleep(200);
    check(await page.evaluate('management.getSnapshot().healthBusy || !!management.getSnapshot().health'), 'keyboard retry did not start or complete');
  });
  await test('health console has no uncaught browser errors or external requests', () => {
    const origin = new URL(process.env.CONSOLE_URL).origin;
    check(page.requests.filter(url=>/^https?:/.test(url)).every(url=>new URL(url).origin===origin), 'health request left the appliance');
    check(!page.thrown.length, page.thrown.join('\n'));
  });
} finally {page.close();}
process.exitCode=summary()?1:0;
