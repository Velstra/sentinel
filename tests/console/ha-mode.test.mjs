// Real API/no-apply console test; never changes a host network or enrolls a peer.
import { browser, signIn, test, check, summary, sleep } from './harness.mjs';
import { mkdirSync, writeFileSync } from 'node:fs';

const page = await browser({width:1440,height:1000});
try {
  await page.goto(process.env.CONSOLE_URL);
  await signIn(page, process.env.CONSOLE_TOKEN);
  await test('HA exposes both explicit election modes and the total-partition warning', async () => {
    const result = await page.evaluate(`(async()=>{
      goto('ha'); await refresh();
      const root=document.querySelector('#view-ha');
      const fields=[...document.querySelectorAll('#haform .field')];
      const mode=fields.find(field=>field.textContent.includes('Election mode')).querySelector('select');
      const label=mode.closest('label'); label.click();
      return {options:[...mode.options].map(o=>o.value),focused:document.activeElement===mode,
        warning:root.textContent.includes('losing every heartbeat path can activate both members') && root.textContent.includes('split-brain'),
        paths:root.textContent.includes('VLANs on one NIC are not independent paths'),
        fields:['Local heartbeat IP:port endpoints','Peer heartbeat IP:port endpoints','Two-node peer timeout (ms)','Two-node startup delay (ms)'].every(text=>fields.some(f=>f.textContent.includes(text)))};
    })()`);
    check(result.options.includes('witness') && result.options.includes('two-node'), 'election choices missing');
    check(result.focused && result.warning && result.paths && result.fields, 'mode controls or risk guidance missing');
  });
  await test('two-node edits stage canonical CLI commands and invalid timing leaves saved configuration untouched', async () => {
    const result = await page.evaluate(`(async()=>{
      const before=await(await api('/api/v1/config')).text();
      const box=document.querySelector('#haform');
      const values={'mode':'two-node','enabled':'false','sync-interface':'eth0',
        'node':'1','heartbeat-listen':'10.0.0.1:5441',
        'heartbeat-peer':'10.0.0.2:5441','peer-timeout-ms':'1500',
        'startup-delay-ms':'3000'};
      for(const [key,value] of Object.entries(values)){
        const field=[...box.querySelectorAll('.field')][HA.findIndex(f=>f[0]===key)];
        if(!field)throw new Error('HA field missing: '+key);
        const input=field.querySelector('.secretfield,.switch,.num,select,input');
        input.value=value;input.dispatchEvent(new Event('input'));
      }
      [...box.querySelectorAll('button')].find(b=>b.textContent.startsWith('Stage')).click();
      const commands=stagedCommands();
      await applyStaged(['commit','save']);
      const output=document.querySelector('#resultout').textContent;
      return{commands,pending:stagedCommands(),output,unchanged:before===await(await api('/api/v1/config')).text()};
    })()`);
    check(result.commands.includes('set system ha mode two-node'), 'mode bypassed canonical staging');
    check(result.commands.some(command=>command.startsWith('set system ha heartbeat-listen ')), 'listen endpoint was not staged');
    check(result.commands.some(command=>command.startsWith('set system ha heartbeat-peer ')), 'peer endpoint was not staged');
    check(result.pending.length>0 && result.unchanged && /timeout|750|1200/.test(result.output), 'invalid timing applied or lost recoverable draft: '+JSON.stringify(result));
  });
  await test('mode form stays keyboard-accessible in both themes at a narrow viewport', async () => {
    await page.evaluate(`(async()=>{staged=[];dirty.clear();renderStaged();if(document.querySelector('#result').open)document.querySelector('#resultclose').click();await refresh();goto('ha');})()`);
    await page.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:false});
    await page.send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
    for(const theme of ['light','dark']){
      await page.evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)})`);
      const controls=await page.evaluate(`(()=>{const mode=[...document.querySelectorAll('#haform .field')].find(f=>f.textContent.includes('Election mode')).querySelector('select');mode.focus();return{focused:document.activeElement===mode,width:document.documentElement.scrollWidth,viewport:innerWidth};})()`);
      check(controls.focused && controls.width<=controls.viewport, 'mode form clips or loses keyboard focus');
      await page.send('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
      await page.send('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
      await sleep(30);
      if(process.env.CONSOLE_SCREENSHOTS){
        mkdirSync(process.env.CONSOLE_SCREENSHOTS,{recursive:true});
        writeFileSync(process.env.CONSOLE_SCREENSHOTS+'/ha-mode-'+theme+'.png',Buffer.from(await page.screenshot(),'base64'));
      }
    }
    check(!page.thrown.length,page.thrown.join('\n'));
  });
} finally {page.close();}
process.exitCode=summary()?1:0;
