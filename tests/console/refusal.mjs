// Real HTTP refusals must identify the staged change without retrying writes.
// Run only through run.sh against its disposable --no-apply appliance.
import {readFileSync} from 'node:fs';
import {browser, signIn, sleep, test, check, equal} from './harness.mjs';
import {click} from './creation.mjs';

export async function refusalTests() {
const page = await browser({width: 1440, height: 1000});
try {
  await page.goto(process.env.CONSOLE_URL);
  await signIn(page, process.env.CONSOLE_TOKEN);
  for (const action of ['validate', 'applystaged']) {
    await test('HTTP 400 identifies the staged change without replay: '+action, async () => {
      const before = readFileSync(process.env.CONSOLE_CONFIG);
      const expected = [
        {label:'Valid change', cmds:['set system hostname refusal-must-not-save']},
        {label:'Invalid <img src=x onerror=alert(1)> change', cmds:[
          'set interface eth1 description refusal-must-not-save',
          'set firewall nonsense true']},
      ];
      await page.evaluate(`(() => {
        staged=[]; dirty.clear(); renderStaged();
        for (const entry of ${JSON.stringify(expected)}) stage(entry.label, entry.cmds);
        if ($('result').open) $('result').close();
        $('resultout').textContent='';
        window.refusalRequests=[];
        const original=window.fetch;
        window.restoreRefusalFetch=()=>{window.fetch=original;};
        window.fetch=async (...args)=>{
          const response=await original(...args);
          if (String(args[0]).includes('/api/v1/configure'))
            window.refusalRequests.push({status:response.status,body:args[1]?.body});
          return response;
        };
      })()`);
      try {
        await click(page, '#'+action);
        for (let i=0;i<80&&!await page.evaluate("$('result').open&&!applying");i++) await sleep(100);
        const result = await page.evaluate(`({open:$('result').open,title:$('resulttitle').textContent,
          text:$('resultout').textContent,images:$('resultout').querySelectorAll('img').length,
          staged:staged.map(e=>({label:e.label,cmds:e.cmds})),requests:window.refusalRequests})`);
        check(result.open, 'No bounded refusal feedback');
        equal(result.title, action==='validate'?'This would be refused':'Not applied', 'Refusal verdict');
        check(result.text.includes('line 3 refused:'), 'Actual API diagnostic was lost: '+result.text);
        check(result.text.includes('The refusal came from: '+expected[1].label), 'Missing staged-change attribution: '+result.text);
        equal(result.images, 0, 'The label was interpreted as HTML');
        equal(result.staged, expected, 'Refusal changed the staged batch');
        equal(result.requests.length, 1, 'A refusal replayed commands to diagnose itself');
        equal(result.requests[0].status, 400, 'Expected real HTTP 400');
        const lines=expected.flatMap(e=>e.cmds);
        if(action==='applystaged') lines.push('commit','save');
        equal(result.requests[0].body.trim(), lines.join('\n'), 'The submitted batch changed');
      } finally {
        await page.evaluate("restoreRefusalFetch(); if($('result').open)$('result').close(); staged=[];renderStaged();");
        equal(readFileSync(process.env.CONSOLE_CONFIG).equals(before), true, 'Refusal wrote persistent configuration');
      }
    });
  }
  await test('line attribution rejects guesses and follows the submitted snapshot', async () => {
    const result=await page.evaluate(`(() => {
      const batch=[{label:'First',cmds:['set system hostname example','']},
        {label:'Second',cmds:['set interface eth0 description example\\nset firewall nonsense true']}];
      const resolve=(status,message)=>refusedChange({status,message},batch);
      return {first:resolve(400,'line 1 refused: bad'),second:resolve(400,'line 4 refused: bad'),
        unnumbered:resolve(400,'a candidate-level error'),zero:resolve(400,'line 0 refused: bad'),
        beyond:resolve(400,'line 5 refused: bad'),fraction:resolve(400,'line 1.5 refused: bad'),
        overflow:resolve(400,'line 9007199254740992 refused: bad'),
        permission:resolve(403,'line 1 refused: bad'),server:resolve(500,'line 1 refused: bad'),
        transport:resolve(undefined,'line 1 refused: bad'),embedded:resolve(400,'bad value: line 1 refused: bad')};
    })()`);
    equal(result,{first:'First',second:'Second',unnumbered:null,zero:null,beyond:null,fraction:null,
      overflow:null,permission:null,server:null,transport:null,embedded:null},'False attribution or incorrect line mapping');
  });
  await test('refusal flow has no uncaught JavaScript errors', () => {
    equal(page.thrown, [], 'Uncaught browser error');
  });
} finally { page.close(); }
}
