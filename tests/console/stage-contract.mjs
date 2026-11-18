// Real form controls -> physical Stage -> strict API and installed CLI validation.
// No live apply, saved configuration write, API stub or synthesized stage call.
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { test, check, equal, sleep } from "./harness.mjs";
import { click } from "./creation.mjs";

// These are explicit behavioral cases, NOT the grammar-field exposure count.
// Each requested value must survive its actual form, Stage handler and both
// real validators. Coupled features need their own complete fixture, not a
// blanket exemption for messages containing "requires" or "not supported".
const GROUPS = [
  ["system", null, "sys-ident", "system", [
    ["hostname", ["stage-contract", "firewall-lab"]],
    ["timezone", ["UTC", "Europe/Berlin"]],
    ["keyboard", ["us", "de"]],
    ["console speed", ["9600", "115200"]],
    ["commit-revisions", ["20", "40"]],
    ["metrics enable", ["true", "false"]],
  ]],
  ["zones", null, "globalform", "firewall global", [
    ["default-action", ["accept", "drop", "reject"]],
    ["stateful", ["true", "false"]],
    ["block-icmp", ["true", "false"]],
    ["log", ["true", "false"]],
    ["source-validation", ["disable", "loose", "strict"]],
    ["fail-closed", ["true", "false"]],
  ]],
  ["zones", null, "conntrackform", "firewall global conntrack", [
    ["tcp-syn", ["45"]], ["tcp-established", ["3600"]],
    ["tcp-closing", ["15"]], ["udp", ["20"]],
    ["udp-stream", ["90"]], ["icmp", ["5"]],
  ]],
  ["routing", "bgp", "bgpglobal", "protocols bgp", [
    ["local-as", ["65002", "65010"]], ["router-id", ["192.0.2.1"]],
    ["hold-time", ["90"]], ["multipath", ["2", "4"]],
    ["ebgp-require-policy", ["true", "false"]],
  ]],
  ["routing", "ospf", "igp-ospf", "protocols ospf", [
    ["cost", ["30", "55"]], ["network-type", ["broadcast", "point-to-point"]],
    ["hello-interval", ["5"]], ["dead-interval", ["60"]],
    ["bfd", ["true", "false"]], ["graceful-restart", ["true", "false"]],
  ]],
  ["routing", "ospf3", "igp-ospf3", "protocols ospf3", [
    ["cost", ["30"]], ["instance-id", ["7"]],
    ["network-type", ["broadcast", "point-to-point"]], ["bfd", ["true", "false"]],
  ]],
  ["services", "resolution", "svc-dns", "services dns", [
    ["upstream", ["1.1.1.1,9.9.9.9"]], ["local-domain", ["lab.example"]],
    ["dnssec", ["no", "yes", "allow-downgrade"]],
    ["cache-size", ["4096"]], ["negative-ttl", ["60"]],
  ]],
  ["services", "resolution", "svc-ntp", "services ntp", [
    ["upstream", ["0.pool.ntp.org,1.pool.ntp.org"]],
    ["allow-from", ["10.0.0.0/24"]],
  ]],
  ["services", "management", "svc-ssh", "services ssh", [
    ["enable", ["true", "false"]], ["port", ["2222"]],
    ["password-authentication", ["true", "false"]],
    ["loglevel", ["INFO", "VERBOSE", "DEBUG1"]],
  ]],
  ["services", "management", "svc-web", "services web", [
    ["port", ["8443"]], ["confirm-timeout", ["60"]], ["tls", ["true"]],
  ]],
];

// A validation that went through says exactly one thing. Since the API began
// returning the candidate's advisories it may also carry them — as an array,
// and as one `warning:` line each in the same order. The two must be the same
// advisories: a line without an entry, or an entry without a line, is a reply
// this verifier does not understand, and what it does not understand it
// refuses. Any other key or line is still an unexpected state.
export function requireValidation(reply) {
  const shaped = !!reply && !Array.isArray(reply) && reply.ok === true && typeof reply.output === "string";
  const keys = shaped ? Object.keys(reply).sort().join(",") : "";
  const warnings = keys === "ok,output,warnings" ? reply.warnings : [];
  const lines = shaped ? reply.output.split("\n") : [];
  check(shaped && (keys === "ok,output" || keys === "ok,output,warnings")
    && Array.isArray(warnings)
    && warnings.every((w) => typeof w === "string" && w.trim() && !/[\u0000-\u001f\u007f-\u009f]/.test(w))
    && lines[0] === "validation ok; nothing applied"
    && lines.length === 1 + warnings.length
    && warnings.every((w, i) => lines[i + 1] === "warning: " + w),
    "Real validation refused or returned an unexpected state: " + JSON.stringify(reply));
}

// A rejected JavaScript promise alone is not evidence of input validation: a
// transport failure, unauthorised request or server error also rejects. Both
// the real HTTP response and the helper's specific diagnostic must agree.
export function requireRefusal(reply, diagnostic) {
  check(!!reply && !Array.isArray(reply)
    && Object.keys(reply).sort().join(",") === "message,rejected,status"
    && reply.rejected === true && reply.status === 400
    && typeof diagnostic === "string" && diagnostic.length > 0
    && reply.message === diagnostic,
    "Expected a specific HTTP 400 refusal, not another failure: " + JSON.stringify(reply));
}

export async function refusedConfiguration(page, lines, diagnostic) {
  const config = process.env.CONSOLE_CONFIG;
  check(config, "A real private configuration is required for refusal verification");
  const before = readFileSync(config);
  const responses = page.responses.length;
  try {
    const refusal = await page.evaluate(`(async () => {
      try { await configure(${JSON.stringify(lines)}); return {rejected:false}; }
      catch (error) { return {rejected:true,status:error.status,message:error.message}; }
    })()`);
    requireRefusal(refusal, diagnostic);
    equal(page.responses.slice(responses)
      .filter(row => row.url.endsWith('/api/v1/configure')).map(row => row.status),
      [400], "The actual configuration request was not exactly one HTTP 400");
    return refusal.message;
  } finally {
    check(readFileSync(config).equals(before), "A refused configuration changed the saved document");
  }
}

export async function stageContractTests(page) {
  const config = process.env.CONSOLE_CONFIG;
  const binary = process.env.CONSOLE_BINARY;
  check(config && binary, "The stage contract requires the actual runner config and binary");
  const before = readFileSync(config);
  const rows = [];
  const negatives = [];
  const commands = new Set();
  let plannedMutations = 0;
  await test("strict stage verifier rejects refusals, incomplete replies and applied results", () => {
    for (const reply of [null, {}, {ok:false,output:"error: requires a prerequisite"},
      {ok:false,output:"error: not supported"}, {ok:true,output:"error: invalid command"},
      {ok:1,output:"validation ok; nothing applied"},
      {ok:true,output:"validation ok; nothing applied",pending:false},
      {ok:true,output:"validation ok; nothing applied",saved:true},
      {ok:true,output:"validation ok; nothing applied",pending:{id:"unexpected"}},
      // Advisories are admitted only as the same list said twice.
      {ok:true,output:"validation ok; nothing applied\nwarning: a rule is narrower than it reads"},
      {ok:true,output:"validation ok; nothing applied\nwarning: a rule is narrower than it reads",warnings:[]},
      {ok:true,output:"validation ok; nothing applied",warnings:["a rule is narrower than it reads"]},
      {ok:true,output:"validation ok; nothing applied\nwarning: one",warnings:["another"]},
      {ok:true,output:"validation ok; nothing applied\nwarning: one\nerror: refused",warnings:["one"]},
      {ok:true,output:"validation ok; nothing applied\nwarning: one",warnings:"one"},
      {ok:true,output:"validation ok; nothing applied\nwarning: ",warnings:[""]},
      {ok:true,output:"validation ok; nothing applied\nwarning: one\nwarning: two",warnings:["two","one"]},
      {ok:true,output:"validation ok; nothing applied\nwarning: one\ntwo",warnings:["one\ntwo"]},
      ...[...Array.from({length:32},(_,i)=>String.fromCharCode(i)),
        ...Array.from({length:33},(_,i)=>String.fromCharCode(127+i))].map(control=>({
        ok:true,output:"validation ok; nothing applied\nwarning: raw"+control+"control",
        warnings:["raw"+control+"control"],
      })),
      {ok:true,output:"validation ok; nothing applied",warnings:[],pending:false}]) {
      let refused = false;
      try { requireValidation(reply); } catch { refused = true; }
      check(refused, "A false-green validator reply was accepted: " + JSON.stringify(reply));
    }
    // And the two shapes a real validation has: with nothing to advise, and
    // with advisories that agree with their lines.
    for (const reply of [{ok:true,output:"validation ok; nothing applied"},
      {ok:true,output:"validation ok; nothing applied",warnings:[]},
      {ok:true,output:"validation ok; nothing applied\nwarning: one\nwarning: two",warnings:["one","two"]}]) {
      requireValidation(reply);
    }
  });
  await test("strict refusal verifier rejects unrelated failures and false refusals", () => {
    const diagnostic = 'line 1 refused: services ssh port "65536": not a 1-65535 port';
    const valid = {rejected:true,status:400,message:diagnostic};
    requireRefusal(valid,diagnostic);
    for (const reply of [null,{}, {...valid,rejected:false}, {...valid,status:undefined},
      ...[200,401,403,409,500,503].map(status=>({...valid,status})),
      {...valid,message:""}, {...valid,message:"the appliance could not be reached"},
      {...valid,message:"a different input was refused"}, {...valid,output:diagnostic}]) {
      let rejected = false;
      try { requireRefusal(reply,diagnostic); } catch { rejected = true; }
      check(rejected, "An unrelated failure counted as input refusal: "+JSON.stringify(reply));
    }
  });

  // Observe the real field builders only to identify their live DOM widgets.
  // Original builders, validation, stage(), requests and responses are intact.
  await page.evaluate(`(() => {
    window.__stageMasks = {};
    let active = null;
    const grid = fieldGrid, panelBuilder = settingsPanel;
    window.__stageRestore = () => {fieldGrid=grid;settingsPanel=panelBuilder;delete window.__stageMasks;delete window.__stageRestore;};
    fieldGrid = (...args) => {
      const result = grid(...args);
      if (active) window.__stageMasks[active.id] = {...active, fields:args[0], widgets:result.widgets};
      return result;
    };
    settingsPanel = (...args) => {
      active = {id:args[0],path:args[3]};
      try { return panelBuilder(...args); } finally { active = null; }
    };
  })()`);

  for (const [viewName, tab, box, path, fields] of GROUPS) {
    await page.evaluate(`(async () => {
      staged = []; dirty.clear(); renderStaged();
      view = ${JSON.stringify(viewName)}; panel = null;
      ${tab ? `tabs[${JSON.stringify(viewName)}] = ${JSON.stringify(tab)};` : ""}
      await refresh();
    })()`);
    await sleep(50);
    const values = await page.evaluate(`(() => {
      const m = window.__stageMasks[${JSON.stringify(box)}];
      if (!m || m.path !== ${JSON.stringify(path)}) throw Error('Actual form/path is absent: '+${JSON.stringify(box)});
      return m.widgets.map(w => w ? String(w.value || '') : null);
    })()`);
    for (const [key, requested] of fields) for (const value of requested) {
      const identity = `${path} ${key} = ${value}`;
      await test("real Stage + API + CLI: " + identity, async () => {
        const control = await page.evaluate(`(() => {
          staged=[]; dirty.clear(); renderStaged();
          const m=window.__stageMasks[${JSON.stringify(box)}], initial=${JSON.stringify(values)};
          m.widgets.forEach((w,i)=>{if(w)w.value=initial[i]||'';});
          document.querySelectorAll('[id="qa-contract-widget"],[id="qa-contract-more"]').forEach(n=>n.removeAttribute('id'));
          const index=m.fields.findIndex(f=>f[0]===${JSON.stringify(key)});
          if(index<0||!m.widgets[index])throw Error('Actual field missing');
          const w=m.widgets[index]; w.id='qa-contract-widget';
          return {switch:w.classList.contains('switch'),visible:!!w.getClientRects().length,
            before:String(w.value||''),more:!![...document.getElementById(${JSON.stringify(box)}).querySelectorAll('button')].find(b=>b.textContent==='More settings')};
        })()`);
        if(control.before!==value)plannedMutations++;
        if (!control.visible && control.more) {
          await page.evaluate(`(()=>{const b=[...document.getElementById(${JSON.stringify(box)}).querySelectorAll('button')].find(b=>b.textContent==='More settings');b.id='qa-contract-more';})()`);
          await click(page, "#qa-contract-more");
        }
        if (control.switch) {
          for (let count=0;count<2;count++) {
            if (await page.evaluate("document.getElementById('qa-contract-widget').value") === value) break;
            await click(page, "#qa-contract-widget [role=switch]");
          }
        } else {
          await page.evaluate(`(()=>{const w=document.getElementById('qa-contract-widget');
            if(!w.getClientRects().length)throw Error('Requested field is hidden');
            w.value=${JSON.stringify(value)};
            w.dispatchEvent(new Event('input',{bubbles:true}));
            w.dispatchEvent(new Event('change',{bubbles:true}));})()`);
        }
        await click(page, "#" + box + " .maskfoot > button.primary");
        const staged = await page.evaluate("stagedCommands()");
        if(control.before===value){
          equal(staged,[],"An unchanged value unexpectedly staged work");
          check(await page.evaluate("document.getElementById('banner').textContent.includes('Nothing changed')"),
            "Unchanged-value Stage gave no feedback");
          rows.push({path,key,value,kind:"unchanged-value-feedback",commands:[],api_validated:false,cli_validated:false});
          return;
        }
        const expected = `set ${path} ${key} ${value}`;
        check(staged.includes(expected), "Actual Stage did not produce the requested command: " + JSON.stringify(staged));
        const reply = await page.evaluate(`configure(${JSON.stringify(staged)})`);
        requireValidation(reply);
        const cli = spawnSync(binary, ["configure", "--config", config, "--no-apply"], {
          input: staged.join("\n") + "\ncommit\n", encoding:"utf8", timeout:15000,
          env:{...process.env,NO_COLOR:"1"},
        });
        const output=(cli.stdout||"")+(cli.stderr||"");
        check(!cli.error && cli.status===0 && output.includes("commit ok (validated)")
          && !/\berror:/i.test(output), "Installed CLI refused: " + output.slice(-1200));
        equal(readFileSync(config).toString(), before.toString(), "Validation modified the saved appliance document");
        staged.forEach(command=>commands.add(command));
        rows.push({path,key,value,kind:"validated-change",commands:staged,api_validated:true,cli_validated:true});
      });
    }
  }
  for(const [viewName,tab,box,key,value,path] of [
    ["services","management","svc-ssh","port","65536","services ssh"],
    ["system",null,"sys-update","url","javascript:alert(1)","update"],
  ])await test("invalid actual form/API/CLI value is refused: "+path+" "+key,async()=>{
    await page.evaluate(`(async()=>{
      staged=[];dirty.clear();renderStaged();view=${JSON.stringify(viewName)};panel=null;
      ${tab?`tabs[${JSON.stringify(viewName)}]=${JSON.stringify(tab)};`:""}
      await refresh();
      const m=window.__stageMasks[${JSON.stringify(box)}],i=m.fields.findIndex(f=>f[0]===${JSON.stringify(key)});
      if(i<0||!m.widgets[i])throw Error('Actual negative-case field absent');
      const w=m.widgets[i];w.value=${JSON.stringify(value)};
      w.dispatchEvent(new Event('input',{bubbles:true}));w.dispatchEvent(new Event('change',{bubbles:true}));
    })()`);
    await click(page,"#"+box+" .maskfoot > button.primary");
    equal(await page.evaluate("stagedCommands()"),[],"Invalid form value staged commands");
    check(await page.evaluate(`!!document.getElementById(${JSON.stringify(box)}).querySelector('[aria-invalid="true"]')`),
      "Invalid actual field has no associated inline refusal");
    const command=`set ${path} ${key} ${value}`;
    const diagnostic=path==='services ssh'
      ? 'line 1 refused: services ssh port "65536": not a 1-65535 port'
      : 'update: url "javascript:alert(1)" must be an https:// or file:// URL';
    await refusedConfiguration(page,[command],diagnostic);
    const cli=spawnSync(binary,["configure","--config",config,"--no-apply"],{
      input:command+"\ncommit\n",encoding:"utf8",timeout:15000,env:{...process.env,NO_COLOR:"1"},
    });
    const output=(cli.stdout||"")+(cli.stderr||"");
    // The API adds batch line attribution; the installed CLI prints the same
    // underlying diagnostic with its own `error:` prefix and failure exit.
    const cliDiagnostic=diagnostic.replace(/^line 1 refused: /,'');
    check(!cli.error&&cli.status!==null&&cli.status!==0&&output.includes('error: '+cliDiagnostic),"CLI did not reject the specific invalid input: "+output);
    equal(readFileSync(config).toString(),before.toString(),"Rejected value modified the saved config");
    negatives.push({path,key,value,ui_refused:true,api_refused:true,cli_refused:true});
  });
  await test("real stage inventory cannot pass on repeated global controls", () => {
    const expected = GROUPS.reduce((sum,g)=>sum+g[4].reduce((n,f)=>n+f[1].length,0),0);
    equal(rows.length,expected,"Some actual form/value cases failed or disappeared");
    equal(rows.filter(row=>row.kind==="validated-change").length,plannedMutations,"A planned changed value was not validated");
    check(plannedMutations>=55 && commands.size>=plannedMutations,
      "Distinct validated command inventory unexpectedly shrank: "+commands.size+" / "+plannedMutations);
    check(new Set(rows.map(row=>row.path)).size===GROUPS.length,"A planned form/path was never validated");
    equal(negatives.length,2,"An invalid-input path was not actively verified");
    check(!page.thrown.length,"Real Stage interactions threw browser exceptions: "+page.thrown.join("\n"));
    equal(readFileSync(config).toString(),before.toString(),"Saved configuration drifted during validation");
  });
  await page.evaluate("window.__stageRestore()");
  let cleanupRefresh = false;
  await test("negative-case cleanup refreshes the real form without bypassing the draft guard", async () => {
    check(await page.evaluate('dirty.has("sys-update") && stagedCommands().length === 0'),
      "The actual invalid URL did not leave the expected unstaged draft");
    await page.evaluate('window.__stageOldUrl = document.querySelector(\'#sys-update [aria-label="Default channel URL"]\')');
    await click(page, "#refresh");
    for (let attempt = 0; attempt < 100; attempt++) {
      cleanupRefresh = await page.evaluate('!!document.querySelector(\'#sys-update [aria-label="Default channel URL"]\') && document.querySelector(\'#sys-update [aria-label="Default channel URL"]\') !== window.__stageOldUrl && dirty.size === 0 && stagedCommands().length === 0');
      if (cleanupRefresh) break;
      await sleep(50);
    }
    await page.evaluate('delete window.__stageOldUrl');
    check(cleanupRefresh, "The real Refresh did not discard the temporary invalid form before navigation");
    equal(readFileSync(config).toString(), before.toString(), "Cleanup changed the saved configuration");
  });
  console.log(`  actual Stage contract: ${rows.length} form/value cases, ${commands.size} distinct validated commands`);
  const folder=process.env.CONSOLE_SCREENSHOTS;
  if(folder){mkdirSync(folder,{recursive:true});writeFileSync(join(folder,"stage-contract.json"),JSON.stringify({
    scope:"explicit form/value staging and validation only; not every CLI field or native behavior",
    planned:GROUPS.map(([view,tab,box,path,fields])=>({view,tab,box,path,fields})),
    rows,negatives,distinct_commands:commands.size,cleanup_refresh:cleanupRefresh,network_apply:false,saved_document_unchanged:readFileSync(config).equals(before),
  },null,2));}
}
