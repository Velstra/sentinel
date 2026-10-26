import { test, check, equal, sleep } from "./harness.mjs";

export async function managementTests(page) {
  await test("the live inspector filters named IPv6 rules and bounds its history view", async () => {
    const state = await page.evaluate(`(async () => {
      if ($("result").open) $("result").close();
      telemetryAbort.abort();
      view = "rules"; panel = null; await refresh();
      liveFrame = { events: Array.from({length:120}, (_,i) => ({id:i+1,src:"2001:db8::1",dst:"2001:db8::2",src_port:2345,dst_port:443,protocol:6,interface:2,interface_name:"wan0",rule:i%2?"web-in":"default",rule_id:7,action:i%2?"drop":"accept"})), rule_counters:[{rule:"web-in",packets:60}], errors:{} };
      liveStatus = "Live telemetry connected."; renderLive();
      const bounded = $("live-flows").rows.length;
      $("flow-search").value="web-in"; $("flow-search").dispatchEvent(new Event("input"));
      $("flow-action").value="drop"; $("flow-action").dispatchEvent(new Event("change"));
      const filtered = $("live-flows").textContent;
      $("flow-next").click();
      const range = $("flow-range").textContent;
      $("flow-clear").click();
      const clearFocus = document.activeElement.id;
      $("flow-search").value="no-such-rule"; $("flow-search").dispatchEvent(new Event("input"));
      const empty = $("flow-state").textContent;
      $("flow-search").value=""; $("flow-action").value=""; flowPage=0;
      startManagement();
      return {bounded,filtered,range,clearFocus,empty};
    })()`);
    check(state.bounded <= 51, "the live event table is unbounded");
    check(state.filtered.includes("web-in") && state.filtered.includes("[2001:db8::1]:2345"), "rule or IPv6 endpoint missing");
    equal(state.range,"51–60 of 60","filter pagination lost matching events");
    equal(state.clearFocus,"flow-search","clearing did not restore search focus");
    check(state.empty.includes("No events match"),"no-results state missing");
  });

  await test("TOML validation retains rejected drafts and applies only after an explicit confirmation", async () => {
    const result = await page.evaluate(`(async () => {
      if ($("result").open) $("result").close();
      view="config"; panel=null; await refresh(); await loadToml();
      const baseline=tomlBaseline;
      $("toml-candidate").value="[system\\nhostname=broken";
      $("toml-candidate").dispatchEvent(new Event("input"));
      await submitToml(true);
      const invalid=$("toml-candidate").getAttribute("aria-invalid");
      const retained=$("toml-candidate").value;
      $("toml-candidate").value=baseline.replace(/hostname = "[^"]+"/, 'hostname = "management-confirmed"');
      $("toml-candidate").dispatchEvent(new Event("input"));
      await submitToml(true);
      const diff=$("toml-diff").textContent;
      const draft=$("toml-candidate").value;
      await configure(["set system hostname concurrent-revision","commit","save"]);
      await submitToml(true);
      const conflict=$("toml-feedback").textContent;
      await loadToml(true);
      const preserved=$("toml-candidate").value===draft;
      await submitToml(false);
      const pending=!!pendingTransaction;
      const visible=!$("confirmation").classList.contains("hidden");
      const deadline=pendingTransaction?.remaining_seconds;
      const realApi=api; let release, calls=0;
      const hold=new Promise(resolve => release=resolve);
      api=async(...args)=>{if(args[0]==="/api/v1/config/confirm"){calls++;await hold;}return realApi(...args);};
      let disabled;
      try {
        $("confirm-change").click(); await new Promise(resolve=>setTimeout(resolve,20));
        drawConfirmation(); gateWrites();
        disabled=$("confirm-change").disabled;
        $("confirm-change").click(); release();
        for(let i=0;i<100&&(pendingTransaction || $("confirm-change").classList.contains("busy"));i++) await new Promise(resolve=>setTimeout(resolve,30));
      } finally {release();api=realApi;}
      const stored=(await (await api("/api/v1/config")).json()).system.hostname;
      const confirmed=!pendingTransaction;
      await configure(["set system hostname " + JSON.stringify((baseline.match(/hostname = "([^"]+)"/)||[])[1]), "commit", "save"]);
      return {invalid,retained,diff,pending,visible,deadline,stored,confirmed,conflict,preserved,disabled,calls};
    })()`);
    equal(result.invalid,"true","invalid TOML was not associated with the editor");
    equal(result.retained,"[system\nhostname=broken","the invalid draft was lost");
    check(result.diff.includes("management-confirmed"),"validation did not provide a real diff");
    check(result.conflict.includes("configuration changed") && result.preserved,"stale edits were overwritten or their draft was lost");
    check(result.pending && result.visible && result.deadline <= 60,"default confirmation protection missing");
    equal(result.stored,"management-confirmed","the proposed TOML did not reach appliance.toml");
    check(result.confirmed,"explicit confirmation did not complete");
    check(result.disabled && result.calls === 1,"polling re-enabled a pending confirmation or submitted it twice");
  });

  await test("reverting a provisional form batch restores its staged commands", async () => {
    const result = await page.evaluate(`(async()=>{
      if($("result").open) $("result").close();
      clearToml();view="config";panel=null;staged=[];
      const baseline=(await(await api("/api/v1/config")).json()).system.hostname;
      stage("Test hostname change",["set system hostname form-reverted"]);
      const original=JSON.stringify(staged);
      // The workstation harness has live networking disabled. Supply the live
      // configure response through the real durable document endpoint instead.
      const realConfigure=configure;
      configure=async()=>{
        const doc=await(await api("/api/v1/config/document")).json();
        const response=await api("/api/v1/config/document",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({toml:doc.toml.replace(/hostname = "[^"]+"/,'hostname = "form-reverted"'),expected_revision:doc.revision})});
        const reply={ok:true,output:"",...await response.json()};setTransaction(reply.pending);return reply;
      };
      try {await applyStagedNow(["commit","save"]);}finally{configure=realConfigure;}
      const applying=!!pendingTransaction && staged.length===0;
      await finishTransaction("revert");
      const restored=JSON.stringify(staged)===original;
      const outcome=$("resulttitle").textContent;
      const hostname=(await(await api("/api/v1/config")).json()).system.hostname;
      staged=[];pendingBatch=null;renderStaged();if($("result").open)$("result").close();
      return {applying,restored,outcome,hostname,baseline};
    })()`);
    check(result.applying && result.restored,"rollback lost the staged form commands: "+JSON.stringify(result));
    equal(result.hostname,result.baseline,"reverted form batch left the provisional configuration");
    equal(result.outcome,"Configuration restored","result dialog did not reflect completed recovery");
  });

  await test("an unconfirmed TOML revision automatically returns to its saved baseline", async () => {
    const result = await page.evaluate(`(async () => {
      await configure(["set services web confirm-timeout 2","commit","save"]);
      clearToml(); await loadToml();
      const baseline=tomlBaseline;
      $("toml-candidate").value=baseline.replace(/hostname = "[^"]+"/, 'hostname = "must-roll-back"');
      $("toml-candidate").dispatchEvent(new Event("input"));
      await submitToml(false);
      const id=pendingTransaction?.id;
      await new Promise((resolve) => setTimeout(resolve,4200));
      await refreshTransaction();
      const stored=(await (await api("/api/v1/config")).json()).system.hostname;
      let rejected=false;
      try { await api("/api/v1/config/confirm",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({id})}); } catch (e) {rejected=true;}
      const draftRetained=dirty.has("toml-editor") && $("toml-candidate").value.includes("must-roll-back");
      clearToml();
      await configure(["delete services web confirm-timeout","commit","save"]);
      return {stored,rejected,draftRetained,pending:!!pendingTransaction};
    })()`);
    check(result.stored !== "must-roll-back","expired revision remained persisted");
    check(result.rejected && !result.pending,"late confirmation resurrected an expired revision");
    check(result.draftRetained,"rollback discarded the proposed TOML draft");
  });
}
