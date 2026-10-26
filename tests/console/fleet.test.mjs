import { test, check, equal } from "./harness.mjs";

export async function fleetTests(page) {
  await test("fleet enrollment stages every field, protects credentials and disconnects declaratively", async () => {
    const result = await page.evaluate(`(async()=>{
      if($("result").open)$("result").close();
      staged=[];dirty.clear();view="system";panel=null;await refresh();
      const input=(label)=>[...$("sys-fleet").querySelectorAll(".field")].find(n=>n.firstElementChild?.textContent.trim()===label)?.querySelector("input");
      const values={"Controller HTTPS URL":"https://fleet.example","Enrolled node ID":"console-edge","Enrollment token":"console-fleet-enrollment-credential","Controller CA file":"/etc/fleet/ca.pem","Client certificate file":"/etc/fleet/client.pem","Private client key file":"/etc/fleet/client.key","Ed25519 signing public key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","Check-in interval (seconds)":"5"};
      for(const[label,value]of Object.entries(values)){const n=input(label);if(!n)throw Error("missing field "+label);n.value=value;n.dispatchEvent(new Event("input",{bubbles:true}));}
      const masked=input("Enrollment token").type==="password";
      [...$("sys-fleet").querySelectorAll("button")].find(b=>b.textContent.startsWith("Stage")).click();
      const commands=stagedCommands();
      await applyStagedNow(["commit","save"]);if($("result").open)$("result").close();
      const saved=(await(await api("/api/v1/config/document")).json()).toml;
      const publicRead=(await(await api("/api/v1/config")).json()).fleet;
      input("Check-in interval (seconds)").value="9";input("Check-in interval (seconds)").dispatchEvent(new Event("input",{bubbles:true}));
      [...$("sys-fleet").querySelectorAll("button")].find(b=>b.textContent.startsWith("Stage")).click();
      const retentionCommands=stagedCommands();await applyStagedNow(["commit","save"]);if($("result").open)$("result").close();
      const retained=(await(await api("/api/v1/config/document")).json()).toml;
      input("Controller HTTPS URL").value="http://unsafe.example";input("Controller HTTPS URL").dispatchEvent(new Event("input",{bubbles:true}));
      [...$("sys-fleet").querySelectorAll("button")].find(b=>b.textContent.startsWith("Stage")).click();
      await applyStagedNow(["commit","save"]);
      const refused=staged.length>0&&$("resulttitle").textContent==="Not applied";
      const still=(await(await api("/api/v1/config")).json()).fleet["controller-url"];
      if($("result").open)$("result").close();staged=[];dirty.clear();await refresh();
      $("disconnect-fleet").click();const disconnect=stagedCommands();await applyStagedNow(["commit","save"]);
      const removed=!(await(await api("/api/v1/config")).json()).fleet;
      if($("result").open)$("result").close();
      return {masked,commands,saved,publicRead,retentionCommands,retained,refused,still,disconnect,removed};
    })()`);
    check(result.masked,"fleet token is visible by default");
    equal(result.commands.length,8,"fleet fields did not stage through the shared form");
    check(result.saved.includes('node-id = "console-edge"'),"fleet identity was not persisted");
    equal(result.publicRead["enrollment-token"],"__redacted__","read API exposed the fleet credential");
    check(result.retained.includes("console-fleet-enrollment-credential") && result.retentionCommands.every(c=>!c.includes("enrollment-token")),"editing another field replaced the protected credential");
    check(result.refused && result.still==="https://fleet.example","unsafe enrollment replaced working state or lost the staged correction");
    equal(result.disconnect,["delete fleet"],"disconnect bypassed the declarative editor");
    check(result.removed,"disconnect did not remove fleet desired state");
  });
}
