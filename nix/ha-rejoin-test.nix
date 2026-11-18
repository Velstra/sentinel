# Continuous witness-mode rejoin admission, not a final-state-only HA check.
# No synthetic authority, map writes, lease changes or favorable-port selection.
{ pkgs, self }:
let
  lib = pkgs.lib;
  probe = ./ha-rejoin-probe.py;
  reader = ./nat-capacity-pressure-probe.py;
  command = "${pkgs.python3}/bin/python3 -B ${probe}";
  # Transient services do not inherit a login shell's system-package PATH.
  # These are the complete external dependencies of the read-only collector.
  observerPath = lib.makeBinPath [ pkgs.bpftools pkgs.iproute2 pkgs.systemd ];
  secret = "ha-vm-test-credential-at-least-32-bytes";
  cluster = "vm-cluster-0123456789";
  appliance = node: (pkgs.formats.toml {}).generate "ha-rejoin-${toString node}.toml" {
    system = {
      hostname = "rejoin-${toString node}";
      config-sync = { inherit secret; peer = [ "10.3.0.${toString (3 - node)}:8080" ]; };
      conntrack-sync = { listen = "10.3.0.${toString node}:5429"; peer = [ "10.3.0.${toString (3 - node)}:5429" ]; };
      ha = {
        enabled = true; inherit cluster node;
        mode = "witness"; witness = "10.3.0.3:5440"; sync-interface = "eth3";
        priority = if node == 1 then 200 else 100;
        preempt = false;
      };
    };
    services.web.listen-address = "10.3.0.${toString node}";
    interface = [
      { name = "eth1"; zone = "wan"; address = "10.1.0.${toString node}/24"; }
      { name = "eth2"; zone = "lan"; address = "10.2.0.${toString node}/24"; }
      { name = "eth3"; zone = "control"; address = "10.3.0.${toString node}/24"; }
    ];
    firewall = { default_action = "drop"; stateful = true; fail_closed = true; };
    zone = { wan.default_action = "drop"; lan.default_action = "drop"; control.default_action = "accept"; };
    rule = [{ name = "nonce-echo"; from = "lan"; proto = "tcp"; port = 8443; action = "accept"; }];
    nat.source = [{ name = "vip-snat"; zone = "wan"; to = "10.1.0.100"; }];
    protocols.vrrp = map (vip: {
      inherit (vip) name vrid;
      interface = "eth3"; address-interface = vip.interface;
      virtual-address = [ vip.address ]; prefix-length = 24;
      priority = if node == 1 then 200 else 100;
      preempt = false;
    }) [
      { name = "wan"; interface = "eth1"; vrid = 20; address = "10.1.0.100"; }
      { name = "lan"; interface = "eth2"; vrid = 21; address = "10.2.0.100"; }
    ];
  };
  scratch = {
    systemd.tmpfiles.rules = [
      "d /run/qa-ha-rejoin 0700 root root -"
      "f /run/qa-ha-rejoin-disposable 0600 root root - disposable-only"
      "f /run/qa-ha-rejoin/phase 0600 root root - baseline"
    ];
    environment.systemPackages = [ pkgs.python3 pkgs.tcpdump pkgs.bpftools pkgs.iproute2 ];
  };
  member = node: { lib, ... }: {
    imports = [ self.nixosModules.sentinel scratch ];
    virtualisation = { vlans = [ 1 2 3 ]; memorySize = 2048; cores = 2; };
    networking.firewall.enable = lib.mkForce false;
    services.velstra.interface = lib.mkForce "eth1";
    services.velstra.appliance = lib.mkForce (appliance node);
    systemd.services.wren.environment.RUST_LOG = "wren::vrrp=debug";
    systemd.services.velstra.environment.RUST_LOG = "velstra::ha=debug,velstra::conntrack_sync=debug";
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-ha-nonpreempting-rejoin-admission";
  globalTimeout = 600;
  nodes = {
    primary = member 1;
    secondary = member 2;
    witness = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      virtualisation = { vlans = [ 3 ]; memorySize = 1536; };
      networking.firewall.enable = lib.mkForce false;
      services.velstra.interface = lib.mkForce "eth1";
      services.velstra.appliance = lib.mkForce ((pkgs.formats.toml {}).generate "rejoin-witness.toml" {
        system = {
          hostname = "rejoin-witness";
          ha-witness = {
            listen = "10.3.0.3:5440";
            key = "c0b85d40a476e906218005259304678cbafc193059b70394a58334edfb13882b";
            inherit cluster;
            member = [ "10.3.0.1" "10.3.0.2" ];
          };
        };
        interface = [{ name = "eth1"; address = "10.3.0.3/24"; zone = "control"; }];
        firewall.default_action = "accept";
      });
    };
    client = {
      imports = [ scratch ];
      virtualisation = { vlans = [ 2 ]; memorySize = 512; };
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.2.0.10"; prefixLength = 24; }];
      networking.interfaces.eth1.ipv4.routes = [{ address = "10.1.0.0"; prefixLength = 24; via = "10.2.0.100"; }];
    };
    server = {
      imports = [ scratch ];
      virtualisation = { vlans = [ 1 ]; memorySize = 512; };
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.10"; prefixLength = 24; }];
      # Reply to the VIP is on-link; this route makes a missing SNAT observable,
      # not an accidental blackhole that could falsely prove fencing.
      networking.interfaces.eth1.ipv4.routes = [{ address = "10.2.0.0"; prefixLength = 24; via = "10.1.0.100"; }];
      systemd.services.qa-rejoin-echo = {
        wantedBy = [ "multi-user.target" ]; after = [ "network.target" ];
        serviceConfig.ExecStart = "${command} serve";
      };
    };
  };
  testScript = ''
    import hashlib, importlib.util, json, os, secrets, shlex, time
    from pathlib import Path
    from typing import Any

    spec = importlib.util.spec_from_file_location("rejoin", "${probe}")
    assert spec is not None and spec.loader is not None
    diagnostic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostic)
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = {"version":1,"passed":False,"variant":"clean-outbox witness/nonpreempting rejoin",
               "probe_sha256":hashlib.sha256(Path("${probe}").read_bytes()).hexdigest(),
               "reader_sha256":hashlib.sha256(Path("${reader}").read_bytes()).hexdigest(),
               "sentinel":"${self.packages.x86_64-linux.sentinel}",
               "fabric":"${self.packages.x86_64-linux.velstra}",
               "object":"${self.packages.x86_64-linux.velstra-ebpf}","events":[]}
    alive = {"primary":True,"secondary":True,"client":True,"server":True,"witness":True}

    def py(source):
        return "${pkgs.python3}/bin/python3 -c " + shlex.quote(source)

    def preserve(name, value):
        (artifacts/name).write_text(json.dumps(value,separators=(",",":"))+"\n")

    def fetch(machine, name):
        path = "/run/qa-ha-rejoin/" + name
        expected = machine.succeed("sha256sum " + shlex.quote(path)).split()[0]
        target = "guest-files/" + machine.name
        machine.copy_from_machine(path,target)
        local = artifacts/target/name
        assert hashlib.sha256(local.read_bytes()).hexdigest() == expected, (machine.name,name,"artifact transport mismatch")
        return local

    def set_phase(name):
        for node in (client,server,secondary):
            node.succeed("${command} phase --value " + shlex.quote(name))
        receipt["events"].append({"phase":name,"driver_monotonic_ns":time.monotonic_ns()})

    def clean_outbox(node):
        node.succeed("test ! -e /var/lib/sentinel/configsync/pending.json")

    def role(node):
        return json.loads(node.succeed("cat /run/velstra/ha/role.json"))

    def wait_owner(node, number, budget=30):
        # One guest process samples at20ms rather than using the driver's
        # one-second retry interval for a subsecond product transition.
        source = "import json,time\nfrom pathlib import Path\nuntil=time.monotonic()+"+str(budget)+"\n"
        source += "while time.monotonic()<until:\n"
        source += " try:\n  r=json.loads(Path('/run/velstra/ha/role.json').read_text()); a=json.loads(Path('/run/velstra/ha/agent.json').read_text()); now=time.clock_gettime_ns(time.CLOCK_BOOTTIME)\n"
        source += "  ready=r['authority']['owner']=="+str(number)+" and r['deadline_ns']>now and r['vips_ready'] and a['forwarding_term']==r['authority']['term']>0\n"
        source += " except (OSError,ValueError,KeyError):\n  ready=False\n"
        source += " if ready:\n  Path('/run/qa-ha-rejoin/owner-observed.json').write_text(json.dumps({'boottime_ns':now,'authority':r['authority']})); break\n"
        source += " time.sleep(.02)\nelse:\n raise RuntimeError('no forwarding owner within bounded observation')\n"
        node.succeed(py(source))

    def wait_backup(node):
        node.wait_until_succeeds(py('import json,time; r=json.load(open("/run/velstra/ha/role.json")); a=json.load(open("/run/velstra/ha/agent.json")); assert r["authority"]["owner"]==2 and r["deadline_ns"]==0 and a["forwarding_term"]==0 and a["ready_term"]==r["authority"]["term"]>0 and a["eligible"] and a["policy"]==r["authority"]["policy"] and time.clock_gettime_ns(time.CLOCK_BOOTTIME)-a["updated_ns"]<200_000_000'),timeout=40)

    def capture(node, label, interface):
        node.succeed("systemd-run --unit=qa-rejoin-pcap-"+label+" ${pkgs.tcpdump}/bin/tcpdump -p -U -C 4 -W 4 -w /run/qa-ha-rejoin/"+label+".pcap -i "+interface+" 'tcp port 8443 or arp'")
        node.wait_until_succeeds("journalctl -u qa-rejoin-pcap-"+label+" --no-pager | grep -q 'listening on'",timeout=5)

    try:
        witness.start()
        witness.wait_for_unit("sentinel-witness.service")
        # Establish the intended initial incumbent before another eligible
        # member starts. Priority is not an implicit preemption request.
        primary.start()
        for unit in ("multi-user.target","sentinel-boot.service","velstra.service","wren.service"):
            primary.wait_for_unit(unit)
        wait_owner(primary,1)
        for node in (secondary,client,server):
            node.start()
        for node in (primary,secondary,client,server):
            node.wait_for_unit("multi-user.target")
        server.wait_for_unit("qa-rejoin-echo.service")
        for node in (primary,secondary):
            for unit in ("sentinel-boot.service","velstra.service","wren.service","sentinel-api.service"):
                node.wait_for_unit(unit)
            node.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
            clean_outbox(node)
            node.succeed(py('import tomllib; a=tomllib.load(open("/var/lib/sentinel/appliance.toml","rb")); assert a["system"]["ha"]["mode"]=="witness" and not a["system"]["ha"]["preempt"]; assert all(not v["preempt"] for v in a["protocols"]["vrrp"]); assert a["firewall"]["stateful"] and a["firewall"]["fail_closed"] and a["firewall"]["default_action"]=="drop"; assert a["zone"]["lan"]["default_action"]==a["zone"]["wan"]["default_action"]=="drop"; assert a["nat"]["source"][0]["to"]=="10.1.0.100"'))
        wait_owner(primary,1)
        secondary.wait_until_succeeds("sentinel show ha | grep -qx 'HA Backup'",timeout=30)
        initial_boot = primary.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        saved = {node.name:node.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] for node in (primary,secondary)}
        receipt["initial"] = {"primary_boot":initial_boot,"owner":role(primary)["authority"],"saved_hashes":saved}
        for node in (primary,secondary):
            process = node.succeed("systemctl show velstra.service -p ExecStart --value")
            assert "${self.packages.x86_64-linux.velstra}/bin/velstra" in process, process
            receipt.setdefault("agent_execstart",{})[node.name] = process.strip()
        for node,label,interface in ((client,"client","eth1"),(server,"server","eth1"),(secondary,"wan","eth1"),(secondary,"lan","eth2")):
            capture(node,label,interface)
        nonce = secrets.token_hex(16)
        client.succeed("systemd-run --unit=qa-rejoin-client ${command} client --nonce "+nonce+" --seconds 180")
        client.wait_until_succeeds("test -s /run/qa-ha-rejoin/stream.json",timeout=8)
        time.sleep(5)
        secondary.wait_until_succeeds("sentinel show firewall flows | grep '10.2.0.10:41000' | grep -q '10.1.0.10:8443'",timeout=15)
        secondary.succeed("systemd-run --unit=qa-rejoin-observer --setenv=PATH=${observerPath} ${command} observe --reader ${reader} --seconds 180")
        # A role row alone does not prove that BPF/tool collection works.
        # Fail before crashing anything if the observer cannot collect a real
        # complete map record, or has already recorded a collection failure.
        secondary.wait_until_succeeds(py('import json; rows=[json.loads(line) for line in open("/run/qa-ha-rejoin/observer.jsonl")]; assert any(r["kind"]=="maps" and r["nat"]["complete"] is True for r in rows) and not any(r["kind"]=="collection-error" for r in rows)'),timeout=8)
        set_phase("failover")
        failure_at = time.monotonic()
        primary.crash()
        alive["primary"] = False
        wait_owner(secondary,2,budget=1.5)
        failover_seconds = time.monotonic()-failure_at
        receipt["failover_observation"] = {
            "driver_upper_bound_seconds":failover_seconds,"guest_poll_period_seconds":.02,
            "guest":json.loads(secondary.succeed("cat /run/qa-ha-rejoin/owner-observed.json")),
        }
        assert failover_seconds<1.5, ("separate failover prerequisite exceeded bound",failover_seconds)
        time.sleep(2)
        set_phase("incumbent")
        clean_outbox(secondary)
        incumbent = role(secondary)["authority"]
        time.sleep(5)
        set_phase("rejoin")
        # All client and incumbent observers were already running before start.
        primary.start()
        alive["primary"] = True
        for unit in ("multi-user.target","sentinel-boot.service","velstra.service","wren.service","sentinel-api.service"):
            primary.wait_for_unit(unit)
        new_boot = primary.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        assert new_boot != initial_boot and new_boot, (initial_boot,new_boot)
        wait_backup(primary)
        primary.succeed("! ip -o address show eth1 | grep -q 10.1.0.100")
        primary.succeed("! ip -o address show eth2 | grep -q 10.2.0.100")
        assert role(secondary)["authority"] == incumbent, "incumbent changed during nonpreempting rejoin"
        wait_owner(secondary,2)
        for node in (primary,secondary):
            clean_outbox(node)
            assert node.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == saved[node.name]
            node.succeed("test -z \"$(systemctl --failed --plain --no-legend)\"")
        receipt["rejoined"] = {"primary_boot":new_boot,"primary_role":role(primary),"secondary_authority":incumbent}
        set_phase("after")
        time.sleep(10)
        for node in (client,secondary):
            node.succeed("touch /run/qa-ha-rejoin/stop")
        client.wait_until_succeeds("test -s /run/qa-ha-rejoin/client-finished.json",timeout=5)
        secondary.wait_until_succeeds("test -s /run/qa-ha-rejoin/observer-finished.json",timeout=15)
        for node,unit in ((client,"qa-rejoin-client"),(secondary,"qa-rejoin-observer")):
            node.succeed("test $(systemctl show "+unit+" -p ExecMainStatus --value) = 0")
        for node,label in ((client,"client"),(server,"server"),(secondary,"wan"),(secondary,"lan")):
            node.succeed("systemctl is-active --quiet qa-rejoin-pcap-"+label)
        client_rows,client_sha = diagnostic.read_rows(fetch(client,"client.jsonl"))
        owner_rows,owner_sha = diagnostic.read_rows(fetch(secondary,"observer.jsonl"))
        analysis = diagnostic.analyse(client_rows,owner_rows)
        preserve("ha-rejoin-analysis.json",analysis)
        receipt["analysis_sha256"] = hashlib.sha256((artifacts/"ha-rejoin-analysis.json").read_bytes()).hexdigest()
        receipt["raw_log_hashes"] = {"client":client_sha,"incumbent":owner_sha}
        assert analysis["passed"], analysis["failures"]
        receipt["passed"] = True
    except BaseException as error:
        receipt["execution_error"] = {"type":type(error).__name__,"detail":str(error)[:300]}
        raise
    finally:
        # Preserve useful raw evidence even when a strict admission assertion
        # fails. Never clear product maps, outboxes, journals or failure state.
        for node in (client,server,secondary,primary):
            if not alive[node.name]:
                continue
            try:
                node.execute("touch /run/qa-ha-rejoin/stop; systemctl stop qa-rejoin-client.service qa-rejoin-observer.service qa-rejoin-pcap-client.service qa-rejoin-pcap-server.service qa-rejoin-pcap-wan.service qa-rejoin-pcap-lan.service 2>/dev/null")
                if node in (primary,secondary):
                    node.execute("journalctl -b -u velstra -u wren -u sentinel-configsync --no-pager -o short-monotonic > /run/qa-ha-rejoin/services.log")
                archive = "/run/qa-ha-rejoin-"+node.name+".tar.gz"
                node.succeed("tar -czf "+archive+" -C /run qa-ha-rejoin")
                expected = node.succeed("sha256sum "+archive).split()[0]
                target = "archives/"+node.name
                node.copy_from_machine(archive,target)
                actual = hashlib.sha256((artifacts/target/Path(archive).name).read_bytes()).hexdigest()
                assert actual == expected, (node.name,"archive transport mismatch")
                receipt.setdefault("archives",{})[node.name] = actual
            except Exception as error:
                receipt.setdefault("collection_failures",[]).append({"node":node.name,"error":str(error)[:200]})
                receipt["passed"] = False
        try:
            journal = "/run/qa-ha-rejoin-witness.log"
            witness.succeed("journalctl -b -u sentinel-witness.service --no-pager -o short-monotonic > "+journal)
            expected = witness.succeed("sha256sum "+journal).split()[0]
            witness.copy_from_machine(journal,"guest-files/witness")
            actual = hashlib.sha256((artifacts/"guest-files/witness"/Path(journal).name).read_bytes()).hexdigest()
            assert actual == expected, "witness journal transport mismatch"
            receipt["witness_journal_sha256"] = actual
        except Exception as error:
            receipt.setdefault("collection_failures",[]).append({"node":"witness","error":str(error)[:200]})
            receipt["passed"] = False
        preserve("ha-rejoin.json",receipt)
        if not receipt.get("execution_error"):
            assert receipt["passed"] and not receipt.get("collection_failures"), receipt
  '';
}
