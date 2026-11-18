# Fresh TCP connections across real XDP: a periodic active-intent refresh must
# not undo a partly successful rollback after its independent service failed.
# The real runtime-storage negative and the earlier hostname-only premise
# failure are separately frozen. This positive fixture keeps actual PID1,
# external filesystem failure and fresh traffic as its admission oracles.
{ pkgs, self }:
let
  lib = pkgs.lib;
  webRoot = pkgs.writeTextDir "index.html" "disposable QA endpoint\n";
  handoff = pkgs.writeShellScript "qa-refresh-confirm-handoff" ''
    set -euo pipefail
    if test -e /run/qa-refresh-hold-recovery; then
      ${pkgs.coreutils}/bin/touch /run/qa-refresh-recovery-waiting
      while test -e /run/qa-refresh-hold-recovery; do ${pkgs.coreutils}/bin/sleep 0.02; done
    fi
    exec "$@"
  '';
  timer = pkgs.writeShellScript "qa-refresh-confirm-systemd-run" ''
    set -euo pipefail
    args=()
    inserted=false
    for arg in "$@"; do
      if test "$arg" = --on-active=1min; then
        if test -e /run/qa-refresh-long-window; then args+=(--on-active=40s)
        else args+=(--on-active=5s); fi
        continue
      fi
      if ! "$inserted" && [[ "$arg" = /* ]]; then
        args+=(${handoff})
        inserted=true
      fi
      args+=("$arg")
    done
    "$inserted"
    exec ${pkgs.systemd}/bin/systemd-run "''${args[@]}"
  '';
  hostname = pkgs.writeShellScript "qa-refresh-confirm-hostname" ''
    set -euo pipefail
    if test -e /run/qa-refresh-fail-restore && test "''${1:-}" = before-trial; then
      ${pkgs.nettools}/bin/hostname partial-restore
      # A real temporary read-only mount makes the subsequent undo fail in the
      # kernel, instead of mocking a healthy daemon or synthesizing unit state.
      # /run/sentinel is the disposable VM's tmpfs runtime directory only.
      if ! test -e /run/qa-refresh-readonly-mounted; then
        ${pkgs.util-linux}/bin/mount --bind /run/sentinel /run/sentinel
        ${pkgs.util-linux}/bin/mount -o remount,bind,ro /run/sentinel
        ${pkgs.coreutils}/bin/touch /run/qa-refresh-readonly-mounted
      fi
      echo 'disposable fixture: rollback failed; its runtime-storage undo now encounters real EROFS' >&2
      exit 1
    fi
    exec ${pkgs.nettools}/bin/hostname "$@"
  '';
  cli = self.packages.x86_64-linux.sentinel.overrideAttrs (old:
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.nettools}/bin/hostname" old.buildCommand;
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.systemd}/bin/systemd-run" old.buildCommand;
    { buildCommand = builtins.replaceStrings
        [ "${pkgs.nettools}/bin/hostname" "${pkgs.systemd}/bin/systemd-run" ]
        [ "${hostname}" "${timer}" ] old.buildCommand; });
  apiReady = pkgs.writeText "qa-refresh-api-ready.py" ''
    import json, pathlib, ssl, subprocess, sys, time, urllib.request

    context = ssl._create_unverified_context()  # Disposable loopback TLS only.
    token = pathlib.Path("/var/lib/sentinel/api-token").read_text().strip()
    def request(method, path, body=None):
        headers = {"Authorization": "Bearer " + token}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request("https://127.0.0.1:8443/api/v1/" + path,
                                     headers=headers, data=data, method=method)
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            return json.load(response)
    if sys.argv[1] == "begin":
        document = request("GET", "config/document")
        request("POST", "config/document", dict(
            toml=document["toml"].replace("before-trial", "api-ready"),
            expected_revision=document["revision"]))
        for _ in range(200):
            pending = request("GET", "config/transaction").get("pending") or {}
            if pending.get("ready"):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("real API worker never became ready")
        paths = [pathlib.Path(p) for p in ("/var/lib/sentinel/appliance.toml",
                 "/run/sentinel/running.toml", "/var/lib/sentinel/.appliance.toml.pending.json")]
        before = [p.read_bytes() for p in paths]
        compiled = pathlib.Path("/run/sentinel/velstra.toml")
        inode = compiled.stat().st_ino
        subprocess.run(["systemctl", "start", "sentinel-fwsched.service"], check=True, timeout=10)
        assert compiled.stat().st_ino != inode, "API-ready refresh was incorrectly frozen"
        assert [p.read_bytes() for p in paths] == before, "refresh changed protected API intent"
        current = request("GET", "config/transaction")["pending"]
        assert current["id"] == pending["id"] and current["ready"]
        print("API-READY-REFRESH " + json.dumps(dict(ready=True, policy_reinstalled=True, intent_unchanged=True)), flush=True)
    elif sys.argv[1] == "confirm":
        pending = request("GET", "config/transaction")["pending"]
        assert request("POST", "config/confirm", dict(id=pending["id"]))["confirmed"]
    else:
        raise AssertionError("invalid fixture mode")
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-confirm-refresh-admission";
  globalTimeout = 300;
  nodes = {
    fw = { ... }: {
      imports = [ self.nixosModules.sentinel ];
      virtualisation = { vlans = [ 1 ]; memorySize = 1536; };
      networking.firewall.enable = lib.mkForce false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.90.0.1"; prefixLength = 24; }];
      services.velstra.interface = lib.mkForce "eth1";
      services.velstra.appliance = lib.mkForce (pkgs.writeText "confirm-refresh-appliance.toml" ''
        [system]
        hostname = "boot-saved"
        [[interface]]
        name = "eth0"
        address = "dhcp"
        zone = "wan"
        [[interface]]
        name = "eth1"
        address = "10.90.0.1/24"
        zone = "wan"
      '');
      environment.systemPackages = [ pkgs.python3 pkgs.curl ];
    };
    client = { ... }: {
      virtualisation = { vlans = [ 1 ]; memorySize = 512; };
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.90.0.2"; prefixLength = 24; }];
      environment.systemPackages = [ pkgs.curl ];
    };
  };
  testScript = ''
    import json, shlex
    start_all()
    for node in (fw, client):
        node.wait_for_unit("multi-user.target")
    for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
        fw.wait_for_unit(unit)
    fw.succeed("systemd-run --unit=qa-refresh-http ${pkgs.python3}/bin/python3 -m http.server 9999 --bind 0.0.0.0 --directory ${webRoot}")
    fw.wait_for_unit("qa-refresh-http.service")
    fw.wait_for_open_port(9999)
    saved = "/var/lib/sentinel/appliance.toml"
    running = "/run/sentinel/running.toml"
    snapshot = "/var/lib/sentinel/.appliance.toml.commit-confirm.toml"
    compiled = "/run/sentinel/velstra.toml"

    def configure(lines, fault=False):
        binary = "${cli}/bin/sentinel" if fault else "sentinel"
        script = "\n".join(lines + ["exit", ""])
        fw.succeed("printf %s " + shlex.quote(script) + " | " + binary + " configure")

    def probe(port):
        return "curl -fsS --local-port " + str(port) + " --connect-timeout 1 --max-time 2 http://10.90.0.1:9999/"

    configure(["set firewall rule permit-http from wan", "set firewall rule permit-http action accept",
               "set firewall rule permit-http proto tcp", "set firewall rule permit-http port 9999",
               "set services web enable true", "set services web tls true", "set services web port 8443",
               "set services web listen-address 127.0.0.1", "set services web confirm-timeout 300", "commit", "save"])
    client.succeed(probe(41000))
    with subtest("normal Armed enforcement actually refreshes the active candidate"):
        fw.succeed("touch /run/qa-refresh-long-window")
        configure(["set system hostname armed-trial", "delete firewall rule permit-http", "commit-confirm 1"], fault=True)
        client.fail(probe(42000))
        inode = fw.succeed("stat -c %i " + compiled).strip()
        fw.succeed("systemctl start sentinel-fwsched.service")
        assert fw.succeed("stat -c %i " + compiled).strip() != inode, "Armed refresh must not become a no-op"
        fw.succeed("systemctl is-active --quiet sentinel-confirm.timer")
        client.fail(probe(42001))
        configure(["confirm"])
        fw.succeed("rm /run/qa-refresh-long-window")
    configure(["set system hostname before-trial", "set firewall rule permit-http from wan",
               "set firewall rule permit-http action accept", "set firewall rule permit-http proto tcp",
               "set firewall rule permit-http port 9999", "commit"])
    client.succeed(probe(41001))
    fw.succeed("touch /run/qa-refresh-fail-restore")
    configure(["set system hostname trial-active", "delete firewall rule permit-http", "commit-confirm 1"], fault=True)
    client.fail(probe(41002))
    fw.wait_until_succeeds("test $(systemctl show --property=ActiveState --value sentinel-confirm.service) = failed", timeout=20)
    fw.succeed("test $(hostname) = partial-restore")
    fw.succeed("test -e /run/qa-refresh-readonly-mounted")
    fw.fail("touch /run/sentinel/qa-readonly-write-must-fail")
    fw.succeed("${pkgs.util-linux}/bin/mount -o remount,bind,rw /run/sentinel")
    fw.succeed("touch /run/sentinel/qa-storage-recovered && rm /run/sentinel/qa-storage-recovered")
    # The real rollback has already restored the working firewall before its
    # later hostname/storage failure prevented undo. Storage has recovered, but
    # the Failed state and mixed intent remain until explicit operator recovery.
    # A fresh TCP flow proves that actual live state.
    client.succeed(probe(41003))
    before = {p: fw.succeed("cat " + p) for p in (saved, running, snapshot)}
    before_policy = fw.succeed("cat " + compiled)
    generation = fw.succeed("cat /run/sentinel/mutation.json")
    assert "permit-http" not in before[running] and "permit-http" in before[snapshot]
    assert "port = 9999" in before_policy
    periodic, output = fw.execute("systemctl start sentinel-fwsched.service 2>&1")
    after, response = client.execute(probe(41004))
    proof = dict(periodic_exit=periodic, fresh_tcp_exit=after,
                 retained_failed=fw.succeed("systemctl show --property=ActiveState --value sentinel-confirm.service").strip() == "failed",
                 intent_unchanged={p: fw.succeed("cat " + p) for p in before} == before,
                 compiled_unchanged=fw.succeed("cat " + compiled) == before_policy)
    print("FAILED-REFRESH-ADMISSION " + json.dumps(proof, sort_keys=True), flush=True)
    assert proof["retained_failed"] and proof["intent_unchanged"], proof
    assert periodic == 0 and after == 0 and proof["compiled_unchanged"], "periodic refresh changed the actually restored firewall while recovery remained Failed"
    assert fw.succeed("cat /run/sentinel/mutation.json") == generation

    with subtest("pending exact retry is real Reverting and defers unattended refresh"):
        fw.succeed("rm /run/qa-refresh-fail-restore && touch /run/qa-refresh-hold-recovery")
        fw.succeed("sentinel confirm-rollback")
        fw.wait_until_succeeds("test -e /run/qa-refresh-recovery-waiting", timeout=10)
        fw.succeed("systemctl is-active --quiet sentinel-confirm.service")
        retry_generation = fw.succeed("cat /run/sentinel/mutation.json")
        fw.succeed("systemctl start sentinel-fwsched.service")
        assert fw.succeed("cat " + compiled) == before_policy
        assert {p: fw.succeed("cat " + p) for p in before} == before
        assert fw.succeed("cat /run/sentinel/mutation.json") == retry_generation
        client.succeed(probe(41005))
        fw.succeed("rm /run/qa-refresh-hold-recovery")
        fw.wait_until_succeeds("test $(hostname) = before-trial && grep -q before-trial " + running, timeout=30)
        fw.wait_until_succeeds("test $(systemctl show --property=LoadState --value sentinel-confirm.service) = not-found", timeout=30)
        client.succeed(probe(41006))

    with subtest("Idle refresh is restored after successful explicit recovery"):
        inode = fw.succeed("stat -c %i " + compiled).strip()
        fw.succeed("systemctl start sentinel-fwsched.service")
        assert fw.succeed("stat -c %i " + compiled).strip() != inode
        assert fw.succeed("cat " + saved) == before[saved]
        client.succeed(probe(41007))

    with subtest("a genuinely ready API trial keeps legitimate schedule and feed enforcement"):
        fw.wait_for_unit("sentinel-api.service")
        fw.wait_for_open_port(8443)
        print(fw.succeed("${pkgs.python3}/bin/python3 ${apiReady} begin"), flush=True)
        client.succeed(probe(41008))
        fw.succeed("${pkgs.python3}/bin/python3 ${apiReady} confirm")
        fw.succeed("test $(hostname) = api-ready")
        fw.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
  '';
}
