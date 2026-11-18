# A real HTTPS provisional change must not be mistaken for a prior-boot
# journal by the public boot-seed command. A genuine reboot must still recover.
{ pkgs, self }:
let
  lib = pkgs.lib;
  probe = pkgs.writeText "qa-confirm-boot-journal.py" ''
    import json, pathlib, ssl, subprocess, urllib.request

    root = pathlib.Path("/var/lib/sentinel")
    saved = root / "appliance.toml"
    running = pathlib.Path("/run/sentinel/running.toml")
    journal = root / ".appliance.toml.pending.json"
    token = (root / "api-token").read_text().strip()
    context = ssl._create_unverified_context()  # Disposable loopback TLS only.
    def request(method, path, body=None):
        headers = {"Authorization": "Bearer " + token}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request("https://127.0.0.1:8443/api/v1/" + path,
                                     data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            return json.load(response)
    document = request("GET", "config/document")
    baseline = saved.read_bytes()
    pathlib.Path("/var/lib/qa-boot-baseline").write_bytes(baseline)
    result = request("POST", "config/document", dict(
        toml=document["toml"].replace("boot-saved", "api-provisional"),
        expected_revision=document["revision"]))
    import time
    for _ in range(200):
        status = request("GET", "config/transaction")
        if (status.get("pending") or {}).get("ready"):
            break
        time.sleep(0.1)
    else:
        raise AssertionError("real provisional worker did not become ready")
    assert subprocess.check_output(["hostname"], text=True).strip() == "api-provisional"
    before = [p.read_bytes() for p in (saved, running, journal)]
    epoch = pathlib.Path("/run/sentinel/mutation.json")
    generation = epoch.read_bytes()
    # A real automatic unit restart must defer, not report a failed-service
    # storm and not consume the transaction by applying saved intent.
    def console_property(name):
        return subprocess.check_output(["systemctl", "show", "--property=" + name,
                                        "--value", "sentinel-console.service"], text=True).strip()
    previous_invocation = console_property("InvocationID")
    subprocess.run(["systemctl", "restart", "systemd-vconsole-setup.service"], check=True, timeout=15)
    # PartOf propagates a separate child job; the parent's completed restart
    # does not acknowledge completion of that new oneshot invocation.
    for _ in range(100):
        invocation = console_property("InvocationID")
        state = console_property("ActiveState")
        assert state in ("inactive", "activating", "deactivating", "active", "failed"), state
        if invocation and invocation != previous_invocation:
            assert state != "failed", "the new automatic console invocation actually failed"
            if state == "active":
                break
        time.sleep(0.05)
    else:
        raise AssertionError("new automatic console invocation did not finish within its bound")
    assert [p.read_bytes() for p in (saved, running, journal)] == before
    assert epoch.read_bytes() == generation
    explicit = subprocess.run(["sentinel", "apply-console", "--config", str(saved)], capture_output=True, text=True, timeout=10)
    assert explicit.returncode != 0 and "confirmation pending" in explicit.stderr
    assert [p.read_bytes() for p in (saved, running, journal)] == before
    assert epoch.read_bytes() == generation
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text()
    pathlib.Path("/var/lib/qa-boot-id").write_text(boot_id)
    result = subprocess.run(["sentinel", "apply-boot"], capture_output=True, text=True, timeout=30)
    proof = dict(exit=result.returncode, hostname=subprocess.check_output(["hostname"], text=True).strip(),
                 saved_unchanged=saved.read_bytes() == before[0],
                 running_unchanged=running.read_bytes() == before[1],
                 journal_unchanged=journal.exists() and journal.read_bytes() == before[2])
    print("SAME-BOOT-JOURNAL " + json.dumps(proof, sort_keys=True), flush=True)
    assert result.returncode != 0 and all(proof[k] for k in (
        "saved_unchanged", "running_unchanged", "journal_unchanged")), "same-boot boot-seed erased or changed a live API transaction"
    assert proof["hostname"] == "api-provisional"
    assert epoch.read_bytes() == generation
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-confirm-boot-journal-admission";
  globalTimeout = 300;
  nodes.fw = { ... }: {
    imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
    virtualisation = { vlans = [ 1 ]; memorySize = 1536; };
    networking.firewall.enable = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [{ address = "192.0.2.1"; prefixLength = 24; }];
    services.velstra.interface = lib.mkForce "eth1";
    environment.systemPackages = [ pkgs.python3 ];
  };
  testScript = ''
    import shlex
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    script = "\n".join([
        "set system hostname boot-saved", "set services web enable true",
        "set services web tls true", "set services web port 8443",
        "set services web listen-address 127.0.0.1", "set services web confirm-timeout 300",
        "commit", "save", "exit", ""])
    fw.succeed("printf %s " + shlex.quote(script) + " | sentinel configure")
    fw.wait_for_unit("sentinel-api.service")
    fw.wait_for_open_port(8443)
    print(fw.succeed("${pkgs.python3}/bin/python3 ${probe}"), flush=True)
    with subtest("genuine new boot restores the exact saved baseline and clears only the prior-boot journal"):
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        for unit in ("sentinel-boot.service", "sentinel-console.service", "velstra.service", "wren.service"):
            fw.wait_for_unit(unit)
        fw.succeed("test $(hostname) = boot-saved")
        fw.succeed("cmp /var/lib/qa-boot-baseline /var/lib/sentinel/appliance.toml")
        fw.fail("test -e /var/lib/sentinel/.appliance.toml.pending.json")
        fw.fail("grep -q api-provisional /run/sentinel/running.toml")
        fw.succeed("test $(cat /proc/sys/kernel/random/boot_id) != $(cat /var/lib/qa-boot-id)")
        fw.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
  '';
}
