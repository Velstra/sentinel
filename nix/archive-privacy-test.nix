# Real root/API and wheel/CLI persistence, legacy migration, unprivileged reads
# and rollback. Every credential in this fixture is disposable public QA data.
{ pkgs, self }:
let
  factory = pkgs.writeText "archive-privacy-appliance.toml" ''
    [system]
    hostname = "archive-fw"
    [system.config-sync]
    secret = "public-qa-fixture-never-a-real-credential"
    [[interface]]
    name = "eth1"
    zone = "lan"
    address = "192.0.2.1/24"
    [services.web]
    enable = true
    tls = false
    listen-address = "127.0.0.1"
  '';
  inspect = pkgs.writeText "inspect-private-archives.py" ''
    import grp, pathlib, stat, sys, tomllib
    root = pathlib.Path("/var/lib/sentinel")
    directory = root / "archive"
    gid = grp.getgrnam("wheel").gr_gid
    assert stat.S_IMODE(directory.stat().st_mode) == 0o750
    assert (directory.stat().st_uid, directory.stat().st_gid) == (0, gid)
    if len(sys.argv) > 1:
        # The initial factory fixture is intentionally public in the Nix store.
        # Every actual CLI/API save must use the private canonical boundary.
        saved = (root / "appliance.toml").stat()
        assert stat.S_IMODE(saved.st_mode) == 0o640
        assert (saved.st_uid, saved.st_gid) == (0, gid)
    revisions = list(directory.glob("config-*.toml"))
    assert revisions
    for path in directory.iterdir():
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o640, (path.name, oct(stat.S_IMODE(info.st_mode)))
        assert (info.st_uid, info.st_gid) == (0, gid)
    for path in revisions + [root / "appliance.toml"]:
        with path.open("rb") as stream: config = tomllib.load(stream)
        assert config["system"]["config-sync"]["secret"] == "public-qa-fixture-never-a-real-credential"
    print(len(revisions))
  '';
  apiChange = pkgs.writeText "archive-api-change.py" ''
    import json, pathlib, time, tomllib, urllib.request
    root = pathlib.Path("/var/lib/sentinel")
    token = (root / "api-token").read_text().strip()
    base = "http://127.0.0.1:8080/api/v1/"
    def request(path, body=None, method=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base + path, data=data, method=method,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as response: return json.load(response)
    with (root / "appliance.toml").open("rb") as stream: candidate = tomllib.load(stream)
    candidate["system"]["hostname"] = "archive-api"
    result = request("config", candidate, "PUT")
    if result.get("pending"):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            pending = request("config/transaction")["pending"]
            assert pending is not None, "candidate reverted before confirmation"
            if pending["ready"]:
                request("config/confirm", {"id": pending["id"]})
                break
            time.sleep(0.2)
        else: raise AssertionError("candidate did not become ready")
    assert request("config")["system"]["hostname"] == "archive-api"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-archive-privacy";
  nodes.machine = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 1536;
    virtualisation.vlans = [ 1 ];
    virtualisation.emptyDiskImages = [ 128 ];
    virtualisation.fileSystems."/var/lib/sentinel" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
      options = [ "nofail" ];
    };
    services.velstra.appliance = lib.mkForce factory;
    services.velstra.interface = lib.mkForce "eth1";
    # Qualify the actual legacy upgrade path before the PRODUCT migration.
    # This fixture creates old public copies, never performs their migration.
    systemd.services.lab-legacy-archive = {
      before = [ "sentinel-archive-protect.service" ];
      requiredBy = [ "sentinel-archive-protect.service" ];
      unitConfig.RequiresMountsFor = [ "/var/lib/sentinel" ];
      serviceConfig.Type = "oneshot";
      script = ''
        if test ! -e /var/lib/sentinel/lab-seeded; then
          mkdir -m 0755 /var/lib/sentinel/archive
          install -m 0644 ${factory} /var/lib/sentinel/archive/config-00000000000000000001.toml
          install -m 0644 ${factory} /var/lib/sentinel/archive/.config-2.toml.tmp
          touch /var/lib/sentinel/lab-seeded
        fi
      '';
    };
  };
  nodes.broken = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 1024;
    services.velstra.appliance = lib.mkForce factory;
    systemd.services.lab-linked-archive = {
      before = [ "sentinel-archive-protect.service" ];
      requiredBy = [ "sentinel-archive-protect.service" ];
      after = [ "systemd-tmpfiles-setup.service" ];
      serviceConfig.Type = "oneshot";
      script = ''
        mkdir -m 0755 /var/lib/sentinel/outside
        printf '%s' unrelated > /var/lib/sentinel/outside/keep
        chmod 0644 /var/lib/sentinel/outside/keep
        ln -s outside /var/lib/sentinel/archive
      '';
    };
  };
  testScript = ''
    import shlex
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.wait_for_unit("sentinel-api.service")
    machine.wait_for_unit("velstra.service")
    machine.wait_for_open_port(8080)
    config = "/var/lib/sentinel/appliance.toml"
    directory = "/var/lib/sentinel/archive"
    inspect = "${pkgs.python3}/bin/python3 ${inspect}"

    def private(saved=True):
        count = int(machine.succeed(inspect + (" --saved" if saved else "")).strip())
        latest = machine.succeed("find " + directory + " -maxdepth 1 -name 'config-*.toml' -type f | sort | tail -n1").strip()
        # Real open/read as each UID, not just a root-mode calculation.
        probe = "${pkgs.python3}/bin/python3 -c " + shlex.quote("import sys; assert open(sys.argv[1], 'rb').read(1)") + " " + shlex.quote(latest)
        machine.fail("runuser -u nobody -- " + probe)
        machine.succeed("runuser -u admin -- " + probe)
        machine.fail("runuser -u nobody -- ls " + directory)
        return count

    def configure(lines, no_apply=False):
        command = "printf %s " + shlex.quote("\n".join(lines + ["exit"]) + "\n") + " | sentinel configure" + (" --no-apply" if no_apply else "")
        result = machine.succeed("su admin -s /bin/sh -c " + shlex.quote("umask 077; " + command) + " 2>&1")
        assert "error:" not in result.lower() and "could not archive" not in result.lower(), result
        return result

    with subtest("legacy secrets are migrated before login, config parsing and management starts"):
        machine.succeed("systemctl is-active sentinel-archive-protect.service")
        for service in ("sentinel-boot", "sentinel-api", "sshd", "systemd-user-sessions"):
            dependencies = machine.succeed("systemctl show " + service + ".service -p Requires --value").split()
            assert "sentinel-archive-protect.service" in dependencies, (service, dependencies)
            protected = int(machine.succeed("systemctl show sentinel-archive-protect.service -p ExecMainExitTimestampMonotonic --value"))
            started = int(machine.succeed("systemctl show " + service + ".service -p ExecMainStartTimestampMonotonic --value"))
            assert 0 < protected <= started, (service, protected, started)
        assert private(saved=False) == 1

    with subtest("wheel CLI save under umask077 creates root-owned protected revisions"):
        # Simulate a historical copy arriving after boot, so this path must use
        # the privileged migration helper while its caller holds apply.lock.
        # This is a PUBLIC QA credential, never an actual secret disclosure.
        machine.succeed("chmod 0755 " + directory + "; chmod 0644 " + directory + "/config-*.toml")
        machine.succeed("runuser -u nobody -- ${pkgs.python3}/bin/python3 -c " + shlex.quote(
            "assert open('" + directory + "/config-00000000000000000001.toml', 'rb').read(1)"))
        result = configure(["set system hostname archive-cli", "set system commit-revisions 3", "commit", "save"])
        assert "commit ok" in result, result
        machine.succeed("hostname | grep -x archive-cli")
        assert private() == 2
        machine.succeed("su admin -s /bin/sh -c 'sentinel show system commit'")

    with subtest("real authenticated API confirmation saves the same credential boundary"):
        machine.succeed("${pkgs.python3}/bin/python3 ${apiChange}")
        machine.succeed("hostname | grep -x archive-api")
        assert private() == 3

    with subtest("wheel rollback reads protected history and restores live plus persisted state"):
        index = machine.succeed("${pkgs.python3}/bin/python3 -c " + shlex.quote(
            "import pathlib,tomllib; p=sorted(pathlib.Path('" + directory + "').glob('config-*.toml'), reverse=True); "
            "print(next(i for i,f in enumerate(p) if tomllib.loads(f.read_text())['system']['hostname']=='archive-cli'))")).strip()
        configure(["rollback " + index])
        machine.succeed("hostname | grep -x archive-cli")
        machine.succeed("sentinel show configuration commands | grep -x 'set system hostname archive-cli'")
        # Rollback uses the existing default keep window; the next ordinary
        # save restores the configured retention, without deleting temp copies.
        configure(["save"], no_apply=True)
        assert private() == 3
        machine.succeed("test -f " + directory + "/.config-2.toml.tmp")

    with subtest("cold boot preserves protected history and working management"):
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-api.service")
        machine.succeed("hostname | grep -x archive-cli")
        assert private() == 3
        machine.succeed("test $(systemctl --failed --plain --no-legend | wc -l) -eq 0")

    with subtest("a substituted archive fails closed before login or API and never chmods its target"):
        broken.wait_until_succeeds("systemctl is-failed --quiet sentinel-archive-protect.service", timeout=60)
        for service in ("sentinel-boot", "sentinel-api", "sshd", "systemd-user-sessions"):
            broken.fail("systemctl is-active --quiet " + service + ".service")
        broken.succeed("test $(stat -c %a /var/lib/sentinel/outside) = 755")
        broken.succeed("test $(stat -c %a /var/lib/sentinel/outside/keep) = 644")
        broken.succeed("grep -qx unrelated /var/lib/sentinel/outside/keep")
  '';
}
