# End-to-end installer authentication, not merely matching seeded config text.
{ pkgs, self }:
let
  lib = pkgs.lib;
  base = {
    imports = [ self.nixosModules.sentinel ./image.nix ];
    velstra.appliance.imageVersion = "2.0.1-qa-wizard-key";
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (pkgs.writeText "wizard-source.toml" ''
      [system]
      hostname = "wizard-source"
      [[interface]]
      name = "eth0"
      address = "dhcp"
      zone = "wan"
    '');
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 2048;
      fileSystems = lib.mkVMOverride {};
    };
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-wizard-independent-key-ssh-boots";
  globalTimeout = 1200;
  nodes = {
    installer = {
      imports = [ base ];
      virtualisation.emptyDiskImages = [ 8000 ];
      environment.systemPackages = [ pkgs.expect ];
      # No host store is mounted: include the real driver fixture in the
      # immutable test image rather than referencing a host-only store file.
      environment.etc."qa-drive-wizard-key.exp".source = ./drive-wizard-key.exp;
    };
    installed = { imports = [ base ]; };
  };
  testScript = { nodes, ... }: ''
    import hashlib, json, os, re, shlex, socket, subprocess, tempfile, time
    from pathlib import Path

    temporary = tempfile.TemporaryDirectory()
    directory = Path(temporary.name)
    image = "${nodes.installer.system.build.finalImageSigned}/${nodes.installer.image.filePath}"
    qemu_img = "${nodes.installer.virtualisation.qemu.package}/bin/qemu-img"
    source_disk = directory / "source.qcow2"
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "raw", "-b", image, str(source_disk)], check=True)
    os.environ["NIX_DISK_IMAGE"] = str(source_disk)
    installer.start()
    installer.wait_for_unit("multi-user.target")
    installer.wait_for_unit("sentinel-boot.service")
    listing = installer.succeed("sentinel install < /dev/null")
    picks = re.findall(r"\[(\d+)\]\s+/dev/vdb\s", listing)
    assert len(picks) == 1, listing
    installer.succeed("ssh-keygen -q -t ed25519 -N \"\" -f /tmp/wizard-client-key")
    public = installer.succeed("cat /tmp/wizard-client-key.pub").strip()
    private = installer.succeed("cat /tmp/wizard-client-key")
    password = '#wizard  "quoted" \\ secret'
    command = "PICK=" + picks[0] + " SSH_PUBLIC_KEY=" + shlex.quote(public) + " WIZARD_PASSWORD=" + shlex.quote(password)
    command += " timeout 1000 ${pkgs.expect}/bin/expect -f /etc/qa-drive-wizard-key.exp > /tmp/wizard-key.log 2>&1"
    # This password is a public disposable fixture. The operator-facing wizard
    # transcript must nevertheless never echo or partially reveal it.
    code, _ = installer.execute(command, timeout=1100)
    transcript = installer.succeed("tr '\r' '\n' < /tmp/wizard-key.log")
    assert code == 0, transcript
    assert not re.search(r"\berror:", transcript, re.I), transcript
    assert password not in transcript and "#wizard" not in transcript and "quoted" not in transcript, "Installer exposed a partial password"
    installer.succeed("mkdir -p /run/qa-wizard-seed; mount -t ext4 -o ro,noload /dev/vdb6 /run/qa-wizard-seed")
    seeded = installer.succeed("cat /run/qa-wizard-seed/appliance.toml")
    assert public in seeded and 'hostname = "wizard-key-fw"' in seeded, "Supplied public key was not seeded"
    installer.succeed("umount /run/qa-wizard-seed")
    installer.shutdown()
    target = installer.state_dir / "empty0.qcow2"
    info = json.loads(subprocess.check_output([qemu_img, "info", "--output=json", str(target)], text=True))
    assert info["format"] == "qcow2" and "backing-filename" not in info
    os.environ["NIX_DISK_IMAGE"] = str(target)
    private_path = directory / "client-key"
    private_path.write_text(private)
    private_path.chmod(0o600)
    password_path = directory / "fixture-password"
    password_path.write_text(password)
    password_path.chmod(0o600)
    askpass = directory / "fixture-askpass"
    askpass.write_text("#!${pkgs.runtimeShell}\nexec ${pkgs.coreutils}/bin/cat " + shlex.quote(str(password_path)) + "\n")
    askpass.chmod(0o700)
    original_key = None
    original_config = None
    authentication_observations = []
    for attempt in range(2):
        installed.start()
        installed.wait_for_unit("multi-user.target")
        installed.wait_for_unit("sshd.service")
        installed.wait_for_unit("velstra.service")
        actual_key = installed.succeed("cat /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").strip()
        actual_config = installed.succeed("cat /var/lib/sentinel/appliance.toml")
        if original_key is None:
            original_key, original_config = actual_key, actual_config
        assert (actual_key, actual_config) == (original_key, original_config), "Installed state or host key changed on reboot"
        known = directory / "known_hosts"
        known.write_text("wizard-key-target " + actual_key + "\n")
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0))
            port = free.getsockname()[1]
        response = installed.send_monitor_command(f"hostfwd_add tcp:127.0.0.1:{port}-:22")
        assert "Error" not in response, response
        args = ["${pkgs.openssh}/bin/ssh", "-F", "/dev/null", "-i", str(private_path), "-p", str(port),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "HostKeyAlias=wizard-key-target", "-o", "UserKnownHostsFile=" + str(known),
                "-o", "ConnectTimeout=3", "admin@127.0.0.1", "hostname"]
        deadline = time.monotonic() + 45
        while True:
            request = subprocess.run(args, capture_output=True, text=True, timeout=10)
            if request.returncode == 0:
                assert request.stdout.strip() == "wizard-key-fw", request.stdout
                break
            if time.monotonic() >= deadline:
                print(installed.succeed("ip -br address; networkctl status eth0 --no-pager; sentinel show firewall statistics; journalctl -u systemd-networkd -u sshd --no-pager -n 30"))
                raise AssertionError("Real wizard SSH failed without any repair: " + request.stderr)
            time.sleep(1)
        actual_service = installed.succeed("systemctl show sshd.service -p ExecStart --value")
        assert "/etc/ssh/sshd_config" in actual_service, actual_service
        effective = installed.succeed("${lib.getExe' nodes.installed.services.openssh.package "sshd"} -T -f /etc/ssh/sshd_config -C user=admin,host=10.0.2.2,addr=10.0.2.2,laddr=10.0.2.15,lport=22")
        # OpenSSH10.5 prints canonical CamelCase, older versions lower case.
        settings = dict(line.split(None, 1) for line in effective.lower().splitlines() if len(line.split(None, 1)) == 2)
        assert settings.get("passwordauthentication") == "no", settings
        def password_probe(method, allowed=False):
            authentication_args = ["BatchMode=no" if value == "BatchMode=yes" else value for value in args[:-2]]
            authentication_args += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=" + method,
                                    "-o", "NumberOfPasswordPrompts=1"]
            if method == "keyboard-interactive":
                authentication_args += ["-o", "PasswordAuthentication=no"]
            authentication_args += args[-2:]
            probe = subprocess.run(authentication_args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                   env={**os.environ, "SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": ":qa"}, timeout=15)
            observation = {"boot": attempt, "method": method, "expected_password_opt_in": allowed,
                           "exit": probe.returncode, "stdout": probe.stdout, "stderr": probe.stderr}
            authentication_observations.append(observation)
            print("WIZARD_KEYONLY_AUTH_PROBE " + json.dumps(observation), flush=True)
            if allowed:
                assert probe.returncode == 0 and probe.stdout.strip() == "wizard-key-fw", "Explicit password opt-in did not work: " + probe.stderr
            else:
                assert probe.returncode == 255 and not probe.stdout.strip() and "Permission denied" in probe.stderr, "Key-only SSH accepted the fixture password via " + method
        for method in ("password", "keyboard-interactive"):
            password_probe(method)
        assert settings.get("kbdinteractiveauthentication") == "no", settings
        assert public in actual_config
        if attempt == 1:
            for enabled in (True, False):
                command = "set services ssh password-authentication " + str(enabled).lower() + "\ncommit\nsave\nexit\n"
                applied = installed.succeed("printf %s " + shlex.quote(command) + " | sentinel configure")
                assert "error:" not in applied.lower(), applied
                installed.wait_for_unit("sshd.service")
                password_probe("password", enabled)
                password_probe("keyboard-interactive")
                key_probe = subprocess.run(args, capture_output=True, text=True, timeout=10)
                assert key_probe.returncode == 0 and key_probe.stdout.strip() == "wizard-key-fw", key_probe.stderr
            assert installed.succeed("cat /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").strip() == original_key
        installed.shutdown()
    assert original_config is not None
    Path(os.environ["out"], "wizard-key-boot.json").write_text(json.dumps({
        "real_wizard": True, "actual_key_authenticated_SSH_boots": 2,
        "complex_password_not_disclosed": True, "key_only_authentication": True,
        "independent_target": True, "post_install_repair": False,
        "password_protocol_and_PAM_probes": authentication_observations,
        "normal_CLI_password_opt_in_and_revocation": True,
        "config_SHA256": hashlib.sha256(original_config.encode()).hexdigest()
    }, indent=2))
  '';
}
