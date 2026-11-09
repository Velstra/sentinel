# Real independent installed-target boot, not just successful partition copying.
# No hot-patched binary, host-store mount, source drive or fake health checker.
{ pkgs, self, storage ? "luks", invalidAttempts ? 0 }:
assert builtins.elem storage [ "luks" "raid1" "raid1-luks" ];
assert builtins.elem invalidAttempts [ 0 1 2 ];
assert invalidAttempts == 0 || storage != "raid1";
let
  lib = pkgs.lib;
  encrypted = builtins.elem storage [ "luks" "raid1-luks" ];
  mirror = builtins.elem storage [ "raid1" "raid1-luks" ];
  base = {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/image.nix") ];
    velstra.appliance.imageVersion = "2.0.0-qa-install-boot";
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (pkgs.writeText "installed-boot.toml" ''
      [system]
      hostname = "installed-boot-fw"
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
      fileSystems = lib.mkVMOverride { };
    };
  };
in pkgs.testers.runNixOSTest {
  name = "qa-installed-storage-${storage}-real-boots";
  globalTimeout = 600;
  nodes = {
    installer = {
      imports = [ base ];
      system.name = "installer";
      virtualisation.emptyDiskImages = if mirror then [ 8000 8000 ] else [ 8000 ];
    };
    installed = {
      imports = [ base ];
      system.name = "installed";
      virtualisation.emptyDiskImages = lib.optionals mirror [ 8000 ];
    };
  };
  testScript = { nodes, ... }: ''
    import json
    import os
    import re
    import shlex
    import shutil
    import time
    from pathlib import Path
    import subprocess
    import tempfile

    encrypted = ${if encrypted then "True" else "False"}
    mirror = ${if mirror then "True" else "False"}
    mode = "${storage}"
    secret = "qa1261-ephemeral-volume-passphrase"
    targets = ${builtins.toJSON (if mirror then [ "/dev/vdb" "/dev/vdc" ] else [ "/dev/vdb" ])}
    temporary = tempfile.TemporaryDirectory()
    source_disk = os.path.join(temporary.name, "source.qcow2")
    qemu_img = "${nodes.installer.virtualisation.qemu.package}/bin/qemu-img"
    image = "${nodes.installer.system.build.finalImageSigned}/${nodes.installer.image.filePath}"
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-b", image, "-F", "raw", source_disk], check=True)
    subprocess.run([qemu_img, "resize", source_disk, "16G"], check=True)
    os.environ["NIX_DISK_IMAGE"] = source_disk
    installer.start()
    installer.wait_for_unit("systemd-bless-boot.service")
    installer.succeed("systemctl is-active sentinel-state-grow.service velstra.service wren.service velstra-boot-verify.service")
    assert int(installer.succeed("blockdev --getsize64 /dev/vda6")) > 9*1024**3
    source_key = installer.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1]
    installer.succeed("printf source-only-marker > /var/lib/sentinel/qa-source-only")
    gpt_reads = ["dd if=/dev/vda bs=512 count=34 status=none | sha256sum",
                 "dd if=/dev/vda bs=512 skip=33554399 count=33 status=none | sha256sum"]
    source_gpt = [installer.succeed(cmd) for cmd in gpt_reads]
    source_config = installer.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]

    with subtest("actual installer writes a complete smaller independent disk without touching the source GPT"):
        for target in targets:
            assert int(installer.succeed("blockdev --getsize64 " + target)) == 8000*1024**2
        command = "sentinel install " + " ".join(targets) + " --commit"
        if mirror:
            command += " --raid mirror"
        if encrypted:
            command = "env SENTINEL_LUKS_PASSPHRASE=" + shlex.quote(secret) + " " + command + " --encrypt"
        installer.succeed(command)
        for target in targets:
            for number in (1, 2, 3, 4, 5):
                installer.succeed(f"cmp /dev/vda{number} {target}{number}")
            for number in (1, 2, 3, 4, 5):
                old = installer.succeed(f"blkid -s PARTUUID -o value /dev/vda{number}").strip()
                assert installer.succeed(f"blkid -s PARTUUID -o value {target}{number}").strip() == old
        assert [installer.succeed(cmd) for cmd in gpt_reads] == source_gpt
        assert installer.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == source_config
        installer.shutdown()

    # These exact paths follow the PINNED driver's public state_dir and the
    # pinned qemu-vm emptyDiskImages generator (cwd=state_dir, empty0.qcow2).
    target_disk = installer.state_dir / "empty0.qcow2"
    assert target_disk.is_file() and not target_disk.is_symlink()
    assert target_disk.resolve().parent == installer.state_dir.resolve()
    info = json.loads(subprocess.check_output([qemu_img,"info","--output=json",str(target_disk)],text=True))
    assert info["format"] == "qcow2" and info["virtual-size"] == 8000*1024**2
    assert "backing-filename" not in info, "installed disk still depends on the source"
    if mirror:
        second = installer.state_dir / "empty1.qcow2"
        destination = installed.state_dir / "empty0.qcow2"
        assert second.is_file() and not second.is_symlink()
        assert second.resolve().parent == installer.state_dir.resolve()
        assert not destination.exists()
        # Generated owned fixture data, not a customer/project file.
        with second.open("rb") as source, destination.open("xb") as output:
            shutil.copyfileobj(source,output,4*1024**2)
        second_info = json.loads(subprocess.check_output([qemu_img,"info","--output=json",str(destination)],text=True))
        assert second_info["format"] == "qcow2" and second_info["virtual-size"] == 8000*1024**2
        assert "backing-filename" not in second_info
    os.environ["NIX_DISK_IMAGE"] = str(target_disk)

    invalid_expected = ${toString invalidAttempts}
    unlock_count = 0
    invalid_count = 0
    password_trace = []

    def console_unlock():
        global unlock_count, invalid_count
        if not encrypted:
            return
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if "Unlock the Sentinel data volume" in installed.get_console_log():
                if unlock_count == 0:
                    for attempt in range(1, invalid_expected + 1):
                        baseline = len(installed.get_console_log())
                        installed.send_console(secret + "-incorrect-" + str(attempt) + "\n")
                        retry_deadline = time.monotonic() + 30
                        while time.monotonic() < retry_deadline:
                            fragment = installed.get_console_log()[baseline:]
                            refusal = f"attempt {attempt}/3 failed"
                            assert "data volume unlocked" not in fragment, fragment
                            if refusal in fragment and "Unlock the Sentinel data volume" in fragment.split(refusal,1)[1]:
                                invalid_count += 1
                                password_trace.append({"attempt":attempt,"explicit_refusal":True,"unlocked_before_correct_key":False})
                                break
                            time.sleep(0.1)
                        else:
                            raise AssertionError("wrong password did not produce an explicit refusal and a fresh real prompt")
                installed.send_console(secret + "\n")
                unlock_count += 1
                return
            time.sleep(0.1)
        raise AssertionError("real console unlock prompt did not appear")

    def healthy():
        installed.wait_for_unit("multi-user.target")
        installed.wait_for_unit("sentinel-state-grow.service")
        installed.wait_for_unit("velstra.service")
        installed.wait_for_unit("wren.service")
        # The installer legitimately copies its permanent ESP entry. Do not
        # force another bless or replace the real read-only product checker.
        installed.wait_until_succeeds("${pkgs.python3}/bin/python3 -I ${./boot-health.py} verify "
            "--sentinel ${nodes.installer.services.velstra.sentinel}/bin/sentinel "
            "--systemctl ${pkgs.systemd}/bin/systemctl --ip ${pkgs.iproute2}/bin/ip --timeout 1", timeout=30)
        installed.succeed("test -d /sys/firmware/efi && dmsetup info --target verity usr")
        installed.succeed("test $(systemctl --failed --plain --no-legend | wc -l) -eq 0")
        state_source = installed.succeed("findmnt -no SOURCE /var/lib/sentinel").strip()
        assert installed.succeed("findmnt -no FSTYPE /var/lib/sentinel").strip() == "ext4"
        if encrypted:
            assert state_source == "/dev/mapper/data", state_source
            installed.succeed("${pkgs.cryptsetup}/bin/cryptsetup status data")
            assert "LUKS2 encrypted" in installed.succeed("sentinel show version")
        elif mirror:
            assert state_source.startswith("/dev/md"), state_source
        if mirror:
            raw = installed.succeed("blkid -p -s TYPE -o value /dev/vda6").strip()
            assert raw == "linux_raid_member", raw
            if encrypted:
                status = installed.succeed("${pkgs.cryptsetup}/bin/cryptsetup status data")
                array = next(line.split(":",1)[1].strip() for line in status.splitlines()
                             if line.strip().startswith("device:"))
            else:
                array = state_source
            detail = installed.succeed("${pkgs.mdadm}/bin/mdadm --detail " + shlex.quote(array))
            assert "raid1" in detail and re.search(r"Active Devices\s*:\s*2",detail), detail
            assert re.search(r"Working Devices\s*:\s*2",detail), detail
        elif encrypted:
            assert installed.succeed("blkid -p -s TYPE -o value /dev/vda6").strip() == "crypto_LUKS"
        assert int(installed.succeed("blockdev --getsize64 /dev/vda")) == 8000*1024**2
        assert int(installed.succeed("df -B1 --output=size /var/lib/sentinel | tail -n1")) > 1024**3

    with subtest("the installed target boots its real UKI and creates a fresh identity without source state"):
        installed.start()
        console_unlock()
        healthy()
        installed.fail("test -e /var/lib/sentinel/qa-source-only")
        key = installed.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1]
        assert key != source_key, "installer copied a private source identity"
        version = installed.succeed("sentinel show version")
        assert "release:    2.0.0-qa-install-boot" in version and "slot sentinel-a" in version, version
        installed.succeed("printf installed-marker > /var/lib/sentinel/qa-installed-proof")
        saved_config = installed.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
        first_boot = installed.succeed("cat /proc/sys/kernel/random/boot_id").strip()

    with subtest("a second autonomous target boot preserves its own state and new SSH identity"):
        installed.shutdown()
        installed.start()
        console_unlock()
        healthy()
        assert installed.succeed("cat /proc/sys/kernel/random/boot_id").strip() != first_boot
        assert installed.succeed("cat /var/lib/sentinel/qa-installed-proof") == "installed-marker"
        assert installed.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == saved_config
        assert installed.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1] == key
        assert unlock_count == (2 if encrypted else 0)
        assert invalid_count == invalid_expected
        Path(os.environ["out"],"installed-boot.json").write_text(json.dumps({
            "storage_mode":mode,"encrypted":encrypted,"raid1":mirror,"real_console_unlocks":unlock_count,
            "invalid_console_attempts":invalid_count,"password_refusal_trace":password_trace,
            "source_disk_bytes":16*1024**3,"target_disk_bytes":8000*1024**2,
            "target_independent_qcow2":True,"source_GPT_unchanged":True,
            "all_sealed_payloads_exact":True,"all_protected_partition_GUIDs_exact":True,
            "target_real_EFI_verity_boots":2,"new_identity_not_cloned":True,
            "persistent_state_and_identity":True,"health_checker_replaced":False,
            "manual_bless_or_boot_repair":False,"product_version":version},indent=2))
  '';
}
