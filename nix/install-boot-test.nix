# Real independent installed-target boot, not just successful partition copying.
# No hot-patched binary, host-store mount, source drive or fake health checker.
{
  pkgs,
  self,
  withUpdate ? false,
}:
let
  lib = pkgs.lib;
  base = {
    imports = [
      self.nixosModules.sentinel
      ./image.nix
    ];
    velstra.appliance.imageVersion = "2.0.0-qa-install-boot";
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (
      pkgs.writeText "installed-boot.toml" ''
        [system]
        hostname = "installed-boot-fw"
        [[interface]]
        name = "eth0"
        address = "dhcp"
        zone = "wan"
      ''
    );
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 2048;
      fileSystems = lib.mkVMOverride { };
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "sentinel-grown-source-installed-target-boot${lib.optionalString withUpdate "-after-B-update"}";
  globalTimeout = if withUpdate then 900 else 600;
  nodes = {
    installer = { nodes, ... }: {
      imports = [ base ];
      system.name = "installer";
      virtualisation.emptyDiskImages = [ 8000 ];
      virtualisation.qemu.options = lib.optionals withUpdate [ "-device qemu-xhci,id=update-usb" ];
      environment.etc."qa-install-update-proof" = lib.mkIf withUpdate {
        source =
          pkgs.runCommand "qa-install-updated-source-proof" { nativeBuildInputs = [ pkgs.openssl ]; }
            ''
              mkdir -p $out
              # Disposable test identity only, never a production trust key.
              openssl genpkey -algorithm ed25519 -out release.pem
              openssl pkey -in release.pem -pubout -out $out/release-pub.pem
              sha256sum ${nodes.installed.system.build.finalImageSigned}/${nodes.installed.image.filePath} | cut -d ' ' -f1 > $out/candidate.raw.sha256
              openssl pkeyutl -sign -rawin -inkey release.pem \
                -in $out/candidate.raw.sha256 -out $out/candidate.raw.sha256.sig
            '';
      };
    };
    installed = {
      imports = [ base ];
      system.name = "installed";
      velstra.appliance.imageVersion = lib.mkIf withUpdate (lib.mkForce "2.0.1-qa-install-boot");
      environment.etc."qa-installed-source-B" = lib.mkIf withUpdate {
        text = "Source and target must genuinely boot the updated B payload.\n";
      };
    };
  };
  testScript = { nodes, ... }: ''
    import json
    import os
    from pathlib import Path
    import subprocess
    import tempfile

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
    source_config = installer.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]

    ${lib.optionalString withUpdate ''
      with subtest("normal signed update and autonomous assessment put the real install source in active B"):
          donor = os.path.join(temporary.name, "update-donor.qcow2")
          donor_image = "${nodes.installed.system.build.finalImageSigned}/${nodes.installed.image.filePath}"
          subprocess.run([qemu_img, "create", "-f", "qcow2", "-b", donor_image, "-F", "raw", donor], check=True)
          original_A = installer.succeed("sha256sum /dev/vda2 /dev/vda3")
          installer.fail("test -b /dev/sda")
          added = installer.send_monitor_command(f"drive_add 0 if=none,id=install-update,format=qcow2,file={donor}")
          assert "Error" not in added, added
          added = installer.send_monitor_command("device_add usb-storage,bus=update-usb.0,drive=install-update,id=install-update-stick")
          assert "Error" not in added, added
          installer.wait_until_succeeds("test -b /dev/sda3", timeout=30)
          output = installer.succeed("sentinel update --commit --pubkey file:/etc/qa-install-update-proof/release-pub.pem "
              "--signature /etc/qa-install-update-proof/candidate.raw.sha256.sig /dev/sda 2>&1")
          assert "signature verified" in output and "image SHA-256 verified" in output, output
          assert installer.succeed("sha256sum /dev/vda2 /dev/vda3") == original_A
          installer.succeed("cmp /dev/vda4 /dev/sda2 && cmp /dev/vda5 /dev/sda3")
          installer.shutdown()
          installer.start()
          installer.wait_for_unit("systemd-bless-boot.service")
          installer.fail("test -b /dev/sda")
          source_version = installer.succeed("sentinel show version")
          assert "release:    2.0.1-qa-install-boot" in source_version and "slot sentinel-b" in source_version, source_version
          installer.succeed("test -e /etc/qa-installed-source-B && test -e /boot/EFI/Linux/sentinel-b.efi")
          assert installer.succeed("sha256sum /dev/vda2 /dev/vda3") == original_A
          assert installer.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == source_config
          assert installer.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1] == source_key
          installer.succeed("test $(systemctl --failed --plain --no-legend | wc -l) -eq 0")
    ''}
    # The install operation must preserve this real, already-updated source GPT.
    source_gpt = [installer.succeed(cmd) for cmd in gpt_reads]

    with subtest("actual installer writes a complete smaller independent disk without touching the source GPT"):
        assert int(installer.succeed("blockdev --getsize64 /dev/vdb")) == 8000*1024**2
        installer.succeed("sentinel install /dev/vdb --commit")
        for number in (1, 2, 3, 4, 5):
            installer.succeed(f"cmp /dev/vda{number} /dev/vdb{number}")
        for number in (1, 2, 3, 4, 5):
            old = installer.succeed(f"blkid -s PARTUUID -o value /dev/vda{number}").strip()
            assert installer.succeed(f"blkid -s PARTUUID -o value /dev/vdb{number}").strip() == old
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
    os.environ["NIX_DISK_IMAGE"] = str(target_disk)

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
        assert installed.succeed("findmnt -no SOURCE /var/lib/sentinel").strip() == "/dev/vda6"
        assert int(installed.succeed("blockdev --getsize64 /dev/vda")) == 8000*1024**2
        assert int(installed.succeed("df -B1 --output=size /var/lib/sentinel | tail -n1")) > 1024**3

    with subtest("the installed target boots its real UKI and creates a fresh identity without source state"):
        installed.start()
        healthy()
        installed.fail("test -e /var/lib/sentinel/qa-source-only")
        key = installed.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1]
        assert key != source_key, "installer copied a private source identity"
        version = installed.succeed("sentinel show version")
        assert "release:    ${
          if withUpdate then "2.0.1" else "2.0.0"
        }-qa-install-boot" in version and "slot sentinel-${
          if withUpdate then "b" else "a"
        }" in version, version
        ${lib.optionalString withUpdate ''installed.succeed("test -e /etc/qa-installed-source-B")''}
        installed.succeed("printf installed-marker > /var/lib/sentinel/qa-installed-proof")
        saved_config = installed.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
        first_boot = installed.succeed("cat /proc/sys/kernel/random/boot_id").strip()

    with subtest("a second autonomous target boot preserves its own state and new SSH identity"):
        installed.shutdown()
        installed.start()
        healthy()
        assert installed.succeed("cat /proc/sys/kernel/random/boot_id").strip() != first_boot
        assert installed.succeed("cat /var/lib/sentinel/qa-installed-proof") == "installed-marker"
        assert installed.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == saved_config
        assert installed.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1] == key
        Path(os.environ["out"],"installed-boot.json").write_text(json.dumps({
            "source_disk_bytes":16*1024**3,"target_disk_bytes":8000*1024**2,
            "target_independent_qcow2":True,"source_GPT_unchanged":True,
            "all_sealed_payloads_exact":True,"all_protected_partition_GUIDs_exact":True,
            "target_real_EFI_verity_boots":2,"new_identity_not_cloned":True,
            "persistent_state_and_identity":True,"health_checker_replaced":False,
            "manual_bless_or_boot_repair":False,"product_version":version},indent=2))
  '';
}
