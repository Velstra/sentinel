# Real immutable UKIs and the actual updater/product health gate. The only fault
# is a broken dataplane executable in the candidate; no replacement health check,
# manual bless, boot-target recovery timer, or post-failure disk repair is used.
{ pkgs, self }:
let
  lib = pkgs.lib;
  base = version: {
    imports = [ self.nixosModules.sentinel ./image.nix ];
    velstra.appliance.imageVersion = version;
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (pkgs.writeText "fallback-appliance.toml" ''
      [system]
      hostname = "fallback-fw"
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
  name = "sentinel-product-boot-fallback";
  globalTimeout = 1200;
  nodes = {
    bad = {
      imports = [ (base "2-qa-broken-dataplane") ];
      system.name = "bad";
      # Preserve all real attachment/hold/security hooks around ExecStart.
      systemd.services.velstra.serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/false";
      environment.etc."sentinel-qa-broken-dataplane".text = "QA-only failing candidate\n";
      systemd.services.qa-boot-observer = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = { Type = "oneshot"; StandardOutput = "journal+console"; };
        script = "echo SENTINEL_QA_BROKEN_DATAPLANE_BOOT $(cat /proc/sys/kernel/random/boot_id)";
      };
    };
    machine = { nodes, ... }: {
      imports = [ (base "1-qa-good-dataplane") ];
      system.name = "machine";
      virtualisation.qemu.options = [ "-device qemu-xhci,id=update-usb" ];
      environment.etc."qa-release-proof".source = pkgs.runCommand "qa-fallback-release-proof"
        { nativeBuildInputs = [ pkgs.openssl ]; } ''
          mkdir -p $out
          # Disposable QA identity, never a production signing key.
          openssl genpkey -algorithm ed25519 -out qa-release.pem
          openssl pkey -in qa-release.pem -pubout -out $out/release-pub.pem
          sha256sum ${nodes.bad.system.build.finalImageSigned}/${nodes.bad.image.filePath} | cut -d ' ' -f1 > $out/candidate.raw.sha256
          openssl pkeyutl -sign -rawin -inkey qa-release.pem \
            -in $out/candidate.raw.sha256 -out $out/candidate.raw.sha256.sig
        '';
      # Observation only: the marker is emitted by the healthy image after the
      # boot loader has exhausted B. It never changes the boot target/counter.
      systemd.services.qa-boot-observer = {
        wantedBy = [ "multi-user.target" ];
        after = [ "local-fs.target" ];
        unitConfig.RequiresMountsFor = "/boot";
        serviceConfig = { Type = "oneshot"; StandardOutput = "journal+console"; };
        path = [ pkgs.util-linux pkgs.coreutils ];
        script = ''
          if test -e /boot/EFI/Linux/sentinel-b+0-3.efi; then
            echo SENTINEL_QA_PRODUCT_FALLBACK_OBSERVED
          fi
        '';
      };
    };
  };
  testScript = { nodes, ... }: ''
    import os, queue, re, select, subprocess, tempfile, time

    temporary = tempfile.TemporaryDirectory()
    overlay = os.path.join(temporary.name, "appliance.qcow2")
    donor = os.path.join(temporary.name, "candidate.qcow2")
    qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
    for path, image in ((overlay, "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}"),
                        (donor, "${nodes.bad.system.build.finalImageSigned}/${nodes.bad.image.filePath}")):
        subprocess.run([qemu_img, "create", "-f", "qcow2", "-b", image, "-F", "raw", path], check=True)
    os.environ["NIX_DISK_IMAGE"] = overlay
    machine.start(allow_reboot=True)
    machine.wait_for_unit("systemd-bless-boot.service")

    def public_keys():
        return {kind: machine.succeed(f"ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_{kind}_key.pub").split()[1]
                for kind in ("ed25519", "rsa")}

    with subtest("healthy real XDP boot is assessed before its trial is made permanent"):
        machine.succeed("systemctl is-active velstra.service velstra-boot-verify.service")
        machine.succeed("test -e /boot/EFI/Linux/sentinel-a.efi")
        started = int(machine.succeed("systemctl show velstra.service -p ExecMainStartTimestampMonotonic --value"))
        assessed = int(machine.succeed("systemctl show velstra-boot-verify.service -p ExecMainExitTimestampMonotonic --value"))
        blessed = int(machine.succeed("systemctl show systemd-bless-boot.service -p ExecMainStartTimestampMonotonic --value"))
        assert 0 < started < assessed <= blessed, (started, assessed, blessed)
        keys = public_keys()
        config_hash = machine.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
        machine.succeed("printf persistent-boot-proof > /var/lib/sentinel/qa-boot-proof")

    with subtest("the actual signed updater stages only inactive B from another image"):
        disks = {fields[0] for line in machine.succeed("lsblk -nsro NAME,TYPE /dev/mapper/usr").splitlines()
                 if len(fields := line.split()) == 2 and fields[1] == "disk"}
        assert len(disks) == 1, disks
        disk = "/dev/" + disks.pop()
        original_a = machine.succeed(f"sha256sum {disk}3").split()[0]
        assert machine.succeed("findmnt -no SOURCE /var/lib/sentinel").strip() == disk + "6"
        machine.fail("test -b /dev/sda")
        added = machine.send_monitor_command(f"drive_add 0 if=none,id=candidate,format=qcow2,file={donor}")
        assert "Error" not in added, added
        added = machine.send_monitor_command("device_add usb-storage,bus=update-usb.0,drive=candidate,id=qa-update-stick")
        assert "Error" not in added, added
        machine.wait_until_succeeds("test -b /dev/sda3", timeout=30)
        output = machine.succeed("sentinel update --commit --pubkey file:/etc/qa-release-proof/release-pub.pem "
                                 "--signature /etc/qa-release-proof/candidate.raw.sha256.sig /dev/sda 2>&1")
        assert "signature verified" in output and "image SHA-256 verified" in output, output
        assert machine.succeed(f"sha256sum {disk}3").split()[0] == original_a
        machine.succeed("test -e /boot/EFI/Linux/sentinel-b+3.efi && test -e /boot/EFI/Linux/sentinel-a.efi")
        machine.shutdown()

    with subtest("three actual failed-dataplane trials automatically fall back without manual rescue"):
        while True:
            try:
                machine.last_lines.get_nowait()
            except queue.Empty:
                break
        machine.start(allow_reboot=True)
        deadline = time.monotonic() + 420
        failed_boots, fallback, recent = set(), False, []
        while time.monotonic() < deadline and not fallback:
            try:
                while True:
                    line = re.sub(r"\x1b\[[0-9;]*m", "", machine.last_lines.get_nowait())
                    recent = (recent + [line])[-40:]
                    marker = re.search(r"SENTINEL_QA_BROKEN_DATAPLANE_BOOT ([0-9a-f-]{36})", line)
                    if marker:
                        failed_boots.add(marker.group(1))
                    if "SENTINEL_QA_PRODUCT_FALLBACK_OBSERVED" in line:
                        fallback = True
            except queue.Empty:
                pass
            time.sleep(0.05)
        assert fallback and len(failed_boots) == 3, (failed_boots, recent)
        # No guest command was sent during the autonomous reboots. QEMU's
        # persistent virtio-serial socket consequently contains FOUR backdoor
        # greetings. The pinned driver's connect() consumes only the first,
        # which corrupts its next base64 response with the remaining greetings.
        # Consume the exact readiness handshakes before using its normal API;
        # this only resynchronises the controller, not any appliance state.
        assert machine.shell is not None
        handshakes = b""
        ready_marker = b"Spawning backdoor root shell..."
        deadline = time.monotonic() + 30
        while handshakes.count(ready_marker) < 4 and time.monotonic() < deadline:
            if select.select([machine.shell], [], [], 1)[0]:
                chunk = machine.shell.recv(4096)
                assert chunk, "test-driver shell disconnected after fallback"
                handshakes += chunk
                assert len(handshakes) < 65536, "unexpected test-driver handshake size"
        assert handshakes.count(ready_marker) == 4, "not all four guest shells became ready"
        machine.connected = True
        # A was already made permanent before updating. On its fallback boot
        # the generator must not need another trial/bless. Read-only readiness
        # still has to pass, without manually starting a bless or health unit.
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("velstra.service")
        machine.wait_for_unit("wren.service")
        machine.wait_until_succeeds("${pkgs.python3}/bin/python3 -I ${./boot-health.py} verify "
            "--sentinel ${nodes.machine.services.velstra.sentinel}/bin/sentinel "
            "--systemctl ${pkgs.systemd}/bin/systemctl --ip ${pkgs.iproute2}/bin/ip --timeout 1", timeout=30)
        machine.succeed("grep -Fx IMAGE_VERSION=1-qa-good-dataplane /etc/os-release")
        machine.fail("test -e /etc/sentinel-qa-broken-dataplane")
        machine.fail("test -b /dev/sda")
        machine.succeed("systemctl is-active velstra.service wren.service")
        machine.succeed("test -e /boot/EFI/Linux/sentinel-b+0-3.efi && test ! -e /boot/EFI/Linux/sentinel-b.efi")
        assert public_keys() == keys
        assert machine.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == config_hash
        assert machine.succeed("cat /var/lib/sentinel/qa-boot-proof") == "persistent-boot-proof"
  '';
}
