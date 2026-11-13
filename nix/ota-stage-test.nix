# Fresh real signed RAW -> HTTP job worker -> inactive slot -> counted EFI boot.
# Disposable factory keys only. This is not native/production certification.
{ pkgs, self, publicationFailure ? false }:
let
  lib = pkgs.lib;
  sentinel = self.packages.x86_64-linux.sentinel;
  keys = import ./ota-test-keys.nix { inherit pkgs; };
  common = {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/image.nix") ];
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (pkgs.writeText "qa-stage-appliance.toml" ''
      [system]
      hostname = "stage-fw"
      [[interface]]
      name = "eth0"
      address = "dhcp"
      zone = "wan"
      [update]
      url = "https://127.0.0.1:29485/current"
      public-key = "file:/etc/qa-stage-keys/release.pub"
      [services.web]
      enable = true
      tls = true
      listen-address = "127.0.0.1"
    '');
    security.pki.certificateFiles = [ (keys + "/tls.crt") ];
    environment.etc."qa-stage-keys".source = keys;
    environment.etc."qa-stage.py".source = ./ota-stage-probe.py;
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.openssl ];
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 4096;
      fileSystems = lib.mkVMOverride { };
    };
  };
in pkgs.testers.runNixOSTest {
  name = if publicationFailure then "sentinel-ota-publication-failure" else "sentinel-real-http-ota-stage-boot";
  globalTimeout = 1200;
  nodes.donor = {
    imports = [ common ];
    system.name = "donor";
    velstra.appliance.imageVersion = "3.0.0";
    environment.etc."qa-stage-donor".text = "real signed HTTP job stage donor\n";
  };
  nodes.machine = { nodes, ... }: {
    imports = [ common ];
    system.name = "machine";
    velstra.appliance.imageVersion = "2.0.3-qa-http-stage";
    environment.etc."qa-stage-proof".source =
      let raw = "${nodes.donor.system.build.finalImageSigned}/${nodes.donor.image.filePath}";
      in pkgs.runCommand "qa-real-stage-donor-identity" { nativeBuildInputs = [ pkgs.python3 ]; } ''
        mkdir -p "$out"
        python3 - ${raw} "$out/info.json" <<'PY'
        import hashlib, json, pathlib, sys
        path = pathlib.Path(sys.argv[1])
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        pathlib.Path(sys.argv[2]).write_text(json.dumps({'sha256':digest,'size':path.stat().st_size}))
        PY
      '';
    virtualisation.qemu.options = [
      "-device qemu-xhci,id=update-usb"
      "-uuid 3d170c82-4475-4b34-9c58-cdc2ea43d9e0"
    ];
  };
  testScript = { nodes, ... }: ''
    import json, os, subprocess, tempfile
    from pathlib import Path
    publication_failure = ${if publicationFailure then "True" else "False"}
    temporary = tempfile.TemporaryDirectory()
    original = "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}"
    donor = "${nodes.donor.system.build.finalImageSigned}/${nodes.donor.image.filePath}"
    qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
    overlay = os.path.join(temporary.name, "stage.qcow2")
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "raw", "-b", original, overlay], check=True)
    subprocess.run([qemu_img, "resize", overlay, "20G"], check=True)
    os.environ["NIX_DISK_IMAGE"] = overlay
    machine.start()

    def healthy(require_assessment=True):
        for unit in ["multi-user.target", "sentinel-boot.service", "sentinel-boot-late.service", "velstra.service",
                     "wren.service", "sentinel-api.service"]:
            machine.wait_for_unit(unit, timeout=120)
        if require_assessment:
            for unit in ["velstra-boot-verify.service", "systemd-bless-boot.service"]:
                machine.wait_for_unit(unit, timeout=120)
        else:
            # A is already permanent: no boot-count assessment is scheduled
            # on its later boot. Re-run the EXACT read-only product verifier,
            # never start/bless units or manufacture a successful assessment.
            machine.succeed("${pkgs.python3}/bin/python3 -I ${./boot-health.py} verify --sentinel ${sentinel}/bin/sentinel --systemctl ${pkgs.systemd}/bin/systemctl --ip ${pkgs.iproute2}/bin/ip", timeout=100)
        machine.succeed("dmsetup info --target verity usr")
        machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")

    healthy()
    machine.succeed("test $(findmnt -n -o SOURCE /var/lib/sentinel) = /dev/vda6")
    machine.fail("test -b /dev/sda")
    drive = machine.send_monitor_command(f"drive_add 0 if=none,id=stage-source,format=raw,readonly=on,file={donor}")
    assert "Error" not in drive, drive
    attached = machine.send_monitor_command("device_add usb-storage,bus=update-usb.0,drive=stage-source,id=stage-stick")
    assert "Error" not in attached, attached
    machine.wait_until_succeeds("test -b /dev/sda3", timeout=30)
    machine.succeed("test $(findmnt -n -o SOURCE /var/lib/sentinel) = /dev/vda6")
    command = "${pkgs.python3}/bin/python3 /etc/qa-stage.py"
    if publication_failure:
        command += " --publication-failure"
    try:
        output = machine.succeed(command + " --sentinel ${sentinel}/bin/sentinel", timeout=650)
    except Exception:
        print("ACTUAL_STAGE_BOOT_INVENTORY", machine.execute("bootctl --json=short list"), flush=True)
        print("ACTUAL_STAGE_DURABLE_JOB_STATE", machine.execute("cat /var/lib/sentinel/update-jobs/state.json"), flush=True)
        print("ACTUAL_STAGE_FAILURE_JOURNAL", machine.succeed("journalctl -b -u 'sentinel-update-*' --no-pager"), flush=True)
        print("ACTUAL_STAGE_COMPLETED_CASES", machine.execute("cat /run/qa-real-stage-progress.json"), flush=True)
        raise
    print(output, flush=True)
    result = json.loads(output)
    assert result["all_selected_checks_passed"] is True
    if publication_failure:
        assert result["actual_inactive_slot_writes"] is True, result
        assert result["worker_and_api_agree"] is True, result
        assert result["no_automatic_retry"] is True, result
    else:
        assert result["staged"]["boot_entry"] == "sentinel-b+3.efi", result
    Path(os.environ["out"], "stage.json").write_text(json.dumps(result, indent=2))
    # A GUID-identical donor must be detached before the first reboot.
    detached = machine.send_monitor_command("device_del stage-stick")
    assert "Error" not in detached, detached
    machine.wait_until_fails("test -b /dev/sda", timeout=30)
    # The driver starts QEMU with -no-reboot; use its supported cold boot.
    machine.shutdown()
    machine.start()
    healthy(require_assessment=not publication_failure)
    after = "--after-failure-boot" if publication_failure else "--after-boot"
    output = machine.succeed("${pkgs.python3}/bin/python3 /etc/qa-stage.py " + after, timeout=60)
    print(output, flush=True)
    boot = json.loads(output)
    if publication_failure:
        assert boot["booted_original_slot"] is True and boot["unknown_failure_retained"] is True, boot
    else:
        assert boot["booted_new_slot"] is True, boot
    assert boot["preserved_state"] is True, boot
    Path(os.environ["out"], "boot.json").write_text(json.dumps(boot, indent=2))
    print("OTA_PUBLICATION_FAILURE_AND_A_BOOT_PASS" if publication_failure else "REAL_HTTP_OTA_STAGE_AND_B_BOOT_PASS", flush=True)
  '';
}
