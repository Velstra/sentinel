# Disposable test keys only. Real signed EFI/verity, production CLI/API/worker.
{ pkgs, self }:
let
  lib = pkgs.lib;
  sentinel = self.packages.x86_64-linux.sentinel;
  keys = import ./ota-test-keys.nix { inherit pkgs; };
in pkgs.testers.runNixOSTest {
  name = "sentinel-ota-real-mutation-checkpoint";
  globalTimeout = 600;
  nodes.machine = {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/image.nix") ];
    system.name = "machine";
    velstra.appliance.imageVersion = "2.0.3-qa-ota-mutation";
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (pkgs.writeText "qa-mutation-appliance.toml" ''
      [system]
      hostname = "mutation-fw"
      [[interface]]
      name = "eth0"
      address = "dhcp"
      zone = "wan"
      [update]
      url = "https://127.0.0.1:29484/current"
      public-key = "file:/etc/qa-mutation-keys/release.pub"
      [services.web]
      enable = true
      tls = true
      listen-address = "127.0.0.1"
    '');
    security.pki.certificateFiles = [ (keys + "/tls.crt") ];
    environment.etc."qa-mutation-keys".source = keys;
    environment.etc."qa-mutation-guard.py".source = ./ota-mutation-probe.py;
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.openssl ];
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 4096;
      fileSystems = lib.mkVMOverride { };
      qemu.options = [ "-uuid 733d60b0-c34d-44a4-a219-ae2db1c00c25" ];
    };
  };
  testScript = { nodes, ... }: ''
    import json, os, subprocess, tempfile
    from pathlib import Path
    temporary = tempfile.TemporaryDirectory()
    image = "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}"
    overlay = os.path.join(temporary.name, "mutation.qcow2")
    qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "raw", "-b", image, overlay], check=True)
    subprocess.run([qemu_img, "resize", overlay, "10G"], check=True)
    os.environ["NIX_DISK_IMAGE"] = overlay
    machine.start()
    for unit in ["multi-user.target", "sentinel-boot.service", "sentinel-boot-late.service", "velstra.service", "wren.service",
                 "velstra-boot-verify.service", "systemd-bless-boot.service", "sentinel-api.service"]:
        machine.wait_for_unit(unit, timeout=120)
    machine.succeed("test -d /sys/firmware/efi/efivars && dmsetup info --target verity usr")
    machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    output = machine.succeed("${pkgs.python3}/bin/python3 /etc/qa-mutation-guard.py --sentinel ${sentinel}/bin/sentinel", timeout=180)
    print(output, flush=True)
    proof = json.loads(output)
    assert proof["all_selected_checks_passed"] is True and proof["real_efi_verity"] is True
    Path(os.environ["out"], "mutation.json").write_text(json.dumps(proof, indent=2))
    machine.succeed("systemctl is-active sentinel-boot.service velstra.service wren.service sentinel-api.service")
    machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    print("OTA_REAL_MUTATION_CHECKPOINT_PASS", flush=True)
  '';
}
