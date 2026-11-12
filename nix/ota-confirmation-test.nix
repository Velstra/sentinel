# Real EFI/verity, production API/CLI/systemctl pins and transient units.
# No metadata/download/Stage request or simulated healthy boot is used.
{ pkgs, self }:
let
  lib = pkgs.lib;
  sentinel = self.packages.x86_64-linux.sentinel;
  publicKey = pkgs.runCommand "qa-confirmation-disposable-public-key" {
    nativeBuildInputs = [ pkgs.openssl ];
  } ''
    openssl genpkey -algorithm ed25519 -out private.key
    openssl pkey -in private.key -pubout -out "$out"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-ota-real-confirmation-unit-guard";
  globalTimeout = 600;
  nodes.machine = {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/image.nix") ];
    system.name = "machine";
    velstra.appliance.imageVersion = "2.0.2-qa-ota-confirmation";
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (pkgs.writeText "qa-confirmation-appliance.toml" ''
      [system]
      hostname = "guard-fw"
      [[interface]]
      name = "eth0"
      address = "dhcp"
      zone = "wan"
      [update]
      url = "https://127.0.0.1:29484/current"
      public-key = "file:/etc/qa-confirmation-release.pub"
      [services.web]
      enable = true
      tls = true
      listen-address = "127.0.0.1"
    '');
    environment.etc."qa-confirmation-release.pub".source = publicKey;
    environment.etc."qa-confirmation-guard.py".source = ./ota-confirmation-probe.py;
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux ];
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 4096;
      fileSystems = lib.mkVMOverride { };
      qemu.options = [ "-uuid 3bcaa08c-57c7-4ea5-8f17-8f0bd61649ba" ];
    };
  };
  testScript = { nodes, ... }: ''
    import json, os, subprocess, tempfile
    from pathlib import Path
    temporary = tempfile.TemporaryDirectory()
    image = "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}"
    overlay = os.path.join(temporary.name, "confirmation.qcow2")
    qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
    subprocess.run([qemu_img, "create", "-f", "qcow2", "-F", "raw", "-b", image, overlay], check=True)
    subprocess.run([qemu_img, "resize", overlay, "10G"], check=True)
    os.environ["NIX_DISK_IMAGE"] = overlay
    machine.start()
    for unit in ["multi-user.target", "sentinel-boot.service", "velstra.service", "wren.service",
                 "velstra-boot-verify.service", "systemd-bless-boot.service", "sentinel-api.service"]:
        machine.wait_for_unit(unit, timeout=120)
    machine.succeed("test -d /sys/firmware/efi/efivars && dmsetup info --target verity usr")
    machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    output = machine.succeed("${pkgs.python3}/bin/python3 /etc/qa-confirmation-guard.py --sentinel ${sentinel}/bin/sentinel", timeout=210)
    print(output, flush=True)
    proof = json.loads(output)
    assert proof["all_selected_checks_passed"] is True
    assert proof["real_efi_verity"] is True and proof["channel_requests"] == 0
    assert len(proof["phases"]) == 3
    Path(os.environ["out"], "confirmation.json").write_text(json.dumps(proof, indent=2))
    machine.succeed("systemctl is-active sentinel-boot.service velstra.service wren.service sentinel-api.service")
    machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    print("OTA_REAL_CONFIRMATION_UNIT_GUARD_PASS", flush=True)
  '';
}
