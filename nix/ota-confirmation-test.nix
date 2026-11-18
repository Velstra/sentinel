# Real EFI/verity, production API/CLI/systemctl pins and transient units.
# Refused Check admission, no metadata/download/Stage request or fake boot state.
{ pkgs, self }:
let
  lib = pkgs.lib;
  sentinel = self.packages.x86_64-linux.sentinel;
  timer = pkgs.writeShellScript "qa-ota-confirmation-systemd-run" ''
    set -euo pipefail
    args=()
    for arg in "$@"; do
      if test "$arg" = --on-active=1min; then
        args+=(--on-active=5s)
      else
        args+=("$arg")
      fi
    done
    exec ${pkgs.systemd}/bin/systemd-run "''${args[@]}"
  '';
  hostname = pkgs.writeShellScript "qa-ota-confirmation-hostname" ''
    set -euo pipefail
    if test -e /run/qa-ota-fail-restore &&
       test "''${1:-}" = "$(${pkgs.coreutils}/bin/cat /run/qa-ota-restore-hostname)"; then
      ${pkgs.nettools}/bin/hostname guard-partial-restore
      ${pkgs.coreutils}/bin/touch /run/qa-ota-partial-restore
      echo 'disposable fixture: actual restore failed after hostname mutation' >&2
      exit 1
    fi
    exec ${pkgs.nettools}/bin/hostname "$@"
  '';
  faultCli = sentinel.overrideAttrs (old:
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.nettools}/bin/hostname" old.buildCommand;
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.systemd}/bin/systemd-run" old.buildCommand;
    { buildCommand = builtins.replaceStrings
        [ "${pkgs.nettools}/bin/hostname" "${pkgs.systemd}/bin/systemd-run" ]
        [ "${hostname}" "${timer}" ] old.buildCommand; });
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
    # Include the disposable fault wrapper in the sealed image's store without
    # replacing the production sentinel on PATH or the API service executable.
    environment.etc."qa-confirmation-fault-cli".source = "${faultCli}/bin/sentinel";
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
    output = machine.succeed("${pkgs.python3}/bin/python3 /etc/qa-confirmation-guard.py --sentinel ${sentinel}/bin/sentinel --fault-sentinel ${faultCli}/bin/sentinel", timeout=240)
    print(output, flush=True)
    proof = json.loads(output)
    assert proof["all_selected_checks_passed"] is True
    assert proof["real_efi_verity"] is True and proof["channel_requests"] == 0
    assert len(proof["phases"]) == 4
    assert proof["refused_check_requests"] == {"api_http": 409, "cli_exit": 1}
    assert proof["check_admitted"] is False and proof["stage_called"] is False
    Path(os.environ["out"], "confirmation.json").write_text(json.dumps(proof, indent=2))
    machine.succeed("systemctl is-active sentinel-boot.service velstra.service wren.service sentinel-api.service")
    machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    print("OTA_REAL_CONFIRMATION_UNIT_GUARD_PASS", flush=True)
  '';
}
