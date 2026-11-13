# Actual native-provider qualification. The commercial adapter supplies the
# immutable provider and factory/bundle builders; no production key is used.
{ self, updater, nativeImage, resources, client ? "cli", pkgs ? self.nixosConfigurations.appliance.pkgs }:
assert builtins.elem client [ "cli" "ui" ];
let
  lib = pkgs.lib;
  original = self.packages.x86_64-linux.sentinel;
  sentinel = original.overrideAttrs (old: {
    paths = [ (original.unwrapped.overrideAttrs (_: {
      VELSTRA_ENTERPRISE_UPDATE_BIN = "${updater}/bin/velstra-enterprise-update";
    })) ];
  });
  keys = import (self.outPath + "/nix/ota-test-keys.nix") { inherit pkgs; };
  common = {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/image.nix") ];
    services.velstra = {
      sentinel = lib.mkForce sentinel;
      interface = lib.mkForce "eth0";
      appliance = lib.mkForce (pkgs.writeText "qa-native-appliance.toml" ''
        [system]
        hostname = "native-fw"
        [[interface]]
        name = "eth0"
        address = "dhcp"
        zone = "wan"
        [update]
        channel = "qa-enterprise"
        [[update.channels]]
        name = "qa-enterprise"
        url = "https://127.0.0.1:29485/current"
        public-key = "file:/etc/qa-native-keys/release.pub"
        subscription-key = "qa_lab_only_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        [services.web]
        enable = true
        # Management is isolated loopback HTTP for real Chromium automation.
        # The signed release channel still uses real CA/IP/time-validated TLS.
        tls = false
        listen-address = "127.0.0.1"
      '');
    };
    systemd.services.sentinel-api.serviceConfig.ExecStart = lib.mkForce
      "${sentinel}/bin/sentinel api --listen $SENTINEL_API_LISTEN --config /var/lib/sentinel/appliance.toml --token-file /var/lib/sentinel/api-token";
    systemd.services.sentinel-boot-late.serviceConfig.ExecStart = lib.mkForce
      "${sentinel}/bin/sentinel apply-boot-late";
    systemd.services.sentinel-apply-recovery.serviceConfig.ExecStart = lib.mkForce
      "${sentinel}/bin/sentinel apply-recovery --config /var/lib/sentinel/appliance.toml";
    security.pki.certificateFiles = [ (keys + "/tls.crt") ];
    environment.etc."qa-native-keys".source = keys;
    environment.etc."qa-native.py".source = ./native-update-probe.py;
    environment.etc."qa-native-browser".source = pkgs.runCommand "qa-native-browser" { } ''
      mkdir -p "$out"
      cp ${./native-update-browser.mjs} "$out/native.mjs"
      cp ${../tests/console/harness.mjs} "$out/harness.mjs"
    '';
    environment.sessionVariables = {
      CHROMIUM = "${pkgs.chromium}/bin/chromium";
      FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };
    };
    # Keep the base system packages: system.path also supplies D-Bus policy and
    # activation files used by PID 1 and the real boot assessment. Prefer the
    # native CLI over the module's Community CLI without replacing that system.
    environment.systemPackages = [
      (lib.hiPrio sentinel) pkgs.python3 pkgs.util-linux pkgs.openssl pkgs.gptfdisk pkgs.iproute2
      pkgs.nodejs pkgs.chromium
    ];
    velstra.appliance = { storeSize = "4096M"; veritySize = "192M"; dataSize = "2048M"; };
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 4096;
      fileSystems = lib.mkVMOverride { };
    };
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-native-${client}-api-stage";
  globalTimeout = 1500;
  nodes.donor = {
    imports = [ common ];
    system.name = "donor";
    velstra.appliance.imageVersion = "v1.0.0-lts";
  };
  nodes.machine = { nodes, ... }: {
    imports = [ common ];
    system.name = "machine";
    velstra.appliance.imageVersion = "v0.9.0-lts";
    environment.etc."qa-native-resources".source = resources nodes.donor;
  };
  testScript = { nodes, ... }: ''
    import json,os,subprocess,tempfile
    from pathlib import Path
    temporary=tempfile.TemporaryDirectory()
    image="${nativeImage nodes.machine}"
    overlay=os.path.join(temporary.name,"native.qcow2")
    subprocess.run(["${pkgs.qemu}/bin/qemu-img","create","-f","qcow2","-F","raw","-b",image,overlay],check=True)
    subprocess.run(["${pkgs.qemu}/bin/qemu-img","resize",overlay,"24G"],check=True)
    os.environ["NIX_DISK_IMAGE"]=overlay
    machine.start()
    def healthy():
        for unit in ["multi-user.target","sentinel-boot.service","sentinel-boot-late.service",
                     "velstra.service","wren.service","sentinel-api.service",
                     "velstra-boot-verify.service","systemd-bless-boot.service"]:
            machine.wait_for_unit(unit,timeout=150)
        machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
        machine.succeed("dmsetup info --target verity usr")
    healthy()
    before_table=machine.succeed("sfdisk --json /dev/vda")
    try:
        text=machine.succeed("${pkgs.python3}/bin/python3 /etc/qa-native.py --sentinel ${sentinel}/bin/sentinel --client ${client}",timeout=900)
    except Exception:
        # Fixed read-only observations only: no channel config, API token,
        # retry, rescue boot or manual bless is used to diagnose a refusal.
        print("NATIVE_INITIAL_GPT",before_table,flush=True)
        for command in ["sfdisk --json /dev/vda", "bootctl --json=short list",
                        "bootctl get-default", "cat /boot/loader/loader.conf",
                        "findmnt -n -o SOURCE,OPTIONS /boot",
                        "ls -l /boot/EFI/Linux",
                        "sha256sum /boot/EFI/Linux/*.efi",
                        "cat /var/lib/sentinel/update-jobs/state.json"]:
            print("NATIVE_READBACK",command,machine.execute(command),flush=True)
        print(machine.execute("journalctl -b -u 'sentinel-update-*' -u sentinel-api --no-pager"),flush=True)
        print(machine.execute("cat /var/lib/sentinel/qa-native-progress.json"),flush=True)
        raise
    print(text,flush=True)
    result=json.loads(text)
    assert result["passed"] and result["actual_native_writes"]
    Path(os.environ["out"],"stage.json").write_text(json.dumps(result,indent=2))
    machine.copy_from_vm("/var/lib/sentinel/qa-native-ui-check.png", os.environ["out"])
    if "${client}" == "ui":
        machine.copy_from_vm("/var/lib/sentinel/qa-native-ui-stage.png", os.environ["out"])
    machine.shutdown()
    machine.start()
    healthy()
    text=machine.succeed("${pkgs.python3}/bin/python3 /etc/qa-native.py --after-boot",timeout=100)
    print(text,flush=True)
    result=json.loads(text)
    assert result["passed"] and result["booted_new_native_slot"]
    Path(os.environ["out"],"boot.json").write_text(json.dumps(result,indent=2))
    machine.copy_from_vm("/var/lib/sentinel/qa-native-ui-read.png", os.environ["out"])
    print("NATIVE_RUST_API_STAGE_AND_ACTUAL_B_BOOT_PASS",flush=True)
  '';
}
