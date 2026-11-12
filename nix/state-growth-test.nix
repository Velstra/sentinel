# Boot the real verity/UKI image, not an ordinary VM with a fabricated mapper.
# Read-only ExecStartPre/Post witnesses surround the unmodified product helper.
{
  pkgs,
  self,
  withInstallTarget ? false,
}:
let
  lib = pkgs.lib;
  observer = "${pkgs.python3}/bin/python3 -I ${./state-growth-observe.py} ${./grow-state.py}";
in
pkgs.testers.runNixOSTest {
  name = "sentinel-immutable-state-growth${lib.optionalString withInstallTarget "-install"}";
  globalTimeout = 600;
  nodes.machine = {
    imports = [
      self.nixosModules.sentinel
      ./image.nix
    ];
    system.name = "machine";
    velstra.appliance.imageVersion = "2.0.0-qa-state-growth";
    services.velstra.interface = lib.mkForce "eth0";
    services.velstra.appliance = lib.mkForce (
      pkgs.writeText "state-growth-appliance.toml" ''
        [system]
        hostname = "state-growth-fw"
        [[interface]]
        name = "eth0"
        address = "dhcp"
        zone = "wan"
      ''
    );
    image.repart.partitions."50-data".contents."/qa-existing-state-proof".source =
      pkgs.writeText "existing-state-proof" "existing data must survive first boot\n";
    systemd.services.sentinel-state-grow.serviceConfig = {
      ExecStartPre = "${observer} before ${pkgs.util-linux}/bin/sfdisk";
      ExecStartPost = "${observer} after ${pkgs.util-linux}/bin/sfdisk";
    };
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 2048;
      emptyDiskImages = lib.optionals withInstallTarget [ 8000 ];
      fileSystems = lib.mkVMOverride { };
    };
  };
  testScript =
    { nodes, ... }:
    ''
      import json
      import os
      from pathlib import Path
      import subprocess
      import tempfile

      temporary = tempfile.TemporaryDirectory()
      overlay = os.path.join(temporary.name, "appliance.qcow2")
      image = "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}"
      original = json.loads(subprocess.check_output(["${pkgs.util-linux}/bin/sfdisk", "--json", image], text=True))["partitiontable"]
      assert len(original["partitions"]) == 6
      original_data_bytes = original["partitions"][5]["size"] * original["sectorsize"]
      assert original_data_bytes == 128 * 1024**2
      qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
      subprocess.run([qemu_img, "create", "-f", "qcow2", "-b", image, "-F", "raw", overlay], check=True)
      # Only a fresh owned overlay is enlarged. Never resize a host/DUT disk.
      subprocess.run([qemu_img, "resize", overlay, "16G"], check=True)
      os.environ["NIX_DISK_IMAGE"] = overlay

      def observations():
          return {stage: json.loads(machine.succeed(f"cat /run/state-growth-proof/{stage}.json"))
                  for stage in ("before", "after")}

      def retain(label, values):
          # Immutable-image fixtures intentionally do not mount the driver's
          # /tmp/shared 9p exchange. Retain the genuine read-only JSON responses
          # directly on the controller, rather than pretending that share exists.
          print("STATE_GROWTH_OBSERVATIONS " + label + " " + json.dumps(values))
          Path(os.environ["out"], label + ".json").write_text(json.dumps(values, indent=2))

      def assert_no_failed_units():
          failed = machine.succeed("systemctl --failed --plain --no-legend --no-pager")
          if failed.strip():
              print("LIVE_SOURCE_HEALTH_FAILURE " + json.dumps({"failed_units": failed,
                  "verity_unit": machine.succeed("systemctl show systemd-veritysetup@usr.service -p ActiveState -p Result -p BindsTo"),
                  "verity_journal": machine.succeed("journalctl -b -u systemd-veritysetup@usr.service --no-pager -o short-monotonic")}), flush=True)
          assert not failed.strip(), "installer or boot left a failed unit on the live source"

      def assert_healthy():
          machine.wait_for_unit("sentinel-state-grow.service", timeout=120)
          machine.wait_for_unit("systemd-bless-boot.service")
          machine.succeed("systemctl is-active sentinel-state-grow.service sentinel-boot.service velstra.service wren.service velstra-boot-verify.service")
          machine.succeed("test -e /boot/EFI/Linux/sentinel-a.efi")
          machine.succeed("dmsetup info --target verity usr")
          machine.succeed("findmnt --kernel --type tmpfs /")
          assert_no_failed_units()

      machine.start()
      with subtest("real first boot grows only data and ext4 without losing existing bytes"):
          assert_healthy()
          first = observations()
          # Retain raw observations before capacity assertions can abort the test.
          retain("first-boot", first)
          before, after = first["before"], first["after"]
          assert before["layout"]["disk_bytes"] == 16 * 1024**3
          assert before["layout"]["parts"][5]["size"] * 512 == original_data_bytes
          assert after["all_six_original_regions_unchanged"]
          assert before["layout"]["parts"][:5] == after["layout"]["parts"][:5]
          data = after["layout"]["parts"][5]
          data_bytes = data["size"] * 512
          assert data_bytes > 9 * 1024**3, data_bytes
          assert 0 < 16 * 1024**3 - (data["start"]+data["size"]) * 512 < 2 * 1024**2
          fs_bytes = int(machine.succeed("df -B1 --output=size /var/lib/sentinel | tail -n1"))
          assert data_bytes * 0.90 < fs_bytes <= data_bytes, (data_bytes, fs_bytes)
          assert machine.succeed("findmnt -no SOURCE /var/lib/sentinel").strip() == after["layout"]["disk"]+"6"
          assert machine.succeed("cat /var/lib/sentinel/qa-existing-state-proof") == "existing data must survive first boot\n"
          journal = machine.succeed("journalctl -b -u sentinel-state-grow.service --no-pager -o cat")
          assert '"status": "partition-grown"' in journal, journal
          machine.succeed("printf reboot-persistence-proof > /var/lib/sentinel/qa-reboot-proof")
          config_hash = machine.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
          key = machine.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1]

      with subtest("next boot is idempotent and automatically healthy with original identities"):
          machine.shutdown()
          machine.start()
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("velstra.service")
          # The permanent UKI may not pull in a second bless transaction. Verify
          # health read-only instead of manually starting/forcing an assessment.
          machine.wait_until_succeeds("${pkgs.python3}/bin/python3 -I ${./boot-health.py} verify "
              "--sentinel ${nodes.machine.services.velstra.sentinel}/bin/sentinel "
              "--systemctl ${pkgs.systemd}/bin/systemctl --ip ${pkgs.iproute2}/bin/ip --timeout 1", timeout=30)
          assert_no_failed_units()
          second = observations()
          retain("second-boot", second)
          assert second["before"]["boot_id"] != before["boot_id"]
          assert second["before"]["layout"] == after["layout"] == second["after"]["layout"]
          assert second["after"]["all_six_original_regions_unchanged"]
          assert machine.succeed("cat /var/lib/sentinel/qa-reboot-proof") == "reboot-persistence-proof"
          assert machine.succeed("cat /var/lib/sentinel/qa-existing-state-proof") == "existing data must survive first boot\n"
          assert machine.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == config_hash
          assert machine.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1] == key
          assert int(machine.succeed("df -B1 --output=size /var/lib/sentinel | tail -n1")) == fs_bytes
          journal = machine.succeed("journalctl -b -u sentinel-state-grow.service --no-pager -o cat")
          assert '"status": "unchanged"' in journal and '"writes": false' in journal, journal
          machine.succeed("test -e /boot/EFI/Linux/sentinel-a.efi")
    ''
    + lib.optionalString withInstallTarget ''
      with subtest("a grown source still installs onto a smaller disk that fits the factory layout"):
          size = int(machine.succeed("blockdev --getsize64 /dev/vdb"))
          minimum = (original["partitions"][5]["start"] + original["partitions"][5]["size"] + 33) * 512
          assert minimum < size < second["after"]["layout"]["disk_bytes"], (minimum, size)
          snapshot = "dd if=/dev/vdb bs=1M count=1 status=none | sha256sum"
          target_before = machine.succeed(snapshot).split()[0]
          source_gpt = ["dd if=/dev/vda bs=512 count=34 status=none | sha256sum",
              "dd if=/dev/vda bs=512 skip=" + str(second["after"]["layout"]["disk_bytes"]//512-33)
              + " count=33 status=none | sha256sum"]
          source_before = [machine.succeed(cmd) for cmd in source_gpt]
          status, output = machine.execute("sentinel install /dev/vdb --commit 2>&1")
          assert [machine.succeed(cmd) for cmd in source_gpt] == source_before, "installer changed the running source GPT"
          if status:
              # A refusal must remain pre-erase, but is still a failed install
              # contract when the actual factory layout fits this target.
              target_after = machine.succeed(snapshot).split()[0]
              print("GROWN_SOURCE_INSTALL " + json.dumps({"status":status,"output":output,
                  "target_bytes":size,"factory_layout_minimum":minimum,
                  "source_bytes":second["after"]["layout"]["disk_bytes"],
                  "target_first_MiB_before":target_before,"target_first_MiB_after":target_after}))
              assert target_after == target_before, "failed preflight erased the target"
          assert status == 0, output
          machine.succeed("udevadm settle")
          assert 'TYPE="ext4"' in machine.succeed("blkid /dev/vdb6")
          for number in (1, 2, 3, 4, 5):
              source_uuid = machine.succeed(f"blkid -s PARTUUID -o value /dev/vda{number}").strip()
              assert machine.succeed(f"blkid -s PARTUUID -o value /dev/vdb{number}").strip() == source_uuid
          for number in (1, 2, 3):
              machine.succeed(f"cmp /dev/vda{number} /dev/vdb{number}")
          assert machine.succeed("cat /var/lib/sentinel/qa-reboot-proof") == "reboot-persistence-proof"
          assert machine.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == config_hash
          assert machine.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1] == key
          assert_no_failed_units()

      with subtest("reinstalling the existing clone cannot stop the live source verity unit"):
          status, output = machine.execute("sentinel install /dev/vdb --commit 2>&1")
          print("GROWN_SOURCE_REINSTALL " + json.dumps({"exit": status, "actual_installer_output": output}), flush=True)
          assert status == 0, output
          assert [machine.succeed(cmd) for cmd in source_gpt] == source_before
          assert_no_failed_units()
          machine.succeed("dmsetup info --target verity usr")
          assert machine.succeed("cat /var/lib/sentinel/qa-reboot-proof") == "reboot-persistence-proof"
          assert machine.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == config_hash
          assert machine.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1] == key
          for number in (1, 2, 3):
              machine.succeed(f"cmp /dev/vda{number} /dev/vdb{number}")
    '';
}
