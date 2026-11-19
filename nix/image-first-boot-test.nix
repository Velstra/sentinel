# First boot of the real verity/UKI image after OFFLINE seeding — the only way
# into a raw/QCOW2 cloud import (PROV-01). One boot checks what the audit saw
# go wrong on that path:
#   PROV-02/HA-00  the seeded data filesystem grows without ext4 errors and the
#                  first, counted boot is blessed (no trial boot burned);
#   PROV-01        the seeded account, key and host key work over SSH;
#   IMG-07         sentinel-boot-late does not sit out a wait-online timeout;
#   EDGE-03        no IKE socket without an IPsec configuration;
#   IMG-11/IMG-03  the image names its release and ships no dev-key payloads.
# Every check is evaluated and reported before the test fails, so one run
# shows the whole state of a build.
#
# `seeding` picks how partition 6 is written: "tool" runs the shipped
# `seed-image`; "mke2fs" writes a fresh `fakeroot mke2fs -d` filesystem over
# the whole partition, which must survive first boot too; "audit-recipe" is
# the audit's exact recipe, whose `dd conv=sparse` skipped the new
# filesystem's zero blocks and so left the factory filesystem's old metadata
# underneath them. It is a diagnostic of PROV-02's root cause, not a check:
# the seed is corrupt before the first boot.
{
  pkgs,
  self,
  seeding ? "tool",
  seedImage ? null,
}:
let
  lib = pkgs.lib;
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).package.version;
  clientKey = pkgs.runCommand "first-boot-client-key" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -C first-boot-client -f $out/id_ed25519
  '';
  seedConfig = pkgs.runCommand "first-boot-appliance.toml" { } ''
    key=$(cat ${clientKey}/id_ed25519.pub)
    cat > $out <<EOF
    [system]
    hostname = "seeded-fw"

    [[system.group]]
    name = "admins"
    permission = "read-write"

    [[system.login]]
    username = "admin"
    group = "admins"
    ssh-key = ["$key"]

    [zone.mgmt]
    default_action = "drop"

    [zone.firewall]
    local = true

    [[interface]]
    name = "eth0"
    zone = "mgmt"
    address = "dhcp"

    [[rule]]
    name = "mgmt-dhcp"
    from = "mgmt"
    proto = "udp"
    port = "68"
    action = "accept"

    [[rule]]
    name = "mgmt-ssh"
    from = "mgmt"
    to = "firewall"
    proto = "tcp"
    port = "22"
    action = "accept"

    [services.ssh]
    enable = true
    EOF
  '';
  tools = lib.makeBinPath [
    pkgs.util-linux
    pkgs.e2fsprogs
    pkgs.fakeroot
    pkgs.openssh
    pkgs.coreutils
  ];
in
assert lib.elem seeding [ "tool" "mke2fs" "audit-recipe" ];
assert seeding == "tool" -> seedImage != null;
pkgs.testers.runNixOSTest {
  name = "sentinel-image-first-boot-${seeding}";
  globalTimeout = 900;
  nodes.machine = {
    imports = [
      self.nixosModules.sentinel
      ./image.nix
      # As nixosConfigurations.sentinel-image ships it.
      ./security-backports.nix
    ];
    system.name = "machine";
    services.velstra.interface = lib.mkForce "eth0";
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 2048;
      fileSystems = lib.mkVMOverride { };
    };
  };
  testScript =
    { nodes, ... }:
    ''
      import hashlib
      import json
      import os
      import subprocess
      import tempfile

      os.environ["PATH"] = "${tools}:" + os.environ["PATH"]
      work = tempfile.mkdtemp()
      factory = "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}"
      seeded = os.path.join(work, "seeded.raw")
      config = "${seedConfig}"

      def data_partition(image):
          table = json.loads(subprocess.check_output(["sfdisk", "--json", image]))["partitiontable"]
          (part,) = [p for p in table["partitions"] if p.get("name") == "data"]
          return part["start"] * 512, part["size"] * 512

      if "${seeding}" == "tool":
          subprocess.run(["${if seedImage == null then "false" else "${seedImage}/bin/sentinel-seed-image"}",
                          "--image", factory, "--config", config, "--output", seeded], check=True)
          offset, length = data_partition(seeded)
      else:
          # The audit's recipe, verbatim in effect: a NEW ext4 of the partition's
          # size, populated by `mke2fs -d` under fakeroot, written over partition 6.
          stage = os.path.join(work, "stage")
          os.makedirs(os.path.join(stage, "ssh"), mode=0o700)
          subprocess.run(["install", "-m", "0600", config, os.path.join(stage, "appliance.toml")], check=True)
          subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
                          os.path.join(stage, "ssh", "ssh_host_ed25519_key")], check=True)
          subprocess.run(["cp", "--sparse=always", factory, seeded], check=True)
          os.chmod(seeded, 0o644)
          offset, length = data_partition(seeded)
          fs = os.path.join(work, "data.ext4")
          subprocess.run(["fakeroot", "mke2fs", "-q", "-t", "ext4", "-L", "data", "-d", stage,
                          fs, f"{length // 1024}k"], check=True)
          conv = "conv=notrunc,sparse" if "${seeding}" == "audit-recipe" else "conv=notrunc"
          subprocess.run(["dd", f"if={fs}", f"of={seeded}", "bs=512", f"seek={offset // 512}",
                          conv, "status=none"], check=True)

      # The host key the box must present, read back from what was written.
      probe = os.path.join(work, "probe.ext4")
      subprocess.run(["dd", f"if={seeded}", f"of={probe}", "bs=512", f"skip={offset // 512}",
                      f"count={length // 512}", "status=none"], check=True)
      fsck = subprocess.run(["e2fsck", "-fn", probe], capture_output=True, text=True)
      print("SEED_FSCK exit=" + str(fsck.returncode) + "\n" + fsck.stdout[-1500:], flush=True)
      if "${seeding}" != "audit-recipe":
          assert fsck.returncode == 0, "the seeded data partition is not a clean filesystem"
      subprocess.run(["debugfs", "-R", f"dump /ssh/ssh_host_ed25519_key.pub {work}/host.pub", probe], check=True)
      expected_host = subprocess.check_output(["ssh-keygen", "-lf", f"{work}/host.pub"], text=True).split()[1]
      config_hash = hashlib.sha256(open(config, "rb").read()).hexdigest()

      overlay = os.path.join(work, "appliance.qcow2")
      qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
      subprocess.run([qemu_img, "create", "-f", "qcow2", "-b", seeded, "-F", "raw", overlay], check=True)
      subprocess.run([qemu_img, "resize", overlay, "16G"], check=True)
      os.environ["NIX_DISK_IMAGE"] = overlay

      failures = []
      def check(name, ok, detail=""):
          print(("PASS " if ok else "FAIL ") + name + ("" if ok else ": " + str(detail)[-3000:]), flush=True)
          if not ok:
              failures.append(name)

      machine.start()
      machine.wait_for_unit("multi-user.target", timeout=300)
      machine.wait_for_unit("sentinel-boot.service", timeout=120)
      blessed = machine.execute("timeout 180 sh -c 'until test -e /boot/EFI/Linux/sentinel-a.efi; do sleep 2; done'")[0] == 0
      boots = machine.succeed("journalctl --list-boots --no-pager -q | wc -l").strip()
      check("PROV-02 the first counted boot is blessed, no trial burned", blessed and boots == "1",
            machine.execute("ls /boot/EFI/Linux; journalctl --list-boots --no-pager")[1])
      dmesg = machine.succeed("dmesg")
      check("PROV-02 no ext4 error while growing the seeded filesystem",
            "EXT4-fs error" not in dmesg, [l for l in dmesg.splitlines() if "EXT4" in l])
      grow = machine.succeed("journalctl -b -u sentinel-state-grow.service --no-pager -o cat")
      check("PROV-02 the data filesystem was grown before the mount", '"filesystem_growth": "grown"' in grow, grow)
      size = int(machine.succeed("df -B1 --output=size /var/lib/sentinel | tail -n1"))
      check("PROV-02 the filesystem fills the grown partition", size > 9 * 1024**3, size)
      failed = machine.succeed("systemctl --failed --plain --no-legend --no-pager").strip()
      check("HA-00 no failed unit on first boot", failed == "", failed)
      seeded_hash = machine.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
      check("PROV-01 the seeded configuration is the one in use", seeded_hash == config_hash
            and machine.succeed("hostname").strip() == "seeded-fw", seeded_hash)
      host = machine.succeed("ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").split()[1]
      check("PROV-01 the seeded host key is the box's identity", host == expected_host, host)
      machine.succeed("install -d -m 0700 /root/.ssh && install -m 0600 /dev/stdin /root/first-boot-key <<'EOF'\n"
                      + open("${clientKey}/id_ed25519").read() + "EOF")
      # The image carries no netcat for wait_for_open_port; ask the socket table.
      machine.wait_until_succeeds("ss -Hltn 'sport = :22' | grep -q LISTEN", timeout=60)
      status, who = machine.execute("ssh -i /root/first-boot-key -o BatchMode=yes -o StrictHostKeyChecking=no "
                                    "-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR admin@127.0.0.1 id -un 2>&1")
      check("PROV-01 the seeded admin logs in with the seeded key", status == 0 and who.strip() == "admin", who)
      times = dict(line.split("=", 1) for line in machine.succeed(
          "systemctl show sentinel-boot-late.service -p InactiveExitTimestampMonotonic "
          "-p ActiveEnterTimestampMonotonic").split())
      took = (int(times["ActiveEnterTimestampMonotonic"]) - int(times["InactiveExitTimestampMonotonic"])) / 1e6
      wait = machine.succeed("journalctl -b --no-pager -o cat | grep -c 'Timeout occurred while waiting for network' || true").strip()
      check("IMG-07 boot-late waits only for the configured link", took < 15 and wait == "0", (took, wait))
      ike = machine.succeed("ss -Hlun '( sport = :500 or sport = :4500 )'").strip()
      check("EDGE-03 no IKE socket without an IPsec configuration", ike == "", ike)
      osrel = machine.succeed("cat /etc/os-release")
      check("IMG-11 os-release names the release", "IMAGE_VERSION=${version}\n" in osrel, osrel)
      keys = machine.succeed("ls /boot/loader/keys/sentinel").split()
      check("IMG-03 no development-key enrollment payloads ship", keys == ["README.txt"], keys)
      mtimes = machine.succeed("find /boot -type f -newermt 2090-01-01 | head").strip()
      check("IMG-11 no ESP file dated after 2090", mtimes == "", mtimes)
      store = machine.succeed("ls /nix/store")
      check("IMG-04 the backported libcap and Suricata are the ones shipped",
            "-libcap-2.78-lib" in store and "-suricata-8.0.7" in store and "-libcap-2.77" not in store
            and "-suricata-8.0.3" not in store, [l for l in store.split() if "libcap" in l or "suricata" in l])
      assert not failures, "failed: " + ", ".join(failures)
    '';
}
