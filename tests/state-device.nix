# Persistent state must belong to the running verified store even when another
# attached disk has the same filesystem label. Exercise real RAID and LUKS too.
{ pkgs, sentinelModule, imageModule, sentinel }:
let
  # An actual password agent for the known fixture credential. It answers the
  # daemon's real request socket; cryptsetup and systemd-ask-password are intact.
  passwordAgent = pkgs.writeText "state-device-password-agent.py" ''
    import configparser
    import pathlib
    import subprocess
    import time

    seen = set()
    while True:
        for request in pathlib.Path('/run/systemd/ask-password').glob('ask.*'):
            if request in seen:
                continue
            config = configparser.ConfigParser()
            try:
                config.read(request)
                message = config['Ask'].get('Message', "")
                endpoint = config['Ask']['Socket']
            except (OSError, KeyError, configparser.Error):
                continue
            if 'Sentinel data volume' not in message:
                continue
            result = subprocess.run(
                ['${pkgs.systemd}/lib/systemd/systemd-reply-password', '1', endpoint],
                input=b'state-device-fixture-passphrase\n',
            )
            if result.returncode == 0:
                seen.add(request)
                print('Answered boot-owned data password request', flush=True)
        time.sleep(0.05)
  '';
in
pkgs.testers.runNixOSTest {
  name = "sentinel-state-device";
  nodes.machine = {
    imports = [ sentinelModule imageModule ];
    environment.systemPackages = [ pkgs.cryptsetup pkgs.python3 ];
    systemd.services.state-test-password-agent = {
      wantedBy = [ "local-fs.target" ];
      before = [ "local-fs.target" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${passwordAgent}";
    };
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 2048;
      emptyDiskImages = [ 256 256 ];
      fileSystems = pkgs.lib.mkVMOverride { };
    };
  };
  testScript = { nodes, ... }: ''
    import os
    import subprocess
    import tempfile

    image = tempfile.NamedTemporaryFile()
    subprocess.run([
        "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img",
        "create", "-f", "qcow2", "-b",
        "${nodes.machine.system.build.finalImage}/${nodes.machine.image.filePath}",
        "-F", "raw", image.name,
    ], check=True)
    os.environ["NIX_DISK_IMAGE"] = image.name
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-unlock.service")
    machine.wait_for_unit("sentinel-data-fsck.service")
    machine.succeed("systemctl stop state-test-password-agent")
    link = "/run/sentinel-data/device"
    data = "/dev/vda6"
    array = "/dev/md/state-own"

    def identity(device):
        return machine.succeed(f"lsblk -dnro MAJ:MIN {device}").strip()

    def probe():
        machine.succeed("udevadm trigger --subsystem-match=block --action=change; udevadm settle")

    def foreign_alias():
        # Both real filesystems carry LABEL=data. Select the foreign udev-link
        # alternative explicitly so the regression is independent of probe order.
        machine.succeed("ln -sfn /dev/vdb /dev/disk/by-label/data")

    def check_mount(expected):
        assert identity(link) == identity(expected)
        machine.succeed("mkdir -p /mnt/own-state")
        machine.succeed(f"mount {link} /mnt/own-state")
        actual = machine.succeed("findmnt -nro MAJ:MIN /mnt/own-state").strip()
        assert actual == identity(expected), actual
        machine.succeed("umount /mnt/own-state")

    with subtest("a foreign data label cannot select persistent state"):
        assert machine.succeed("findmnt -nro MAJ:MIN /var/lib/sentinel").strip() == identity(data)
        version = machine.succeed("su -s /run/current-system/sw/bin/bash admin -c 'sentinel show version'")
        data_status = next(line for line in version.splitlines() if line.startswith("data:"))
        assert "not encrypted" in data_status, data_status
        machine.succeed("mkfs.ext4 -q -F -L data /dev/vdb")
        probe()
        machine.succeed("mkdir -p /mnt/foreign-state /mnt/own-state; mount /dev/vdb /mnt/foreign-state")
        machine.succeed("echo foreign-canary > /mnt/foreign-state/canary; umount /mnt/foreign-state")
        foreign_alias()
        machine.succeed("sentinel unlock")
        assert identity(link) == identity(data)
        machine.succeed("systemctl stop var-lib-sentinel.mount")

    with subtest("the boot partition selects its own assembled RAID array"):
        machine.succeed(f"wipefs -a {data}")
        machine.succeed(f"mdadm --create {array} --run --metadata=1.2 --level=1 --raid-devices=2 {data} /dev/vdc")
        machine.succeed(f"mkfs.ext4 -q -F -L data {array}")
        probe()
        foreign_alias()
        machine.succeed("sentinel unlock")
        check_mount(array)

    with subtest("plaintext RAID state assembles and mounts across a real boot"):
        machine.succeed(f"mount {link} /mnt/own-state; echo raid-state > /mnt/own-state/marker; umount /mnt/own-state")
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot.service")
        machine.wait_for_unit("sentinel-data-fsck.service")
        array = machine.succeed(f"readlink -f {link}").strip()
        assert machine.succeed(f"lsblk -dnro TYPE {array}").strip() == "raid1"
        assert machine.succeed("findmnt -nro MAJ:MIN /var/lib/sentinel").strip() == identity(array)
        assert machine.succeed("cat /var/lib/sentinel/marker").strip() == "raid-state"
        machine.succeed("systemctl stop state-test-password-agent var-lib-sentinel.mount")

    with subtest("already unlocked state belongs to the boot-owned encrypted array"):
        machine.succeed("umask 077; printf state-device-fixture-passphrase > /run/state-test.key")
        machine.succeed(f"cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --key-file /run/state-test.key {array}")
        machine.succeed(f"cryptsetup open --key-file /run/state-test.key {array} data")
        machine.succeed("mkfs.ext4 -q -F -L data /dev/mapper/data")
        probe()
        foreign_alias()
        machine.succeed("sentinel unlock")
        check_mount("/dev/mapper/data")
        machine.succeed("cryptsetup close data")

    with subtest("the real boot password request opens only the owned container"):
        probe()
        foreign_alias()
        machine.succeed("systemd-run --unit=verify-state-unlock ${sentinel}/bin/sentinel unlock")
        machine.wait_until_succeeds("test -n \"$(find /run/systemd/ask-password -name 'ask.*' -print -quit)\"", timeout=20)
        machine.succeed("python3 - <<'PY'\nimport configparser, pathlib, subprocess\nrequest = next(pathlib.Path('/run/systemd/ask-password').glob('ask.*'))\nconfig = configparser.ConfigParser()\nconfig.read(request)\npassword = pathlib.Path('/run/state-test.key').read_bytes() + b'\\n'\nsubprocess.run(['${pkgs.systemd}/lib/systemd/systemd-reply-password', '1', config['Ask']['Socket']], input=password, check=True)\nPY")
        machine.wait_until_succeeds("journalctl -u verify-state-unlock --no-pager | grep 'boot disk data volume unlocked'", timeout=20)
        machine.wait_until_succeeds("test $(systemctl show verify-state-unlock -p ExecMainStatus --value) -eq 0 && test -b /dev/mapper/data", timeout=20)
        check_mount("/dev/mapper/data")
        machine.succeed("mkdir -p /mnt/foreign-state; mount /dev/vdb /mnt/foreign-state")
        assert machine.succeed("cat /mnt/foreign-state/canary").strip() == "foreign-canary"
        machine.succeed("umount /mnt/foreign-state")
        print(machine.succeed("journalctl -u sentinel-unlock -u verify-state-unlock --no-pager"))

    with subtest("locked RAID state is unlocked and mounted during a real boot"):
        machine.succeed(f"mount {link} /mnt/own-state; echo encrypted-raid-state > /mnt/own-state/marker; umount /mnt/own-state")
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot.service")
        machine.wait_for_unit("sentinel-data-fsck.service")
        assert machine.succeed("findmnt -nro MAJ:MIN /var/lib/sentinel").strip() == identity("/dev/mapper/data")
        assert data in machine.succeed("lsblk -nsrpo NAME /dev/mapper/data").splitlines()
        assert machine.succeed("cat /var/lib/sentinel/marker").strip() == "encrypted-raid-state"
        machine.succeed("journalctl -u state-test-password-agent --no-pager | grep 'Answered boot-owned data password request'")
        print(machine.succeed("journalctl -u sentinel-unlock -u sentinel-data-fsck --no-pager"))
  '';
}
