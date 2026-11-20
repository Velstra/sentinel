# A disposable real block device checks diagnostic privileges and udev parity.
# This is NOT an encrypted-install/verity/boot certificate; those have separate
# installer tests. The linear usr mapping supplies only boot-disk topology.
{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-data-status-readonly";
  nodes.machine = { ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 1536;
    virtualisation.emptyDiskImages = [ 128 ];
    environment.systemPackages = [ pkgs.cryptsetup ];
  };
  testScript = ''
    import shlex
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.succeed("test -b /dev/vdb && test ! -e /dev/mapper/usr")
    layout = "label: gpt\n" + "size=1MiB\n" * 5 + ";\n"
    machine.succeed("printf %s " + shlex.quote(layout) + " | sfdisk /dev/vdb")
    machine.succeed("udevadm settle; mkfs.ext4 -F /dev/vdb6")
    machine.succeed("dmsetup create usr --table '0 2048 linear /dev/vdb3 0'")

    def status(expected):
        machine.succeed("udevadm trigger --subsystem-match=block; udevadm settle")
        root = machine.succeed("sentinel show version")
        viewer = machine.succeed("su -s /bin/sh nobody -c 'sentinel show version'")
        for output in (root, viewer):
            line = next(line for line in output.splitlines() if line.startswith("data:"))
            assert expected in line and "unknown" not in line, output
        machine.fail("su -s /bin/sh nobody -c 'sudo -n id'")
        machine.fail("su -s /bin/sh nobody -c 'test -r /dev/vdb6'")

    with subtest("viewer identifies plaintext without block-device or sudo access"):
        status("not encrypted")
    with subtest("viewer identifies real LUKS metadata without block-device or sudo access"):
        machine.succeed("printf diagnostic-only-key | cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --key-file - /dev/vdb6")
        status("LUKS2 encrypted")
    with subtest("missing filesystem metadata never becomes a plaintext claim"):
        machine.succeed("wipefs -a /dev/vdb6; udevadm trigger --subsystem-match=block; udevadm settle")
        for command in ("sentinel show version", "su -s /bin/sh nobody -c 'sentinel show version'"):
            output = machine.succeed(command)
            line = next(line for line in output.splitlines() if line.startswith("data:"))
            assert "unknown" in line and "not encrypted" not in line, output
    machine.succeed("dmsetup remove usr")
  '';
}
