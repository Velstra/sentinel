# Sentinel's verified-boot appliance image.
#
# The machinery lives in nix/appliance-image.nix (exposed to sibling products
# as `nixosModules.applianceImage`); every `velstra.appliance.*` option there
# DEFAULTS to Sentinel's values, so this wrapper only exists to keep Sentinel's
# own call sites (`imports = [ ./nix/image.nix ]`) and check plumbing stable.
{ config, lib, pkgs, ... }:
{
  imports = [ ./appliance-image.nix ];

  # The unlock unit resolves the data partition through the running verified
  # store, including its RAID/LUKS holders. Update media carry the same label.
  velstra.appliance.stateDevice = "/run/sentinel-data/device";

  # The link is created after fstab generators run. Check the resolved block
  # device after unlock, without waiting on a not-yet-created alias or a label
  # shared with another disk. The systemd helper retains normal fsck recovery.
  fileSystems.${config.velstra.appliance.stateDir} = {
    noCheck = true;
    options = [ "x-systemd.requires=sentinel-data-fsck.service" ];
  };
  systemd.services.sentinel-data-fsck = {
    description = "Check the boot-owned Sentinel data filesystem";
    requires = [ config.velstra.appliance.unlockUnit ];
    after = [ config.velstra.appliance.unlockUnit ];
    before = [ "local-fs.target" ];
    unitConfig.DefaultDependencies = false;
    path = [ pkgs.util-linux ] ++ config.system.fsPackages;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${config.systemd.package}/lib/systemd/systemd-fsck /run/sentinel-data/device";
    };
  };

  # The interactive VM used by the test suite has a convenience login. A
  # flashable appliance must never inherit either that password or its console
  # autologin. Operators seed their own SSH key on the writable data partition.
  users.users.admin.initialPassword = lib.mkForce null;
  services.getty.autologinUser = lib.mkForce null;

  assertions = [
    {
      assertion = config.users.users.admin.initialPassword == null
        && config.services.getty.autologinUser == null;
      message = "the installable Sentinel image must not have a factory admin password or console autologin";
    }
  ];

  # Historical name — the secureboot check builds its OVMF vars from this.
  system.build.sentinelSbKeys = config.system.build.applianceSbKeys;
}
