# Sentinel's verified-boot appliance image.
#
# The machinery lives in nix/appliance-image.nix (exposed to sibling products
# as `nixosModules.applianceImage`); every `velstra.appliance.*` option there
# DEFAULTS to Sentinel's values, so this wrapper only exists to keep Sentinel's
# own call sites (`imports = [ ./nix/image.nix ]`) and check plumbing stable.
{ config, lib, ... }:
{
  imports = [ ./appliance-image.nix ];

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
