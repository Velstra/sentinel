# Sentinel's verified-boot appliance image.
#
# The machinery lives in nix/appliance-image.nix (exposed to sibling products
# as `nixosModules.applianceImage`); every `velstra.appliance.*` option there
# DEFAULTS to Sentinel's values, so this wrapper only exists to keep Sentinel's
# own call sites (`imports = [ ./nix/image.nix ]`) and check plumbing stable.
{ config, ... }:
{
  imports = [ ./appliance-image.nix ];

  # Historical name — the secureboot check builds its OVMF vars from this.
  system.build.sentinelSbKeys = config.system.build.applianceSbKeys;
}
