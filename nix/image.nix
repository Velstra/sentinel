# Sentinel's verified-boot appliance image.
#
# The machinery lives in nix/appliance-image.nix (exposed to sibling products
# as `nixosModules.applianceImage`); every `velstra.appliance.*` option there
# DEFAULTS to Sentinel's values, so this wrapper only exists to keep Sentinel's
# own call sites (`imports = [ ./nix/image.nix ]`) and check plumbing stable.
# Product readiness gates blessing here, not in the product-neutral factory.
{ config, lib, ... }:
{
  imports = [ ./appliance-image.nix ./boot-health.nix ];

  # Runtime upgrades replace immutable images. No package manager, rebuild
  # closure or workstation convenience packages belong on the appliance.
  nix.enable = lib.mkDefault false;
  environment.defaultPackages = lib.mkForce [ ];
  documentation.nixos.enable = false;
  documentation.info.enable = false;

  # Preserve the normal console and expose kernel diagnostics to cloud serial
  # consoles. This is image configuration, not a runtime package mutation.
  boot.kernelParams = [ "console=tty0" "console=ttyS0,115200n8" ];

  # The interactive VM used by the test suite has a convenience login. A
  # flashable appliance must never inherit either that password or its console
  # autologin. Operators seed their own SSH key on the writable data partition.
  users.users.admin.initialPassword = lib.mkForce null;
  services.getty.autologinUser = lib.mkForce null;

  # The image says which release it is (IMG-11): os-release IMAGE_VERSION, the
  # raw file name and `show version` read this. Release builds still force the
  # tagged version; this replaces the bare "1" of an ordinary source build.
  velstra.appliance.imageVersion = lib.mkDefault
    (builtins.fromTOML (builtins.readFile ../Cargo.toml)).package.version;

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
