# Sentinel's live-boot installer ISO.
#
# The machinery lives in nix/appliance-iso.nix (exposed to sibling products as
# `nixosModules.applianceIso`); every `velstra.iso.*` branding option there
# DEFAULTS to Sentinel's values. This wrapper keeps the historical interface —
# the CLI package and the bundled image's raw path arrive as module args
# (specialArgs in the flake, _module.args in the VM checks) — and maps them
# onto the shared module's options.
#
# Build:  nix build .#sentinel-iso     →  result/iso/velstra-sentinel-installer.iso
{
  sentinelPkg,
  sentinelImageRaw,
  ...
}:
{
  imports = [ ./appliance-iso.nix ];

  velstra.iso = {
    installerPackage = sentinelPkg;
    imageSource = sentinelImageRaw;
  };
}
