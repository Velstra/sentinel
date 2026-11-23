# The appliance kernel: nixpkgs' own linux_6_12 recipe (configuration,
# patches, toolchain) at a newer 6.12.y stable release than the pin carries.
#
# Only the source moves. Advancing the whole nixpkgs pin for a kernel release
# would also move the userspace package set (meson, LLVM, ... between the pin
# and the nixos-26.05 head), and the kernel recipe itself is unchanged there:
# that branch differs only in kernels-org.json, whose 6.12 entry is copied
# below. Every check that boots "the 6.12 kernel" (ebpf-verifier-6-12, the
# fragment and publication tests) runs this one, through the overlay in
# flake.nix and the appliance module's boot.kernelPackages.
#
# Remove this file when the pin reaches the version below. The assertion
# names the pin's version, so a pin bump fails evaluation here instead of
# silently keeping or dropping the override.
pkgs:
let
  version = "6.12.118";
  base = pkgs.linux_6_12;
in
assert pkgs.lib.elem base.version [ "6.12.117" version ];
if base.version == version then
  pkgs.linuxPackages_6_12
else
  pkgs.linuxPackagesFor (base.override {
    argsOverride = {
      inherit version;
      modDirVersion = version;
      # nixos-26.05 ab5c18f, pkgs/os-specific/linux/kernel/kernels-org.json.
      src = pkgs.fetchurl {
        url = "mirror://kernel/linux/kernel/v6.x/linux-${version}.tar.xz";
        hash = "sha256:19d5w74ixfhpv3bnwl0kszd1pn0wmv3y6asvfk02m18f69h88c08";
      };
    };
  })
