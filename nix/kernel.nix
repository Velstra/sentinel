# The appliance kernel: nixpkgs' own linux_6_12 recipe (configuration,
# patches, toolchain) at a newer 6.12.y stable release than the pin carries.
#
# Only the source moves. Advancing the whole nixpkgs pin for a kernel release
# would also move the userspace package set, while the kernel recipe itself
# only reads its version and hash from kernels-org.json, whose 6.12 entry is
# copied below. Every check that boots "the 6.12 kernel" (ebpf-verifier-6-12, the
# fragment and publication tests) runs this one, through the overlay in
# flake.nix and the appliance module's boot.kernelPackages.
#
# Remove this file when the pin reaches the version below. The assertion
# names the pin's version, so a pin bump fails evaluation here instead of
# silently keeping or dropping the override.
pkgs:
let
  version = "6.12.119";
  base = pkgs.linux_6_12;
in
assert pkgs.lib.elem base.version [ "6.12.117" "6.12.118" version ];
if base.version == version then
  pkgs.linuxPackages_6_12
else
  pkgs.linuxPackagesFor (base.override {
    argsOverride = {
      inherit version;
      modDirVersion = version;
      # nixpkgs master kernels-org.json (6.12.119); the same SHA-256 as
      # kernel.org's signed v6.x/sha256sums.asc (143b2879...0c0333).
      src = pkgs.fetchurl {
        url = "mirror://kernel/linux/kernel/v6.x/linux-${version}.tar.xz";
        hash = "sha256:0cq31jkzqx5ssihb5xp1sw3a7sz2b578k5av15qf5fdccmwjhfql";
      };
    };
  })
