# Tools from the repository's immutable nixpkgs lock; no signing inputs here.
{ }:
let
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  pin = lock.nodes.nixpkgs.locked;
  source = builtins.fetchTree {
    type = "github";
    inherit (pin) owner repo rev narHash;
  };
  pkgs = import source { system = "x86_64-linux"; };
in pkgs.mkShell {
  passthru.releaseShell = pkgs.bash;
  SENTINEL_TEST_BOOT_EFI = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi";
  packages = with pkgs; [
    python3 git gnupg openssl sbsigntool efitools mtools util-linux
    qemu zstd binutils xorriso squashfsTools
  ];
}
