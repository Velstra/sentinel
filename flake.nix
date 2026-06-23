{
  description = "Velstra Sentinel — an immutable firewall/router appliance OS (NixOS-based)";

  # FIRST DRAFT — verify on a machine with Nix:
  #   nix flake check
  #   nixos-rebuild build-vm --flake .#appliance   # a throwaway QEMU box to try it
  #   ./result/bin/run-*-vm
  #
  # Requires velstra-proto >= 0.1.1 on crates.io (its build.rs must respect
  # $PROTOC so the sandbox uses nixpkgs' protoc, not the vendored binary). After
  # that is published, run `cargo update -p velstra-proto` so Cargo.lock pins it.
  # Adjust the nixpkgs pin below to a release you have.

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      packages.${system}.default = self.packages.${system}.sentinel;

      packages.${system}.sentinel = pkgs.rustPlatform.buildRustPackage {
        pname = "sentinel";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        # velstra-proto compiles its .proto with protoc. Provide nixpkgs' protoc
        # and point the build script at it (its build.rs honours $PROTOC), rather
        # than executing the vendored binary inside the Nix sandbox.
        nativeBuildInputs = [ pkgs.protobuf ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };

      # The appliance as a NixOS module + a ready-to-build configuration.
      nixosModules.sentinel = { ... }: {
        imports = [ ./nix/appliance.nix ];
        environment.systemPackages = [ self.packages.${system}.sentinel ];
      };

      nixosConfigurations.appliance = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ self.nixosModules.sentinel ];
      };
    };
}
