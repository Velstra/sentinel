{
  description = "Velstra Sentinel — an immutable firewall/router appliance OS (NixOS-based)";

  # Verify with Nix:
  #   nix build .#sentinel                       # the CLI (works)
  #   nix build .#velstra                         # the eBPF agent (this milestone)
  #   nixos-rebuild build-vm --flake .#appliance  # the appliance VM
  #
  # nixpkgs must ship rustc >= 1.85 (edition 2024); 25.05 does. The velstra agent
  # needs a NIGHTLY toolchain with rust-src + bpf-linker to compile its eBPF, so
  # it is built with fenix's nightly, not nixpkgs' stable rustc.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The Velstra Fabric source (the data-plane agent lives here). Source only —
    # we build it with our own toolchain, so it needs no flake of its own.
    # Local checkout while fabric is private; switch to "github:Velstra/fabric"
    # once it is public (then it works for CI/others too). Uses fabric's
    # committed HEAD — commit pending fabric changes before building.
    fabric = {
      url = "git+file:///home/mbrandt/01_repositories/velstra/fabric";
      flake = false;
    };
  };

  outputs =
    { self, nixpkgs, fenix, fabric }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;

      # --- the sentinel CLI (stable rustc is fine) ---------------------------
      sentinel = pkgs.rustPlatform.buildRustPackage {
        pname = "sentinel";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [ pkgs.protobuf ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };

      # --- the velstra eBPF/XDP agent (needs nightly + rust-src + bpf-linker) -
      # fenix's `complete` nightly bundles rust-src, which the BPF target's
      # build-std needs. The agent's build.rs (aya-build) compiles the eBPF crate
      # for the bpf target during this build.
      # Pin a nightly whose LLVM matches nixpkgs' bpf-linker (LLVM 20). The latest
      # nightly emits LLVM 22 bitcode, which nixpkgs' LLVM-20 bpf-linker can't
      # read ("Unknown attribute kind"). nixpkgs 25.05 ships at most LLVM 20, so
      # the toolchain must be from the LLVM-20 era. Replace fakeHash with the
      # value the first build reports.
      nightlyDate = "2025-06-15";
      nightlySha = "sha256-hMlbNn0xAaLK+EDwdxW/8ZlC8/GHLpFhqB2fhCoj/iU=";
      nightlyProfile = fenix.packages.${system}.toolchainOf {
        channel = "nightly";
        date = nightlyDate;
        sha256 = nightlySha;
      };
      # fenix reads this manifest at EVAL time (import-from-derivation) to build
      # the toolchain — so an airgapped self-rebuild needs it in the store or even
      # *evaluating* the flake fails offline. Re-fetch it here with the same hash:
      # a fixed-output derivation is content-addressed, so this produces the exact
      # same store path fenix's internal one does, and shipping it makes eval work
      # offline. (Pure store-path reference, no `builtins.storePath` hardcoding.)
      rustNightlyManifest = pkgs.fetchurl {
        url = "https://static.rust-lang.org/dist/${nightlyDate}/channel-rust-nightly.toml";
        sha256 = nightlySha;
      };
      nightly = nightlyProfile.withComponents [
        "cargo"
        "rustc"
        "rust-src"
        "rust-std"
        "clippy"
        "rustfmt"
      ];
      rustPlatformNightly = pkgs.makeRustPlatform {
        cargo = nightly;
        rustc = nightly;
      };

      # All aya-* crates come from one git checkout, so they share one hash.
      ayaHash = "sha256-Py7WDRIjy9p6ntTdnjhahkClKI3wIJRNwwqnONFX7Kk=";

      ayaOutputHashes = {
        "aya-0.13.2" = ayaHash;
        "aya-build-0.1.3" = ayaHash;
        "aya-ebpf-0.1.2" = ayaHash;
        "aya-ebpf-bindings-0.1.2" = ayaHash;
        "aya-ebpf-cty-0.2.3" = ayaHash;
        "aya-ebpf-macros-0.1.2" = ayaHash;
        "aya-log-0.2.2" = ayaHash;
        "aya-log-common-0.1.16" = ayaHash;
        "aya-log-ebpf-0.1.2" = ayaHash;
        "aya-log-ebpf-macros-0.1.1" = ayaHash;
        "aya-log-parser-0.1.14" = ayaHash;
        "aya-obj-0.2.2" = ayaHash;
      };

      # The eBPF object, compiled as a FIXED-OUTPUT derivation. `-Z build-std`
      # needs std's own build-deps, which a sealed offline sandbox can't fetch —
      # so this derivation is allowed network (that's what a FOD grants) and is
      # pinned by its output hash, keeping the result reproducible. First build
      # reports the real hash; replace fakeHash below with it.
      ebpfHash = "sha256-YikSvX+bth9aErTiwgUPQGEe7FyUTmxEDqJjT68/ixA=";
      velstra-ebpf = pkgs.stdenv.mkDerivation {
        pname = "velstra-ebpf";
        version = "0.1.0";
        src = fabric;
        nativeBuildInputs = [ nightly pkgs.bpf-linker ];

        outputHashMode = "flat";
        outputHashAlgo = "sha256";
        outputHash = ebpfHash;
        # The eBPF object embeds build-path strings (debuginfo/BTF) that look like
        # store-path references; a raw object file can't actually "use" them, so
        # discard them. Needs structured attrs.
        __structuredAttrs = true;
        unsafeDiscardReferences.out = true;

        buildPhase = ''
          export HOME=$TMPDIR
          export CARGO_HOME=$TMPDIR/cargo
          # Same flags aya-build uses for the BPF target, plus the explicit
          # bpf-linker selection.
          export RUSTFLAGS='--cfg=bpf_target_arch="x86_64" -Cdebuginfo=2 -Clinker=bpf-linker -Clink-arg=--btf'
          # The lockfile was generated with a newer rustc, so some build-deps of
          # *other* workspace members (aya-build -> cargo-platform) declare a
          # rustc newer than this pinned nightly. They aren't compiled when
          # building velstra-ebpf, so ignore the version gate.
          cargo build -p velstra-ebpf --bins --release \
            --target bpfel-unknown-none -Z build-std=core \
            --ignore-rust-version
        '';
        installPhase = ''
          cp target/bpfel-unknown-none/release/velstra "$out"
        '';
      };

      velstra = rustPlatformNightly.buildRustPackage {
        pname = "velstra";
        version = "0.1.0";
        src = fabric;
        cargoLock = {
          lockFile = "${fabric}/Cargo.lock";
          outputHashes = ayaOutputHashes;
        };
        # bpf-linker: velstra-ebpf is a build-dependency of the agent (for cargo
        # cache tracking) and its build.rs just does `which bpf-linker`, so it
        # must be on PATH even though our shim already supplied the object.
        nativeBuildInputs = [ pkgs.protobuf pkgs.bpf-linker ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
        # Replace the agent's build.rs with the shim that copies the pre-built
        # eBPF object — so this build is fully offline (no build-std here).
        postPatch = ''
          cp ${./nix/velstra-build-shim.rs} velstra-app/build.rs
        '';
        VELSTRA_EBPF_OBJ = velstra-ebpf;
        # Build just the agent binary. --ignore-rust-version: the lockfile (made
        # with a newer rustc) has build-deps declaring a newer rustc than this
        # pinned LLVM-20 nightly; skip the version gate.
        cargoBuildFlags = [ "-p" "velstra" "--ignore-rust-version" ];
        # The workspace's tests need root (they load eBPF) — skip in the sandbox.
        doCheck = false;
      };

      # The factory-default appliance config, baked into the image. At runtime the
      # operator edits /var/lib/sentinel/appliance.toml; the sentinel-boot service
      # compiles the active config (runtime file if present, else this factory
      # default) into /run, and `sentinel commit` applies edits to the running
      # system live (no rebuild). Pure eval — no runtime-path reads.
      factoryAppliance = ./example-appliance.toml;
      applianceData = builtins.fromTOML (builtins.readFile factoryAppliance);
    in
    {
      packages.${system} = {
        default = sentinel;
        inherit sentinel velstra velstra-ebpf;
      };

      # The appliance: the base config + the Velstra data-plane service. The
      # velstra agent runs the build-time-compiled firewall config as a systemd
      # service — so the box filters as part of the immutable, rollback-able
      # generation.
      nixosModules.sentinel =
        { ... }:
        {
          imports = [
            ./nix/appliance.nix
            ./nix/velstra-service.nix
          ];
          environment.systemPackages = [ sentinel ];

          # OS settings driven by the appliance config. The hostname comes from
          # `[system] hostname` — so a `commit` that changes it actually changes
          # the system hostname (the rest of the OS↔config mapping — interface
          # addresses, etc. — builds out from here). Normal priority so it wins
          # over module defaults (and the NixOS test framework's default).
          networking.hostName = applianceData.system.hostname;

          services.velstra = {
            enable = true;
            package = velstra;
            inherit sentinel;
            appliance = factoryAppliance;
            interface = "eth0";
          };
        };

      nixosConfigurations.appliance = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ self.nixosModules.sentinel ];
      };

      # Boots the appliance and verifies `commit` applies config to the running
      # system live — no rebuild, no reboot, fully airgapped (the VM has no
      # network). Edits the hostname and asserts it changed via hostnamectl while
      # the data plane stays up.
      #   nix build .#checks.x86_64-linux.commit -L
      checks.${system}.commit = pkgs.testers.runNixOSTest {
        name = "sentinel-commit";
        nodes.machine = {
          imports = [ self.nixosModules.sentinel ];
          virtualisation.memorySize = 2048;
        };
        testScript = ''
          machine.wait_for_unit("multi-user.target")
          # Boot seeded the editable config from the factory and brought the
          # data plane up with it.
          machine.wait_for_unit("sentinel-boot.service")
          machine.wait_for_unit("velstra.service")
          machine.succeed("test -f /var/lib/sentinel/appliance.toml")
          machine.succeed("test -f /run/sentinel/velstra.toml")
          # The system's real NIC (eth0) is discovered and shows up in the config,
          # ready to assign — VyOS-style. (The minimal factory config has no
          # interfaces of its own.)
          machine.succeed("sentinel configure --no-apply <<< 'show' | grep -q eth0")

          # Edit + commit AS THE ADMIN USER (not root) — exercises the real
          # privilege path: admin writes the config (wheel-group), sentinel
          # escalates hostname/reload via passwordless sudo. Assign the discovered
          # NIC a zone and change the hostname; commit applies live (no reboot).
          # VyOS semantics: `commit` applies to the running system (live);
          # `save` persists to the boot config so it survives reboot.
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set system hostname fw-a' "
              "'set interface eth0 role wan' 'set interface eth0 address dhcp' "
              "commit save exit "
              "| sentinel configure\""
          )

          # Hostname changed live.
          machine.succeed("hostname | grep -x fw-a")
          # Live visibility (the VyOS feel): a fresh shell's dynamic prompt
          # mechanism ($(hostname)) yields the new name immediately — no relogin.
          machine.succeed("su admin -c 'echo $(hostname)' | grep -x fw-a")
          # commit applied live: the running firewall (/run) binds eth0.
          machine.succeed("grep -q eth0 /run/sentinel/velstra.toml")
          # save persisted to the boot config (/var/lib).
          machine.succeed("grep -q eth0 /var/lib/sentinel/appliance.toml")
          machine.wait_for_unit("velstra.service")

          # Operational `show` (VyOS-style) works from the plain shell.
          machine.succeed("sentinel show interfaces | grep -q eth0")
          machine.succeed("sentinel show config | grep -q fw-a")

          # Reboot persistence: re-running boot apply re-asserts the hostname from
          # the persisted config (simulates a reboot without a full restart).
          machine.succeed("hostname scratch")
          machine.succeed("systemctl restart sentinel-boot.service")
          machine.succeed("hostname | grep -x fw-a")
        '';
      };
    };
}
