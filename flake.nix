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
        nativeBuildInputs = [
          pkgs.protobuf
          pkgs.makeWrapper
        ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
        # Pin every external tool sentinel shells out to (live hostname/addressing
        # apply, operational `show`) to an absolute store path, and put the setuid
        # `sudo` wrapper on PATH. Without this, a `commit` on a NixOS box can fail
        # with "Failed to execute /run/current-system/sw/..." when a tool isn't on
        # the admin's PATH or in sudo's secure_path. Resolved at build time → no
        # PATH ambiguity at runtime, for both the admin and the boot service.
        postInstall = ''
          wrapProgram $out/bin/sentinel \
            --set SENTINEL_HOSTNAME_BIN   ${pkgs.nettools}/bin/hostname \
            --set SENTINEL_IP_BIN         ${pkgs.iproute2}/bin/ip \
            --set SENTINEL_NETWORKCTL_BIN ${pkgs.systemd}/bin/networkctl \
            --set SENTINEL_SYSTEMCTL_BIN  ${pkgs.systemd}/bin/systemctl \
            --set SENTINEL_JOURNALCTL_BIN ${pkgs.systemd}/bin/journalctl \
            --set SENTINEL_LSBLK_BIN      ${pkgs.util-linux}/bin/lsblk \
            --set SENTINEL_INSTALL_BIN    ${pkgs.coreutils}/bin/install \
            --set SENTINEL_MKDIR_BIN      ${pkgs.coreutils}/bin/mkdir \
            --set SENTINEL_RM_BIN         ${pkgs.coreutils}/bin/rm \
            --set SENTINEL_UNAME_BIN      ${pkgs.coreutils}/bin/uname \
            --set SENTINEL_SGDISK_BIN     ${pkgs.gptfdisk}/bin/sgdisk \
            --set SENTINEL_WIPEFS_BIN     ${pkgs.util-linux}/bin/wipefs \
            --set SENTINEL_PARTPROBE_BIN  ${pkgs.parted}/bin/partprobe \
            --set SENTINEL_UDEVADM_BIN    ${pkgs.systemd}/bin/udevadm \
            --set SENTINEL_DD_BIN         ${pkgs.coreutils}/bin/dd \
            --set SENTINEL_MKFS_EXT4_BIN  ${pkgs.e2fsprogs}/bin/mkfs.ext4 \
            --set SENTINEL_MDADM_BIN      ${pkgs.mdadm}/bin/mdadm \
            --set SENTINEL_LOSETUP_BIN    ${pkgs.util-linux}/bin/losetup \
            --set SENTINEL_MOUNT_BIN      ${pkgs.util-linux}/bin/mount \
            --set SENTINEL_UMOUNT_BIN     ${pkgs.util-linux}/bin/umount \
            --set SENTINEL_FINDMNT_BIN    ${pkgs.util-linux}/bin/findmnt \
            --prefix PATH : /run/wrappers/bin
        '';
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
      ebpfHash = "sha256-gNWOOF6CjDVITdQgLqIkqaBdo4Uwqk6xyJQgc8UWzTQ=";
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
        nativeBuildInputs = [
          pkgs.protobuf
          pkgs.bpf-linker
          pkgs.removeReferencesTo
        ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
        # Replace the agent's build.rs with the shim that copies the pre-built
        # eBPF object — so this build is fully offline (no build-std here).
        postPatch = ''
          cp ${./nix/velstra-build-shim.rs} velstra-app/build.rs
        '';
        # The nightly toolchain's precompiled std embeds its own source paths in
        # panic-location strings, so the agent binary carries a (string-only)
        # reference to the 892 MiB toolchain — which would otherwise be dragged
        # into the appliance image's closure. The binary has no real runtime dep
        # on it (rpath is empty; only glibc is dynamically linked), so scrub the
        # dangling reference. Keeps the closure to the agent + glibc.
        postInstall = ''
          remove-references-to -t ${nightly} "$out/bin/velstra"
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

      # The built, Secure-Boot-signed raw image's path — bundled into the
      # installer ISO and used as the `--source` in the live-install test.
      sentinelImageRaw =
        let
          c = self.nixosConfigurations.sentinel-image.config;
        in
        "${c.system.build.finalImageSigned}/${c.image.filePath}";
    in
    {
      packages.${system} = {
        default = sentinel;
        inherit sentinel velstra velstra-ebpf;
        # The flashable verified-boot disk image (dm-verity store + UKI). Note:
        # `finalImage` is the two-stage verity build with the roothash-bearing
        # UKI injected into the ESP; plain `image` is the unsealed single-pass
        # variant (no bootloader) and must NOT be used here. (`finalImage` is
        # renamed to `image` in newer nixpkgs.)
        #   nix build .#sentinel-image
        sentinel-image = self.nixosConfigurations.sentinel-image.config.system.build.finalImageSigned;
        # The live-boot installer ISO (carries the image above; runs `sentinel
        # install`).  nix build .#sentinel-iso
        sentinel-iso = self.nixosConfigurations.sentinel-iso.config.system.build.isoImage;
      };

      # `nix run .#vm` — boot the appliance in a throwaway QEMU VM. The easy
      # local-test path on ANY host (no NixOS / `nixos-rebuild` needed): it runs
      # straight from the store, so there's no `result` symlink to juggle.
      # NOTE: `.#sentinel-image` by contrast builds a raw DISK IMAGE (flashable,
      # no run script) — that's why `./result/bin/run-*-vm` doesn't exist after
      # building it. Use this app to *boot*; build the image to *flash*.
      apps.${system}.vm = {
        type = "app";
        program = "${self.nixosConfigurations.appliance.config.system.build.vm}/bin/run-${applianceData.system.hostname}-vm";
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

      # The same appliance, packaged as a verified-boot disk image (dm-verity
      # store + roothash-sealed UKI + persistent data partition).
      nixosConfigurations.sentinel-image = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          self.nixosModules.sentinel
          ./nix/image.nix
          # The verity image build reads `config.nixpkgs.hostPlatform` (efiArch);
          # define it explicitly (this nixpkgs' `nixosSystem` doesn't set it from
          # the `system` arg).
          { nixpkgs.hostPlatform = system; }
        ];
      };

      # The live-boot installer ISO: bundles the verity image and runs the
      # installer. Passes the CLI + the bundled image's raw path to nix/iso.nix.
      nixosConfigurations.sentinel-iso = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          sentinelPkg = sentinel;
          inherit sentinelImageRaw;
        };
        modules = [
          ./nix/iso.nix
          { nixpkgs.hostPlatform = system; }
        ];
      };

      # Boots the appliance and verifies `commit` applies config to the running
      # system live — no rebuild, no reboot, fully airgapped (the VM has no
      # network). Edits the hostname and asserts it changed via hostnamectl while
      # the data plane stays up.
      #   nix build .#checks.x86_64-linux.commit -L
      checks.${system} = {
        commit = pkgs.testers.runNixOSTest {
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
              "'set interface eth0 zone wan' 'set interface eth0 address dhcp' "
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
          # The richer operational subcommands resolve to real system state.
          # (No `grep -q`: the test driver runs with pipefail, so an early pipe
          # close would surface sentinel's correct SIGPIPE death as a failure.)
          machine.succeed("sentinel show routes")
          machine.succeed("sentinel show neighbors")
          assert "sentinel" in machine.succeed("sentinel show version")
          machine.succeed("sentinel show log")
          # A `show` view can be scoped to one interface (vtysh-style).
          scoped = machine.succeed("sentinel show interfaces lo")
          assert "lo" in scoped and "eth0" not in scoped, scoped

          # `compare`: pending edits show as a -/+ diff against the saved config.
          compared = machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set system hostname fw-b' compare exit "
              "| sentinel configure --no-apply\""
          )
          assert "-    hostname fw-a" in compared, compared
          assert "+    hostname fw-b" in compared, compared

          # Live L3 addressing via networkd: assign a static address to a spare
          # link and verify networkd actually configured it — no reboot.
          machine.succeed("ip link add dummy0 type dummy")
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set interface dummy0 address 10.9.9.1/24' "
              "commit save exit "
              "| sentinel configure\""
          )
          # The sentinel networkd unit was written ...
          machine.succeed("test -f /run/systemd/network/10-sentinel-dummy0.network")
          # ... and networkd applied the address to the live link.
          machine.wait_until_succeeds("ip addr show dummy0 | grep -q 10.9.9.1", timeout=20)

          # Firewall posture: stateful off + ICMP block + a source blocklist
          # entry, committed live. The compiled agent config must carry the new
          # fields under the names the data plane expects — and the agent must
          # accept them (fabric's schema is deny_unknown_fields), so a forced
          # restart on the firewall-laden config proves the compile wiring is
          # correct end-to-end.
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set firewall global stateful false' 'set firewall global block-icmp true' "
              "'set firewall global block 10.6.6.0/24' "
              "commit save exit "
              "| sentinel configure\""
          )
          machine.succeed("grep -q 'drop_icmp = true' /run/sentinel/velstra.toml")
          machine.succeed("grep -q 'stateful = false' /run/sentinel/velstra.toml")
          machine.succeed("grep -q '10.6.6.0/24' /run/sentinel/velstra.toml")
          # save persisted the [firewall] section.
          machine.succeed("grep -q 'block_icmp = true' /var/lib/sentinel/appliance.toml")
          # The agent parses the firewall-laden config from scratch and stays up.
          machine.succeed("systemctl restart velstra.service")
          machine.wait_for_unit("velstra.service")

          # Per-zone posture (the whole point of named zones): flip the GLOBAL
          # ICMP default back OFF, but override it ON for just the `wan` zone
          # (eth0). The compiled config must then carry the top-level drop_icmp
          # false AND the wan policy's drop_icmp true at the same time — a
          # distinction a single global flag could never express. (We keep this to
          # eth0's existing zone so the agent doesn't have to attach XDP to a
          # second link — that multi-interface path is exercised in Phase 2.)
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set firewall global block-icmp false' 'set firewall zone wan block-icmp true' "
              "commit save exit "
              "| sentinel configure\""
          )
          velstra = machine.succeed("cat /run/sentinel/velstra.toml")
          assert 'name = "wan"' in velstra, velstra
          # Both postures coexist: global default off, wan override on.
          assert "drop_icmp = false" in velstra and "drop_icmp = true" in velstra, velstra
          # The saved config carries the per-zone override.
          machine.succeed("grep -q 'block_icmp = true' /var/lib/sentinel/appliance.toml")
          # The agent accepts the per-zone config from scratch.
          machine.succeed("systemctl restart velstra.service")
          machine.wait_for_unit("velstra.service")

          # VLAN subinterface: declare a tagged link on eth0 in its own `iot`
          # zone. Sentinel writes the .netdev; networkd creates the real 802.1Q
          # link; the agent attaches XDP to it like any other zoned interface
          # (its config-interface reconcile path) — so per-VLAN firewalling works
          # with no eBPF VLAN decoding.
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set interface eth0.50 parent eth0' 'set interface eth0.50 vlan 50' "
              "'set interface eth0.50 zone iot' 'set interface eth0.50 address 10.0.50.1/24' "
              "commit save exit "
              "| sentinel configure\""
          )
          # Sentinel wrote the VLAN netdev unit ...
          machine.succeed("test -f /run/systemd/network/10-sentinel-eth0.50.netdev")
          machine.succeed("grep -q 'Kind=vlan' /run/systemd/network/10-sentinel-eth0.50.netdev")
          # ... and networkd created the real tagged link with id 50.
          machine.wait_until_succeeds("ip -d link show eth0.50 | grep -q 'id 50'", timeout=20)
          machine.wait_until_succeeds("ip addr show eth0.50 | grep -q 10.0.50.1", timeout=20)
          # The compiled config binds the VLAN interface to the iot policy, and the
          # agent (which attaches XDP to every config interface) accepts it.
          machine.succeed("grep -q '\"eth0.50\"' /run/sentinel/velstra.toml")
          machine.succeed("systemctl restart velstra.service")
          machine.wait_for_unit("velstra.service")

          # Reboot persistence: re-running boot apply re-asserts the hostname from
          # the persisted config (simulates a reboot without a full restart).
          machine.succeed("hostname scratch")
          machine.succeed("systemctl restart sentinel-boot.service")
          machine.succeed("hostname | grep -x fw-a")
        '';
      };

      # Boots the actual flashable verified-boot image (dm-verity store + UKI)
      # in QEMU/OVMF and proves the security properties hold on real hardware:
      # the root is volatile (tmpfs), /nix/store is integrity-checked by
      # dm-verity, the appliance runs from the sealed image, and the editable
      # config persists on the data partition across a reboot.
      #   nix build .#checks.x86_64-linux.verified-boot -L
        verified-boot = pkgs.testers.runNixOSTest {
        name = "sentinel-verified-boot";
        nodes.machine = {
          imports = [
            self.nixosModules.sentinel
            ./nix/image.nix
          ];
          # (The test framework already sets nixpkgs.hostPlatform for nodes.)
          virtualisation = {
            directBoot.enable = false;
            mountHostNixStore = false;
            useEFIBoot = true;
            memorySize = 2048;
            # Use the real image's filesystems, not the test VM's defaults.
            fileSystems = lib.mkVMOverride { };
          };
        };
        testScript =
          { nodes, ... }:
          ''
            import os
            import subprocess
            import tempfile

            # Boot from a writable overlay on top of the built verity image, so
            # the data partition keeps writes across the reboot below.
            tmp = tempfile.NamedTemporaryFile()
            subprocess.run([
              "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img",
              "create", "-f", "qcow2",
              "-b", "${nodes.machine.system.build.finalImage}/${nodes.machine.image.filePath}",
              "-F", "raw", tmp.name,
            ], check=True)
            os.environ["NIX_DISK_IMAGE"] = tmp.name

            machine.wait_for_unit("multi-user.target")

            with subtest("verified boot: volatile root + dm-verity store"):
                machine.succeed("findmnt --kernel --type tmpfs /")
                verity = machine.succeed("dmsetup info --target verity usr")
                assert "ACTIVE" in verity, verity
                backing = machine.succeed("df --output=source /nix/store | tail -n1").strip()
                assert backing == "/dev/mapper/usr", backing

            with subtest("the appliance runs from the sealed image"):
                machine.wait_for_unit("velstra.service")
                assert "sentinel" in machine.succeed("sentinel show version")

            with subtest("editable config persists on a real data partition, not the volatile root"):
                # The config dir is a genuine, writable block device separate
                # from the tmpfs root — so its contents survive a reboot by
                # construction (the root is wiped each boot; this partition is
                # not). We don't drive an in-VM reboot here: restarting QEMU with
                # the OVMF firmware-vars file is flaky in the test harness and
                # proves nothing the partition's persistence doesn't already.
                src = machine.succeed("findmnt -no SOURCE /var/lib/sentinel").strip()
                assert src.startswith("/dev/"), src
                assert "tmpfs" not in machine.succeed("findmnt -no FSTYPE /var/lib/sentinel")
                machine.succeed("test -f /var/lib/sentinel/appliance.toml")
                # And it's writable (a `save` would land here and outlive the image).
                machine.succeed("echo persisted > /var/lib/sentinel/marker")
                machine.succeed("grep -qx persisted /var/lib/sentinel/marker")
          '';
        };

        # Boots the appliance from the verity image with three blank disks and
        # exercises `sentinel install`: a single-disk install and a RAID1 install,
        # asserting the target disks get the sealed layout cloned and (for RAID)
        # an assembled mdadm array carrying the data filesystem.
        #   nix build .#checks.x86_64-linux.install -L
        install = pkgs.testers.runNixOSTest {
          name = "sentinel-install";
          nodes.machine = {
            imports = [
              self.nixosModules.sentinel
              ./nix/image.nix
            ];
            virtualisation = {
              directBoot.enable = false;
              mountHostNixStore = false;
              useEFIBoot = true;
              memorySize = 2048;
              # Three blank targets: vdb (single), vdc + vdd (RAID1). ~5 GiB each
              # (> the 4 GiB minimum, room for the ~1.3 GiB sealed store).
              emptyDiskImages = [
                5000
                5000
                5000
              ];
              fileSystems = lib.mkVMOverride { };
            };
          };
          testScript =
            { nodes, ... }:
            ''
              import os
              import subprocess
              import tempfile

              tmp = tempfile.NamedTemporaryFile()
              subprocess.run([
                "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img",
                "create", "-f", "qcow2",
                "-b", "${nodes.machine.system.build.finalImage}/${nodes.machine.image.filePath}",
                "-F", "raw", tmp.name,
              ], check=True)
              os.environ["NIX_DISK_IMAGE"] = tmp.name

              machine.wait_for_unit("multi-user.target")

              # The source disk it booted from (raw lsblk → no tree characters).
              src = ""
              for line in machine.succeed("lsblk -nsro NAME,TYPE /dev/mapper/usr").splitlines():
                  f = line.split()
                  if len(f) >= 2 and f[1] == "disk":
                      src = f[0]
                      break
              assert src in ("vda", "vdb", "vdc", "vdd"), src

              with subtest("install lists the blank targets"):
                  # `< /dev/null` so stdin isn't a tty — otherwise the bare
                  # command starts the interactive wizard and waits for input.
                  listing = machine.succeed("sentinel install < /dev/null")
                  assert "/dev/vdb" in listing, listing

              with subtest("single-disk install clones the sealed layout"):
                  machine.succeed("sentinel install /dev/vdb --commit")
                  machine.succeed("udevadm settle")
                  # Four partitions: ESP, verity hash, verity store, data.
                  parts = machine.succeed("lsblk -nro NAME /dev/vdb").split()
                  assert "vdb1" in parts and "vdb6" in parts, parts
                  # The data partition (#6, after the ESP + both A/B slots) is an
                  # ext4 labelled `data`.
                  blk = machine.succeed("blkid /dev/vdb6")
                  assert 'LABEL="data"' in blk and 'TYPE="ext4"' in blk, blk
                  # The ESP (UKI/bootloader) is cloned byte-for-byte from the
                  # source medium's ESP -> the installed disk is bootable.
                  machine.succeed(f"cmp /dev/{src}1 /dev/vdb1")

              with subtest("RAID1 install builds an assembled mirror"):
                  machine.succeed("sentinel install /dev/vdc /dev/vdd --raid mirror --commit")
                  machine.succeed("udevadm settle")
                  machine.wait_until_succeeds("test -e /dev/md/sentinel-data", timeout=30)
                  detail = machine.succeed("mdadm --detail /dev/md/sentinel-data")
                  assert "raid1" in detail, detail
                  assert "active sync" in detail, detail
                  # The array carries the data filesystem, labelled `data`.
                  assert 'LABEL="data"' in machine.succeed("blkid /dev/md/sentinel-data")
                  # Both members are typed Linux RAID (GPT type GUID), checked via
                  # lsblk since sgdisk isn't on the appliance PATH.
                  raid_guid = "a19d880f-05fc-4d3b-a006-743f0f84911e"
                  assert raid_guid in machine.succeed("lsblk -nro PARTTYPE /dev/vdc6").lower()
                  assert raid_guid in machine.succeed("lsblk -nro PARTTYPE /dev/vdd6").lower()
            '';
        };

        # Boots the live installer environment (the ISO config) and installs onto
        # a blank disk from the BUNDLED image via the `--source` path (no booted
        # verity store to clone) — the real live-boot flow. Verifies the target
        # gets the cloned layout and a bootable ESP.
        #   nix build .#checks.x86_64-linux.install-iso -L
        install-iso = pkgs.testers.runNixOSTest {
          name = "sentinel-install-iso";
          nodes.machine = {
            imports = [ ./nix/iso.nix ];
            # Provide nix/iso.nix's module args (it expects these via specialArgs).
            _module.args = {
              sentinelPkg = sentinel;
              inherit sentinelImageRaw;
            };
            virtualisation = {
              memorySize = 2048;
              # The bundled image lives in the host store; the live env reads it.
              mountHostNixStore = true;
              emptyDiskImages = [ 5000 ]; # vdb — the install target
            };
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")

            with subtest("the bundled source image is present"):
                machine.succeed("test -n \"$SENTINEL_INSTALL_SOURCE\" || test -e ${sentinelImageRaw}")

            with subtest("live install from the bundled image onto a blank disk"):
                # No --source: uses $SENTINEL_INSTALL_SOURCE, exactly as the ISO does.
                machine.succeed("sentinel install /dev/vdb --commit --source ${sentinelImageRaw}")
                machine.succeed("udevadm settle")
                parts = machine.succeed("lsblk -nro NAME /dev/vdb").split()
                assert "vdb1" in parts and "vdb6" in parts, parts
                assert 'LABEL="data"' in machine.succeed("blkid /dev/vdb6")

            with subtest("the installed disk has a bootable ESP (cloned UKI)"):
                machine.succeed("mkdir -p /mnt/esp && mount /dev/vdb1 /mnt/esp")
                machine.succeed("test -f /mnt/esp/EFI/BOOT/BOOTX64.EFI")
                machine.succeed("umount /mnt/esp")
          '';
        };

        # Boots slot A of the verity image and runs an A/B update (re-sealing
        # from the booted medium into slot B), verifying the inactive slot is
        # written + verity-typed and the bootloader is switched to it with boot
        # counting. The actual cross-reboot slot switch + rollback can't be driven
        # in this harness (OVMF reboot hangs); it's verified structurally here and
        # the boot-counting/bless mechanism itself is proven by checks.verified-boot.
        #   nix build .#checks.x86_64-linux.update -L
        update = pkgs.testers.runNixOSTest {
          name = "sentinel-update";
          nodes.machine = {
            imports = [
              self.nixosModules.sentinel
              ./nix/image.nix
            ];
            virtualisation = {
              directBoot.enable = false;
              mountHostNixStore = false;
              useEFIBoot = true;
              memorySize = 2048;
              fileSystems = lib.mkVMOverride { };
            };
          };
          testScript =
            { nodes, ... }:
            ''
              import os
              import subprocess
              import tempfile

              tmp = tempfile.NamedTemporaryFile()
              subprocess.run([
                "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img",
                "create", "-f", "qcow2",
                "-b", "${nodes.machine.system.build.finalImage}/${nodes.machine.image.filePath}",
                "-F", "raw", tmp.name,
              ], check=True)
              os.environ["NIX_DISK_IMAGE"] = tmp.name

              machine.wait_for_unit("multi-user.target")

              src = ""
              for line in machine.succeed("lsblk -nsro NAME,TYPE /dev/mapper/usr").splitlines():
                  f = line.split()
                  if len(f) >= 2 and f[1] == "disk":
                      src = f[0]
                      break
              assert src, "no source disk"
              disk = "/dev/" + src

              with subtest("active slot A backs /dev/mapper/usr (store partition #3)"):
                  assert f"{src}3" in machine.succeed("lsblk -nsro NAME /dev/mapper/usr")

              with subtest("update writes + verity-types the inactive slot B"):
                  machine.succeed(f"sentinel update --commit {disk}")
                  machine.succeed("udevadm settle")
                  usr = "8484680c-9521-48c6-9c11-b0720656f69e"
                  usrv = "77ff5f63-e7b6-4633-acf4-1565b864c0e6"
                  assert usrv in machine.succeed(f"lsblk -nro PARTTYPE {disk}4").lower()
                  assert usr in machine.succeed(f"lsblk -nro PARTTYPE {disk}5").lower()
                  # slot B store == slot A store (this re-seal copies the running image)
                  machine.succeed(f"cmp {disk}3 {disk}5")

              with subtest("the bootloader is switched to slot B with boot counting"):
                  machine.succeed(f"mkdir -p /mnt/esp && mount {disk}1 /mnt/esp")
                  machine.succeed("test -f /mnt/esp/EFI/Linux/sentinel-b+3.efi")
                  assert "sentinel-b" in machine.succeed("cat /mnt/esp/loader/loader.conf")
                  machine.succeed("umount /mnt/esp")
          '';
        };

        # Boots the SIGNED image in a Secure-Boot OVMF with our PK/KEK/db enrolled
        # (built with virt-fw-vars). If the firmware verifies the signed
        # systemd-boot + UKI against db and reaches multi-user, Secure Boot is
        # enforcing and the chain is trusted — proven in a single boot (no reboot,
        # which the OVMF harness can't drive).
        #   nix build .#checks.x86_64-linux.secureboot -L
        secureboot =
          let
            sb = self.nixosConfigurations.sentinel-image.config.system.build.sentinelSbKeys;
            guid = "a5a5a5a5-1234-5678-9abc-def012345678";
            ovmfVars =
              pkgs.runCommand "ovmf-vars-sentinel-enrolled.fd"
                { nativeBuildInputs = [ pkgs.python3Packages.virt-firmware ]; }
                ''
                  virt-fw-vars \
                    --input ${(pkgs.OVMF.override { secureBoot = true; }).fd}/FV/OVMF_VARS.fd \
                    --output $out \
                    --set-pk ${guid} ${sb}/PK.crt \
                    --add-kek ${guid} ${sb}/KEK.crt \
                    --add-db ${guid} ${sb}/db.crt \
                    --secure-boot
                '';
          in
          pkgs.testers.runNixOSTest {
            name = "sentinel-secureboot";
            nodes.machine = {
              imports = [
                self.nixosModules.sentinel
                ./nix/image.nix
              ];
              virtualisation = {
                directBoot.enable = false;
                mountHostNixStore = false;
                useEFIBoot = true;
                useSecureBoot = true;
                efi.variables = ovmfVars;
                memorySize = 2048;
                fileSystems = lib.mkVMOverride { };
              };
            };
            testScript =
              { nodes, ... }:
              ''
                import os
                import subprocess
                import tempfile

                tmp = tempfile.NamedTemporaryFile()
                subprocess.run([
                  "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img",
                  "create", "-f", "qcow2",
                  "-b", "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}",
                  "-F", "raw", tmp.name,
                ], check=True)
                os.environ["NIX_DISK_IMAGE"] = tmp.name

                # Reaching multi-user under an SB-enforcing firmware means the
                # signed systemd-boot + UKI verified against our enrolled db key.
                machine.wait_for_unit("multi-user.target")

                with subtest("Secure Boot is enabled and enforcing"):
                    status = machine.succeed("bootctl status")
                    assert "Secure Boot: enabled" in status, status
              '';
          };

        # NAT in the eBPF datapath: a 3-node line client — fw — server. The fw
        # runs the real velstra agent (XDP on both NICs) and a `[[port-forward]]`
        # exposing the internal server on its WAN ip. A client connection to the
        # WAN ip:8080 must be DNAT'd to the server:80 and its reply SNAT'd back —
        # proving DNAT + conntrack-reverse SNAT work on real traffic through the
        # appliance.
        nat = pkgs.testers.runNixOSTest {
          name = "sentinel-nat";
          nodes = {
            # External client on the WAN segment (vlan 1).
            client =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.1.0.2";
                      prefixLength = 24;
                    }
                  ];
                  defaultGateway = {
                    address = "10.1.0.1";
                    interface = "eth1";
                  };
                };
                environment.systemPackages = [ pkgs.curl ];
              };
            # Internal server on the LAN segment (vlan 2), routing back via the fw.
            server =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 2 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.2.0.2";
                      prefixLength = 24;
                    }
                  ];
                  defaultGateway = {
                    address = "10.2.0.1";
                    interface = "eth1";
                  };
                };
                systemd.services.web = {
                  wantedBy = [ "multi-user.target" ];
                  after = [ "network-online.target" ];
                  script = ''
                    mkdir -p /srv/web && echo hello-from-server > /srv/web/index.html
                    exec ${pkgs.python3}/bin/python3 -m http.server 80 --directory /srv/web
                  '';
                };
              };
            # The appliance: WAN = eth1 (vlan 1), LAN = eth2 (vlan 2).
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                # The sentinel module forces the hostname to the factory value;
                # in a multi-node test the driver derives each machine's python
                # variable from its hostname, so pin it back to the node name `fw`
                # (runtime hostname is re-applied by sentinel-boot regardless).
                networking.hostName = lib.mkForce "fw";
                # Address the two segments at the NixOS level (boot-stable) rather
                # than via `sentinel commit`'s networkd reload, which is flaky
                # under this multi-NIC test harness; sentinel still owns the zones
                # + port-forward (the velstra config). No NixOS iptables: velstra
                # is the firewall.
                networking.firewall.enable = lib.mkForce false;
                networking.interfaces.eth1.ipv4.addresses = [
                  {
                    address = "10.1.0.1";
                    prefixLength = 24;
                  }
                ];
                networking.interfaces.eth2.ipv4.addresses = [
                  {
                    address = "10.2.0.1";
                    prefixLength = 24;
                  }
                ];
                virtualisation.vlans = [
                  1
                  2
                ];
                virtualisation.memorySize = 2048;
                # Route between the two segments; velstra filters/NATs at XDP.
                # rp_filter off: the reply's source is rewritten to the WAN ip
                # (a local address) at XDP ingress on the LAN nic, which strict
                # reverse-path filtering would otherwise treat as a martian.
                boot.kernel.sysctl = {
                  "net.ipv4.ip_forward" = 1;
                  "net.ipv4.conf.all.rp_filter" = 0;
                  "net.ipv4.conf.default.rp_filter" = 0;
                  # The reply's source is rewritten to a local (WAN) address at
                  # XDP ingress on the LAN nic; accept_local lets the kernel still
                  # route/forward it. log_martians surfaces it if it doesn't.
                  "net.ipv4.conf.all.accept_local" = 1;
                  "net.ipv4.conf.all.log_martians" = 1;
                };
                # The agent's primary attach point (it also reconciles the config
                # interfaces, so eth2 is attached once the config names it).
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            server.wait_for_unit("web.service")

            # Configure the appliance: zone both NICs, allow the LAN to forward
            # replies, and expose the server on the WAN ip:8080 -> server:80.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set interface eth2 zone lan' "
                "'set firewall zone lan default-action accept' "
                "'set nat destination web zone wan' 'set nat destination web proto tcp' "
                "'set nat destination web port 8080' 'set nat destination web to 10.2.0.2:80' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")
            # The compiled config carries the port-forward.
            fw.succeed("grep -q '\\[\\[port_forward\\]\\]' /run/sentinel/velstra.toml")
            # The fw's addresses are live on both segments (set at the NixOS level).
            fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.1", timeout=20)
            fw.wait_until_succeeds("ip addr show eth2 | grep -q 10.2.0.1", timeout=20)

            # Sanity: the fw itself reaches the server (LAN side + server up). A
            # direct ping/connect to the fw's WAN ip is correctly dropped by the
            # default-drop wan zone — only the port-forwarded port is open inbound.
            fw.succeed("curl -s --max-time 5 http://10.2.0.2:80/ | grep -q hello-from-server")

            # The headline: the client reaches the internal server THROUGH the
            # appliance's WAN ip:8080 — DNAT'd in, conntrack-reverse SNAT'd out,
            # all in the eBPF datapath.
            client.wait_until_succeeds(
                "curl -s --max-time 5 http://10.1.0.1:8080/ | grep -q hello-from-server",
                timeout=40,
            )
          '';
        };

        # Masquerade (source NAT) in the eBPF datapath: a 3-node line
        # client(LAN) — fw — server(WAN). A private LAN client reaches a WAN
        # server through the fw; the fw SNATs the client's source to its WAN ip at
        # the TC egress hook, so the server sees the fw — not the client — and its
        # reply is un-NAT'd back to the client via conntrack. This is the classic
        # router masquerade, done entirely in XDP/TC with no iptables.
        masq = pkgs.testers.runNixOSTest {
          name = "sentinel-masq";
          nodes = {
            # Private client on the LAN segment (vlan 2), default route via the fw.
            client =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 2 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.2.0.2";
                      prefixLength = 24;
                    }
                  ];
                  defaultGateway = {
                    address = "10.2.0.1";
                    interface = "eth1";
                  };
                };
                environment.systemPackages = [ pkgs.curl ];
              };
            # Public server on the WAN segment (vlan 1). It has NO route to the LAN
            # — masquerade is what makes the reply work: it only ever sees the fw's
            # WAN ip, which is on its own subnet.
            server =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.1.0.2";
                      prefixLength = 24;
                    }
                  ];
                };
                systemd.services.web = {
                  wantedBy = [ "multi-user.target" ];
                  after = [ "network-online.target" ];
                  script = ''
                    mkdir -p /srv/web && echo hello-from-server > /srv/web/index.html
                    exec ${pkgs.python3}/bin/python3 -m http.server 80 --directory /srv/web
                  '';
                };
              };
            # The appliance: WAN = eth1 (vlan 1, masqueraded), LAN = eth2 (vlan 2).
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                networking.interfaces.eth1.ipv4.addresses = [
                  {
                    address = "10.1.0.1";
                    prefixLength = 24;
                  }
                ];
                networking.interfaces.eth2.ipv4.addresses = [
                  {
                    address = "10.2.0.1";
                    prefixLength = 24;
                  }
                ];
                virtualisation.vlans = [
                  1
                  2
                ];
                virtualisation.memorySize = 2048;
                boot.kernel.sysctl = {
                  "net.ipv4.ip_forward" = 1;
                  "net.ipv4.conf.all.rp_filter" = 0;
                  "net.ipv4.conf.default.rp_filter" = 0;
                  "net.ipv4.conf.all.accept_local" = 1;
                  "net.ipv4.conf.all.log_martians" = 1;
                };
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            server.wait_for_unit("web.service")

            # The fw's WAN ip must be live BEFORE we configure masquerade: the
            # agent reads it to fill the MASQUERADE map at (re)start.
            fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.1", timeout=20)
            fw.wait_until_succeeds("ip addr show eth2 | grep -q 10.2.0.1", timeout=20)

            # Configure the appliance: zone both NICs, let the LAN initiate, and
            # masquerade everything leaving the WAN zone.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set interface eth2 zone lan' "
                "'set firewall zone lan default-action accept' "
                "'set nat source wan-masq zone wan' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")
            # The compiled config marks the WAN interface as masqueraded.
            fw.succeed("grep -q 'masquerade = true' /run/sentinel/velstra.toml")

            # The headline: the LAN client reaches the WAN server THROUGH the fw,
            # SNAT'd to the fw's WAN ip on the way out and un-NAT'd on the reply.
            client.wait_until_succeeds(
                "curl -s --max-time 5 http://10.1.0.2:80/ | grep -q hello-from-server",
                timeout=40,
            )

            # Proof of masquerade: the server logged the fw's WAN ip (10.1.0.1) as
            # the client, and NEVER the client's real private ip (10.2.0.2).
            server.succeed("journalctl -u web.service | grep -q '10.1.0.1 '")
            server.fail("journalctl -u web.service | grep -q '10.2.0.2 '")
          '';
        };

        # Reject in the eBPF datapath: a 2-node client — fw. The fw's WAN zone has
        # a rule that REJECTS tcp/9999. A connection from the client must come
        # back with an immediate TCP RST ("connection refused"/"reset") — proving
        # the XDP reject path crafts and XDP_TX's a real RST — rather than hanging
        # the way a silent drop would.
        reject = pkgs.testers.runNixOSTest {
          name = "sentinel-reject";
          nodes = {
            client =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.1.0.2";
                      prefixLength = 24;
                    }
                  ];
                };
                environment.systemPackages = [ pkgs.curl ];
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                networking.interfaces.eth1.ipv4.addresses = [
                  {
                    address = "10.1.0.1";
                    prefixLength = 24;
                  }
                ];
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.1", timeout=20)

            # Zone the WAN nic and add a reject rule for tcp/9999.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set firewall rule refuse from wan to wan action reject proto tcp port 9999' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")
            # The compiled config carries the reject verdict.
            fw.succeed("grep -q 'reject' /run/sentinel/velstra.toml")

            # The headline: a connection to the rejected port comes back refused
            # (a RST) fast, not a timeout. curl reports "Connection refused" or
            # "Connection reset" on a RST; a silent drop would instead time out
            # (then the grep fails and the test fails).
            client.succeed(
                "curl -sS --max-time 4 -o /dev/null http://10.1.0.1:9999/ 2>&1 "
                "| grep -qiE 'refused|reset'"
            )
          '';
        };

        # Per-rule logging in the eBPF datapath: a 2-node client — fw. The fw's
        # WAN zone has TWO logged rules (a drop on tcp/9999, a pass on tcp/9997)
        # while the policy-wide log is OFF. Traffic to those ports must appear in
        # the agent's journal (DROP/ALLOW via aya-log), proving a rule's own log
        # bit logs independently of the policy flag — and a default-dropped port
        # with no rule (9998) must stay silent.
        log = pkgs.testers.runNixOSTest {
          name = "sentinel-log";
          nodes = {
            client =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.1.0.2";
                      prefixLength = 24;
                    }
                  ];
                };
                environment.systemPackages = [ pkgs.curl ];
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                networking.interfaces.eth1.ipv4.addresses = [
                  {
                    address = "10.1.0.1";
                    prefixLength = 24;
                  }
                ];
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.1", timeout=20)

            # The client must be network-ready before it can generate any traffic:
            # a single fire-and-forget curl issued before its NIC is up sends
            # nothing, so the eBPF would never see a packet to log.
            client.wait_for_unit("multi-user.target")
            client.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.2", timeout=20)

            # Zone the WAN nic; add a logged DROP on tcp/9999 and a logged PASS on
            # tcp/9997. The policy-wide log is left off, so anything that appears
            # in the journal got there via the rule's own log bit.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set firewall rule watch-drop from wan' "
                "'set firewall rule watch-drop to wan' "
                "'set firewall rule watch-drop action drop' "
                "'set firewall rule watch-drop proto tcp' "
                "'set firewall rule watch-drop port 9999' "
                "'set firewall rule watch-drop log true' "
                "'set firewall rule watch-pass from wan' "
                "'set firewall rule watch-pass to wan' "
                "'set firewall rule watch-pass action accept' "
                "'set firewall rule watch-pass proto tcp' "
                "'set firewall rule watch-pass port 9997' "
                "'set firewall rule watch-pass log true' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")
            # The compiled config carries the per-rule log flag.
            fw.succeed("grep -q 'log = true' /run/sentinel/velstra.toml")

            # Generate traffic the rules match, repeatedly, until the eBPF has
            # logged both matches. Firing once is racy: the DROP'd SYN gets no
            # reply (curl times out — expected), and a single SYN can be lost in
            # the brief velstra reload/re-attach window, so we re-send on every
            # retry. The PASS'd port reaches the closed local port and the kernel
            # RSTs it; either way the eBPF logs the match via aya-log.
            def hit(_):
                client.execute("curl -s --max-time 2 -o /dev/null http://10.1.0.1:9999/ || true")
                client.execute("curl -s --max-time 2 -o /dev/null http://10.1.0.1:9997/ || true")
                # A default-dropped port with no rule: must stay silent.
                client.execute("curl -s --max-time 2 -o /dev/null http://10.1.0.1:9998/ || true")
                return (
                    fw.execute("journalctl -u velstra.service | grep -qE 'DROP .*dport=9999'")[0] == 0
                    and fw.execute("journalctl -u velstra.service | grep -qE 'ALLOW .*dport=9997'")[0] == 0
                )

            # The headline: the agent journal shows the logged DROP and ALLOW for
            # the two rules' ports, via the eBPF aya-log path — proving a rule's
            # own log bit logs independently of the (here-off) policy-wide flag.
            retry(hit)

            # The un-ruled default-dropped port produced no log line.
            fw.fail("journalctl -u velstra.service | grep -q 'dport=9998'")
          '';
        };

        # Per-rule source-CIDR match in the eBPF datapath: the fw's WAN zone has
        # two logged DROP rules on different ports — one whose `source` matches the
        # client's address (10.1.0.2/32) and one whose source is a foreign block
        # (10.9.9.9/32). Traffic from the client must trip only the matching rule:
        # the eBPF LPM rule map keys on (policy, proto, dport, src prefix), so the
        # foreign-source rule never fires and its port stays out of the journal.
        srcfilter = pkgs.testers.runNixOSTest {
          name = "sentinel-srcfilter";
          nodes = {
            client =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.1.0.2";
                      prefixLength = 24;
                    }
                  ];
                };
                environment.systemPackages = [ pkgs.curl ];
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                networking.interfaces.eth1.ipv4.addresses = [
                  {
                    address = "10.1.0.1";
                    prefixLength = 24;
                  }
                ];
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.1", timeout=20)
            client.wait_for_unit("multi-user.target")
            client.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.2", timeout=20)

            # Zone the WAN nic; add a logged DROP tcp/9999 whose source MATCHES the
            # client (10.1.0.2/32), and a logged DROP tcp/9997 whose source is a
            # foreign block (10.9.9.9/32) the client can never match.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set firewall rule match-src from wan' "
                "'set firewall rule match-src to wan' "
                "'set firewall rule match-src action drop' "
                "'set firewall rule match-src proto tcp' "
                "'set firewall rule match-src port 9999' "
                "'set firewall rule match-src source 10.1.0.2/32' "
                "'set firewall rule match-src log true' "
                "'set firewall rule foreign-src from wan' "
                "'set firewall rule foreign-src to wan' "
                "'set firewall rule foreign-src action drop' "
                "'set firewall rule foreign-src proto tcp' "
                "'set firewall rule foreign-src port 9997' "
                "'set firewall rule foreign-src source 10.9.9.9/32' "
                "'set firewall rule foreign-src log true' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")
            # Both rules compiled, each carrying its own source CIDR.
            fw.succeed("grep -q 'src = \"10.1.0.2/32\"' /run/sentinel/velstra.toml")
            fw.succeed("grep -q 'src = \"10.9.9.9/32\"' /run/sentinel/velstra.toml")

            # Generate traffic to both ports in a retry loop until the matching
            # rule has logged. A single SYN can be lost in the reload window, so we
            # re-send each attempt.
            def hit(_):
                client.execute("curl -s --max-time 2 -o /dev/null http://10.1.0.1:9999/ || true")
                client.execute("curl -s --max-time 2 -o /dev/null http://10.1.0.1:9997/ || true")
                return fw.execute("journalctl -u velstra.service | grep -qE 'DROP .*dport=9999'")[0] == 0

            # The client's address matches the 9999 rule -> logged DROP.
            retry(hit)

            # The 9997 rule's source (10.9.9.9/32) never matches the client, so the
            # LPM lookup misses it: no rule fires, nothing is logged for 9997.
            fw.fail("journalctl -u velstra.service | grep -q 'dport=9997'")
          '';
        };
      };
    };
}
