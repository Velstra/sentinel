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
    # The Wren routing daemon (BGP/OSPF/IS-IS/RIP/Babel/VRRP control plane).
    # Source only — stable Rust, built with nixpkgs' rustc (no flake of its own).
    # Local checkout while wren is developed alongside; switch to
    # "github:Velstra/wren" once public. Uses wren's committed HEAD.
    wren = {
      url = "git+file:///home/mbrandt/01_repositories/wren";
      flake = false;
    };
  };

  outputs =
    { self, nixpkgs, fenix, fabric, wren }:
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
            --set SENTINEL_NFT_BIN        ${pkgs.nftables}/bin/nft \
            --set SENTINEL_SYSTEMD_RUN_BIN ${pkgs.systemd}/bin/systemd-run \
            --set SENTINEL_JOURNALCTL_BIN ${pkgs.systemd}/bin/journalctl \
            --set SENTINEL_WREN_BIN       ${wrenPkg}/bin/wren \
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

      # --- the Wren routing daemon (stable rustc; the `wren` binary) ----------
      # Pure stable Rust, no codegen/build.rs, no git deps — a plain
      # buildRustPackage over wren's committed source. The full daemon (all
      # protocols) is built via the crate's default features. The resulting
      # binary is named `wren` and serves both as the daemon and the `wren
      # show …` client against its control socket.
      wrenPkg = pkgs.rustPlatform.buildRustPackage {
        pname = "wren";
        version = "0.1.0";
        src = wren;
        cargoLock.lockFile = "${wren}/Cargo.lock";
        cargoBuildFlags = [
          "-p"
          "wren-daemon"
        ];
        # Integration/live tests need root+netns; unit tests are pure. Keep the
        # image build hermetic — the daemon is exercised by the checks.bgp VM.
        doCheck = false;
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
      ebpfHash = "sha256-MCO9Ffi1YM72dhyRFg7OSP3kDRr8nhoMBpJqaEzcTCo=";
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
        wren = wrenPkg;
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
        { pkgs, ... }:
        {
          imports = [
            ./nix/appliance.nix
            ./nix/velstra-service.nix
            ./nix/wren-service.nix
          ];
          # `sentinel` is the CLI; `ppp` provides `pppd` + its bundled `pppoe.so`
          # plugin for `type = pppoe` uplinks (roadmap C5). The plugin dir is
          # compiled into pppd's store path, so `plugin pppoe.so` resolves without
          # any search-path wiring.
          environment.systemPackages = [
            sentinel
            pkgs.ppp
          ];

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

          # The routing control plane. Config is compiled from the same appliance
          # config by the sentinel-boot service (→ /run/sentinel/wren.toml).
          services.wren = {
            enable = true;
            package = wrenPkg;
          };

          # NTP: the box always runs chrony to keep its own clock; the
          # `[services.ntp]` config layers LAN-serving (`server`/`allow`) on top
          # via a confdir drop-in that Sentinel renders to /run/sentinel/chrony.d
          # and applies with a chrony restart. tmpfiles pre-creates the dir so
          # chronyd can read it even before the first commit.
          services.chrony = {
            enable = true;
            extraConfig = "confdir /run/sentinel/chrony.d";
          };

          # DNS: systemd-resolved stays the box's own resolver (127.0.0.53);
          # dnsmasq is the LAN-facing resolver that `[services.dns]` drives via a
          # conf-dir drop-in Sentinel renders to /run/sentinel/dnsmasq.d. The base
          # config binds dnsmasq to loopback only (bind-interfaces + interface=lo)
          # so with no drop-in it never fights resolved for :53 on a real link;
          # the drop-in adds `interface=<serve-on>` to serve the LAN.
          services.dnsmasq = {
            enable = true;
            resolveLocalQueries = false;
            settings = {
              bind-interfaces = true;
              interface = "lo";
              conf-dir = "/run/sentinel/dnsmasq.d/,*.conf";
            };
          };
          # PPPoE client (roadmap C5): one templated `pppd` per `type = pppoe`
          # session. Sentinel renders the peer options to
          # /run/sentinel/ppp/peers/<name> and (re)starts `sentinel-pppoe@<name>`;
          # `%i` is the session (= the ppp link name). `pppd` runs in the
          # foreground (`nodetach`) so systemd owns its lifecycle; the rendered
          # `persist` re-dials within pppd, and `Restart=on-failure` covers a hard
          # exit. It reads the ISP credentials from /etc/ppp/{chap,pap}-secrets,
          # which the symlinks below point at Sentinel's 0600 rendered files.
          systemd.services."sentinel-pppoe@" = {
            description = "PPPoE client session %i (pppd)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.ppp}/bin/pppd file /run/sentinel/ppp/peers/%i nodetach";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };
          systemd.tmpfiles.rules = [
            "d /run/sentinel 0755 root root -"
            "d /run/sentinel/chrony.d 0755 root root -"
            "d /run/sentinel/dnsmasq.d 0755 root root -"
            # PPPoE runtime dir holds the 0600 secrets + peer options (root only).
            "d /run/sentinel/ppp 0700 root root -"
            "d /run/sentinel/ppp/peers 0755 root root -"
            # pppd's fixed credential lookup paths → Sentinel's rendered secrets.
            "d /etc/ppp 0755 root root -"
            "L+ /etc/ppp/chap-secrets - - - - /run/sentinel/ppp/chap-secrets"
            "L+ /etc/ppp/pap-secrets - - - - /run/sentinel/ppp/pap-secrets"
          ];
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

          # --- vtysh/VyOS-style CLI ------------------------------------------
          # Config mode: `edit` context makes set/delete/show relative (VyOS).
          # `edit protocols` + `set router-id …` must land on the real path and
          # compile into the wren config.
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'edit protocols' 'set router-id 10.9.9.9' 'top' "
              "commit save exit "
              "| sentinel configure\""
          )
          machine.succeed("grep -q 'router-id = \\\"10.9.9.9\\\"' /run/sentinel/wren.toml")

          # Operational mode: the word-tree show commands work — routing state
          # proxied from the wren control socket, config in config syntax.
          machine.succeed("sentinel show ip route")
          machine.succeed("sentinel show configuration | grep -q 'router-id 10.9.9.9'")
          # (plain grep, not -q: -q exits on the first match and SIGPIPEs the
          # still-writing producer under pipefail)
          machine.succeed("sentinel show version | grep wren")
          machine.succeed("sentinel show firewall")
        '';
      };

      # WireGuard (roadmap C1): a `[[interface]]` that carries a `private-key`
      # renders to a `Kind=wireguard` netdev (0640 root:systemd-network, since it
      # embeds the key), participates in the firewall via its `zone`, and networkd
      # + the kernel bring up a real `wg0` link with the declared peer.
      #   nix build .#checks.x86_64-linux.wireguard -L
      # The two fixed keys below were produced with the real `wg` tool:
      #   wg genkey | tee /dev/stderr | wg pubkey
      # wg0 private ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=
      #   → derived public 6gUqcU72dUQr2VqzOWxiON1qzkzIOQD7SkZjPjPFWXs=
      # peer public ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ= (a second genkey).
      wireguard = pkgs.testers.runNixOSTest {
        name = "sentinel-wireguard";
        nodes.machine = {
          imports = [ self.nixosModules.sentinel ];
          virtualisation.memorySize = 2048;
          # `wg show` needs the userspace tool; the kernel module ships with the
          # test kernel. `ip -d link show` comes from iproute2 (already present).
          environment.systemPackages = [ pkgs.wireguard-tools ];
        };
        testScript = ''
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("sentinel-boot.service")
          machine.wait_for_unit("velstra.service")

          # Declare a WireGuard tunnel AS THE ADMIN USER: a private key, a listen
          # port, an address (so the link is zoned + brought up), a firewall zone,
          # and one peer with allowed-ips + endpoint. commit applies live.
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set interface wg0 private-key ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=' "
              "'set interface wg0 listen-port 51820' "
              "'set interface wg0 address 10.9.0.1/24' 'set interface wg0 zone lan' "
              "'set interface wg0 peer ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ= allowed-ips 10.9.0.2/32' "
              "'set interface wg0 peer ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ= endpoint 192.0.2.7:51820' "
              "commit save exit "
              "| sentinel configure\""
          )

          # Sentinel wrote the wireguard netdev. It holds the private key, so it is
          # 0640 root:systemd-network — not world-readable, but readable by the
          # systemd-network user networkd runs as (0600 root:root would deny it).
          machine.succeed("test -f /run/systemd/network/10-sentinel-wg0.netdev")
          netdev = machine.succeed("cat /run/systemd/network/10-sentinel-wg0.netdev")
          assert "Kind=wireguard" in netdev, netdev
          assert "PrivateKey=" in netdev, netdev
          assert "[WireGuardPeer]" in netdev, netdev
          assert "PublicKey=ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ=" in netdev, netdev
          assert "AllowedIPs=10.9.0.2/32" in netdev, netdev
          assert "Endpoint=192.0.2.7:51820" in netdev, netdev
          mode = machine.succeed("stat -c %a /run/systemd/network/10-sentinel-wg0.netdev").strip()
          assert mode == "640", mode
          group = machine.succeed("stat -c %G /run/systemd/network/10-sentinel-wg0.netdev").strip()
          assert group == "systemd-network", group

          # networkd + the kernel created a real wireguard link, and wg sees the peer.
          machine.wait_until_succeeds("ip -d link show wg0 | grep -q wireguard", timeout=20)
          machine.wait_until_succeeds("ip addr show wg0 | grep -q 10.9.0.1", timeout=20)
          machine.wait_until_succeeds(
              "wg show wg0 | grep -q ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ=", timeout=20
          )

          # The zone binding compiled through: the firewall sees wg0.
          machine.succeed("grep -q '\"wg0\"' /run/sentinel/velstra.toml")
          # save persisted the wireguard interface (private key + peer).
          machine.succeed("grep -q 'private-key' /var/lib/sentinel/appliance.toml")
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
                  # The dm-verity hash + store partitions (#2, #3) MUST keep the
                  # source's partition UUIDs: they are derived from the roothash,
                  # and systemd auto-binds /dev/mapper/usr by matching them at boot
                  # (there is NO explicit usrhash= on the kernel cmdline). If the
                  # install randomized them, the installed system would time out
                  # waiting for /dev/mapper/usr and drop to emergency mode. Assert
                  # they are preserved (a `sgdisk --randomize-guids` would fail this).
                  for p in (2, 3):
                      srcuuid = machine.succeed(f"blkid -s PARTUUID -o value /dev/{src}{p}").strip()
                      dstuuid = machine.succeed(f"blkid -s PARTUUID -o value /dev/vdb{p}").strip()
                      assert srcuuid and srcuuid == dstuuid, (
                          f"verity partition {p} UUID not preserved: {srcuuid!r} != {dstuuid!r}"
                      )
                  # But the *disk* GUID is freshened so it can't collide with the
                  # source medium.
                  srcdisk = machine.succeed(f"blkid -s PTUUID -o value /dev/{src}").strip()
                  dstdisk = machine.succeed("blkid -s PTUUID -o value /dev/vdb").strip()
                  assert srcdisk != dstdisk, f"disk GUID should differ: {srcdisk!r} == {dstdisk!r}"

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
            client.wait_for_unit("multi-user.target")
            client.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.2", timeout=20)

            # Zone the WAN nic and add a reject rule for tcp/9999.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set firewall rule refuse from wan' "
                "'set firewall rule refuse to wan' "
                "'set firewall rule refuse action reject' "
                "'set firewall rule refuse proto tcp' "
                "'set firewall rule refuse port 9999' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")
            # The compiled config carries the reject verdict.
            fw.succeed("grep -q 'reject' /run/sentinel/velstra.toml")

            # The headline: a connection to the rejected port comes back refused
            # (a RST) fast, not a timeout. curl reports "Connection refused" or
            # "Connection reset" on a RST; a silent drop would instead time out.
            # Retry so a SYN lost in the velstra reload window can't fail us.
            def refused(_):
                out = client.execute(
                    "curl -sS --max-time 4 -o /dev/null http://10.1.0.1:9999/ 2>&1"
                )[1].lower()
                return "refused" in out or "reset" in out

            retry(refused)
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

        # Non-TCP reject in the eBPF datapath: the fw's WAN zone REJECTs udp/9999.
        # A UDP probe from the client must come back as an ICMP port-unreachable
        # (type 3, code 3) — delivered to a connected UDP socket as ECONNREFUSED —
        # proving the XDP path crafts and XDP_TX's a real ICMP error rather than
        # black-holing the way a silent drop would (which would time out instead).
        rejectudp = pkgs.testers.runNixOSTest {
          name = "sentinel-rejectudp";
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
                environment.systemPackages = [ pkgs.python3 ];
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

            # Zone the WAN nic and reject udp/9999.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set firewall rule refuse-udp from wan' "
                "'set firewall rule refuse-udp to wan' "
                "'set firewall rule refuse-udp action reject' "
                "'set firewall rule refuse-udp proto udp' "
                "'set firewall rule refuse-udp port 9999' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")
            fw.succeed("grep -q reject /run/sentinel/velstra.toml")

            # Probe: connect a UDP socket to the rejected port, send, then read. An
            # ICMP port-unreachable is delivered to a connected UDP socket as
            # ECONNREFUSED on the blocked recv; a silent drop would time out.
            client.succeed(
                "cat > /root/probe.py <<'PY'\n"
                "import socket, sys\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                "s.settimeout(3)\n"
                "s.connect(('10.1.0.1', 9999))\n"
                "s.send(b'x' * 40)\n"
                "try:\n"
                "    s.recv(200)\n"
                "except ConnectionRefusedError:\n"
                "    print('REFUSED'); sys.exit(0)\n"
                "except OSError:\n"
                "    print('TIMEOUT'); sys.exit(1)\n"
                "sys.exit(1)\n"
                "PY"
            )

            # The headline: the probe gets an ICMP-driven "connection refused". Re-run
            # in a retry loop so a probe lost in the velstra reload window can't fail us.
            def refused(_):
                return "REFUSED" in client.execute("python3 /root/probe.py")[1]

            retry(refused)
          '';
        };

        # Built-in DHCP server: a 2-node client — fw. The fw gives eth1 a static
        # subnet (10.0.0.1/24) and turns on `dhcp-server` (pool offset 100, size
        # 50, advertising itself as DNS). Sentinel renders `DHCPServer=yes` + a
        # `[DHCPServer]` section into the interface's networkd `.network`, so
        # networkd runs the server — no extra daemon. The client is a plain NixOS
        # DHCP client on the same segment; it must obtain a pool lease (10.0.0.x,
        # offset >= 100, never the server's .1), proving the server handed out an
        # address end to end. The lan zone is set to accept so the XDP firewall
        # passes the client's DHCP request on eth1.
        #   nix build .#checks.x86_64-linux.dhcp -L
        dhcp = pkgs.testers.runNixOSTest {
          name = "sentinel-dhcp";
          nodes = {
            client =
              { ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                };
                # A DHCP client on eth1 — networkd keeps requesting until the fw's
                # server answers.
                systemd.network.networks."10-eth1" = {
                  matchConfig.Name = "eth1";
                  networkConfig.DHCP = "ipv4";
                };
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                # eth1's address + DHCP server are configured via sentinel, so the
                # NIC is left unconfigured here (sentinel owns the .network unit).
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Give eth1 a static subnet + a DHCP server serving a pool from it, on
            # a lan zone set to accept so the XDP firewall passes DHCP on eth1.
            # ONE `set` per line (the inline multi-field form does not parse).
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 address 10.0.0.1/24' "
                "'set interface eth1 zone lan' "
                "'set firewall zone lan default-action accept' "
                "'set interface eth1 dhcp-server enable' "
                "'set interface eth1 dhcp-server pool-offset 100' "
                "'set interface eth1 dhcp-server pool-size 50' "
                "'set interface eth1 dhcp-server dns 10.0.0.1' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")

            # Sentinel rendered the DHCP server into eth1's networkd .network.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-eth1.network", timeout=20
            )
            netw = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "DHCPServer=yes" in netw, netw
            assert "[DHCPServer]" in netw, netw
            assert "PoolOffset=100" in netw, netw
            assert "PoolSize=50" in netw, netw
            assert "EmitDNS=yes" in netw, netw
            # networkd brought the server up on eth1 with the static address.
            fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q '10.0.0.1'", timeout=30)

            # The client obtains a pool lease: some 10.0.0.x that isn't the
            # server's .1 (the pool starts at offset 100). DHCP can take a few
            # seconds, so retry with a generous timeout.
            client.wait_for_unit("multi-user.target")
            client.wait_until_succeeds(
                "ip -4 addr show eth1 | grep -oE '10[.]0[.]0[.][0-9]+' | grep -qv '10.0.0.1'",
                timeout=90,
            )

            # The server side saw the lease it handed out.
            fw.succeed("networkctl status eth1")
          '';
        };

        # PPPoE client + MSS clamping (roadmap C5). Two nodes on the WAN segment
        # (vlan 2): a `concentrator` runs rp-pppoe's `pppoe-server` (its own
        # self-contained pppd + rp-pppoe.so plugin, require-CHAP), and the sentinel
        # `fw` dials it as a PPPoE client on its uplink NIC (eth2). The fw's velstra
        # XDP attaches to an isolated eth1 (vlan 1) so it never sees the raw PPPoE
        # frames on eth2. We assert Sentinel rendered the pppd peer options +
        # 0600 chap-secrets byte-correctly, the `sentinel-pppoe@ppp0` unit is up,
        # `ppp0` negotiates an address from the concentrator's pool, AND the
        # TCP-MSS-clamp nftables table (the `--clamp-mss-to-pmtu` equivalent) is
        # loaded into the kernel.
        #   nix build .#checks.x86_64-linux.pppoe -L
        pppoe = pkgs.testers.runNixOSTest {
          name = "sentinel-pppoe";
          nodes = {
            # The ISP-side PPPoE access concentrator, on the WAN segment (vlan 2).
            concentrator =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 2 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                };
                # eth1 is the raw PPPoE segment — link-up only, no L3 address
                # (PPPoE discovery/session are L2). networkd manages it up.
                systemd.network.networks."10-eth1" = {
                  matchConfig.Name = "eth1";
                  networkConfig.LinkLocalAddressing = "no";
                  linkConfig.RequiredForOnline = false;
                };
                # pppd options the concentrator hands its per-client pppd: require
                # CHAP (so the client's credentials are actually exercised) and push
                # a DNS the client can `usepeerdns` into.
                environment.etc."ppp/pppoe-server-options".text = ''
                  require-chap
                  lcp-echo-interval 10
                  lcp-echo-failure 2
                  ms-dns 10.0.0.1
                  noipdefault
                '';
                # The credential the concentrator checks the client against.
                environment.etc."ppp/chap-secrets" = {
                  mode = "0600";
                  text = ''
                    "testuser"	*	"testpass"	*
                  '';
                };
                systemd.services.pppoe-server = {
                  wantedBy = [ "multi-user.target" ];
                  after = [ "systemd-networkd.service" ];
                  # pppoe-server bakes in its pppd path + rp-pppoe.so plugin, but
                  # still needs them resolvable for exec.
                  path = [
                    pkgs.ppp
                    pkgs.rpPPPoE
                  ];
                  serviceConfig = {
                    ExecStartPre = "${pkgs.iproute2}/bin/ip link set eth1 up";
                    # -F: foreground (systemd owns it). -I: raw NIC. -L/-R: local +
                    # remote-pool addresses. -N: max sessions. -O: our options file.
                    ExecStart =
                      "${pkgs.rpPPPoE}/bin/pppoe-server -F -I eth1 "
                      + "-L 10.0.0.1 -R 10.0.0.100 -N 10 -O /etc/ppp/pppoe-server-options";
                    Restart = "on-failure";
                    RestartSec = "2s";
                  };
                };
              };
            # The appliance: velstra on the isolated eth1 (vlan 1); the PPPoE uplink
            # is eth2 (vlan 2), the same segment as the concentrator.
            fw =
              { lib, pkgs, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                virtualisation.vlans = [
                  1
                  2
                ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
                # `nft` for the MSS-clamp assertion below (sentinel itself uses a
                # wrapped absolute path, so it isn't otherwise on the admin PATH).
                environment.systemPackages = [ pkgs.nftables ];
              };
          };
          testScript = ''
            start_all()
            concentrator.wait_for_unit("pppoe-server.service")
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Dial the concentrator: declare the uplink NIC (eth2) as the pppoe
            # parent and configure the ppp0 client with the ISP credentials. ONE
            # `set` per line (the inline multi-field form does not parse).
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth2 zone wan' "
                "'set interface ppp0 type pppoe' "
                "'set interface ppp0 parent eth2' "
                "'set interface ppp0 zone wan' "
                "'set interface ppp0 pppoe username testuser' "
                "'set interface ppp0 pppoe password testpass' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered the pppd peer options for the session (pppoe.so
            # plugin on the parent NIC, pinned link name, the ISP username — but
            # NOT the password, which lives only in the 0600 secrets file).
            fw.wait_until_succeeds("test -f /run/sentinel/ppp/peers/ppp0", timeout=20)
            peer = fw.succeed("cat /run/sentinel/ppp/peers/ppp0")
            assert "plugin pppoe.so" in peer, peer
            assert "nic-eth2" in peer, peer
            assert "ifname ppp0" in peer, peer
            assert 'user "testuser"' in peer, peer
            assert "testpass" not in peer, peer

            # The credentials landed in the 0600 chap-secrets, reachable via pppd's
            # fixed /etc/ppp lookup path (the module symlinks it into place).
            secret = fw.succeed("cat /etc/ppp/chap-secrets")
            assert '"testuser"' in secret and '"testpass"' in secret, secret
            mode = fw.succeed(
                "stat -L -c '%a' /etc/ppp/chap-secrets"
            ).strip()
            assert mode == "600", mode

            # The templated pppd unit is running for this session.
            fw.wait_for_unit("sentinel-pppoe@ppp0.service")

            # ppp0 negotiates up and takes an address from the concentrator's pool
            # (10.0.0.100+). PPPoE discovery + LCP/CHAP/IPCP takes a few seconds.
            fw.wait_until_succeeds(
                "ip -4 addr show ppp0 | grep -q 'inet 10[.]0[.]0[.]'", timeout=90
            )

            # The MSS clamp is live in the kernel: our `inet sentinel-mss` table
            # clamps TCP MSS to the path MTU (`maxseg ... set rt mtu`) on ppp0's
            # egress — the VyOS `clamp-mss-to-pmtu` equivalent.
            rules = fw.succeed("nft list ruleset")
            assert "sentinel-mss" in rules, rules
            assert "maxseg" in rules, rules
            assert 'oifname "ppp0"' in rules, rules
          '';
        };

        # IPv6 Router Advertisements (SLAAC): the v6 counterpart of the DHCP
        # check. The fw turns on `router-advert` on eth1, advertising the
        # 2001:db8:1::/64 prefix (and itself as v6 DNS). Sentinel renders
        # `IPv6SendRA=yes` + `[IPv6SendRA]`/`[IPv6Prefix]` into the interface's
        # networkd `.network`, so networkd emits RAs — no radvd. The client is a
        # plain networkd node accepting RAs; it must autoconfigure a global
        # 2001:db8:1: address by SLAAC, proving the advertiser works end to end.
        # `Assign=yes` also binds the router its own address from the prefix, so
        # no separate IPv6 addressing is needed. The lan zone is set to accept so
        # the XDP firewall passes the client's Router Solicitation on eth1 (the
        # fw answers it with a solicited RA immediately).
        #   nix build .#checks.x86_64-linux.ra -L
        ra = pkgs.testers.runNixOSTest {
          name = "sentinel-ra";
          nodes = {
            client =
              { ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                };
                # Accept RAs on eth1 and form a SLAAC address from the advertised
                # prefix.
                systemd.network.networks."10-eth1" = {
                  matchConfig.Name = "eth1";
                  networkConfig.IPv6AcceptRA = true;
                };
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                # eth1's addressing + RA are configured via sentinel (it owns the
                # .network unit); Assign=yes gives the router its v6 address.
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Turn on RA (SLAAC) for the 2001:db8:1::/64 prefix on eth1, on a lan
            # zone set to accept so the XDP firewall passes the client's Router
            # Solicitation. ONE `set` per line (the inline multi-field form does
            # not parse).
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone lan' "
                "'set firewall zone lan default-action accept' "
                "'set interface eth1 router-advert enable' "
                "'set interface eth1 router-advert prefix 2001:db8:1::/64' "
                "'set interface eth1 router-advert dns 2001:db8:1::1' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")

            # Sentinel rendered the RA sender into eth1's networkd .network.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-eth1.network", timeout=20
            )
            netw = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "IPv6SendRA=yes" in netw, netw
            assert "[IPv6SendRA]" in netw, netw
            assert "[IPv6Prefix]" in netw, netw
            assert "Prefix=2001:db8:1::/64" in netw, netw
            assert "Assign=yes" in netw, netw

            # The router bound its own address from the advertised prefix.
            fw.wait_until_succeeds(
                "ip -6 addr show eth1 | grep -qi '2001:db8:1:'", timeout=30
            )

            # The client autoconfigures a global 2001:db8:1: address by SLAAC.
            # A solicited RA answers the client's RS near-instantly; allow a
            # generous timeout for boot + the exchange.
            client.wait_for_unit("multi-user.target")
            client.wait_until_succeeds(
                "ip -6 addr show eth1 | grep -qi '2001:db8:1:'", timeout=90
            )
          '';
        };

        # DNS forwarder: a 3-node proof that the box resolves for the LAN. An
        # `upstream` node is authoritative for sentinel.test -> 10.9.9.9
        # (dnsmasq); the sentinel `fw` forwards to it and serves the LAN on
        # eth1's IP; a `client` queries the fw and must get the upstream answer.
        # Sentinel renders `[services.dns]` into a systemd-resolved drop-in
        # (`DNS=<upstream>` + `DNSStubListenerExtra=<lan-ip>`) — no extra daemon.
        # The lan zone accepts so the XDP firewall passes the client's query and
        # the fw's forwarded lookup on eth1.
        #   nix build .#checks.x86_64-linux.dns -L
        dns = pkgs.testers.runNixOSTest {
          name = "sentinel-dns";
          nodes = {
            upstream =
              { ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.0.0.99";
                      prefixLength = 24;
                    }
                  ];
                };
                # Authoritative for the test name; bound to eth1 only so it does
                # not fight resolved for 127.0.0.53.
                services.resolved.enable = false;
                services.dnsmasq = {
                  enable = true;
                  settings = {
                    bind-interfaces = true;
                    interface = "eth1";
                    address = "/sentinel.test/10.9.9.9";
                  };
                };
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
              };
            client =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.0.0.50";
                      prefixLength = 24;
                    }
                  ];
                };
                environment.systemPackages = [ pkgs.dnsutils ];
              };
          };
          testScript = ''
            start_all()
            upstream.wait_for_unit("dnsmasq.service")
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Turn on the LAN DNS forwarder on eth1 (static addr + lan accept so
            # the XDP firewall passes DNS), forwarding to the upstream node.
            # ONE `set` per line (the inline multi-field form does not parse).
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 address 10.0.0.1/24' "
                "'set interface eth1 zone lan' "
                "'set firewall zone lan default-action accept' "
                "'set services dns upstream 10.0.0.99' "
                "'set services dns serve-on eth1' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")

            # Sentinel rendered the dnsmasq drop-in (the LAN resolver): the
            # upstream forwarder + the serving interface. resolved (the box's own
            # resolver) gets the upstream but NO LAN stub listener anymore.
            fw.wait_until_succeeds(
                "test -f /run/sentinel/dnsmasq.d/sentinel.conf", timeout=20
            )
            conf = fw.succeed("cat /run/sentinel/dnsmasq.d/sentinel.conf")
            assert "server=10.0.0.99" in conf, conf
            assert "interface=eth1" in conf, conf
            rconf = fw.succeed("cat /run/systemd/resolved.conf.d/10-sentinel-dns.conf")
            assert "DNS=10.0.0.99" in rconf and "DNSStubListenerExtra" not in rconf, rconf
            fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q '10.0.0.1'", timeout=30)
            fw.wait_for_unit("dnsmasq.service")

            # The client resolves the upstream-only name THROUGH the fw: proof the
            # box (dnsmasq) forwards LAN queries to its configured upstream.
            client.wait_for_unit("multi-user.target")
            client.wait_until_succeeds(
                "dig +short +tries=2 +time=3 @10.0.0.1 sentinel.test | grep -q '10.9.9.9'",
                timeout=90,
            )

            # Host-override + blocklist (the pfBlocker/split-horizon differentiator):
            # a local record answered authoritatively, and a sinkholed domain.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set services dns host-override nas.lan 10.0.0.5' "
                "'set services dns blocklist ads.example' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_until_succeeds(
                "grep -q 'address=/nas.lan/10.0.0.5' /run/sentinel/dnsmasq.d/sentinel.conf",
                timeout=20,
            )
            fw.wait_for_unit("dnsmasq.service")
            # The client sees the local override ...
            client.wait_until_succeeds(
                "dig +short +tries=2 +time=3 @10.0.0.1 nas.lan | grep -q '10.0.0.5'",
                timeout=60,
            )
            # ... and the blocked domain is sinkholed to 0.0.0.0.
            client.wait_until_succeeds(
                "dig +short +tries=2 +time=3 @10.0.0.1 ads.example | grep -qx '0.0.0.0'",
                timeout=60,
            )
          '';
        };

        # L2 devices: a bridge and a bond, both synthesised by Sentinel from the
        # same networkd-.netdev render path as VLANs. One fw node with three NICs:
        # br0 (a bridge holding the LAN address) enslaves eth1; bond0 (active-
        # backup) enslaves eth2; eth3 is left free for the velstra XDP attach so
        # the data plane never touches the enslaved members. Proves the render →
        # kernel path: the bridge/bond devices exist with the right kind/mode and
        # their members are enslaved.
        #   nix build .#checks.x86_64-linux.l2 -L
        l2 = pkgs.testers.runNixOSTest {
          name = "sentinel-l2";
          nodes.fw =
            { lib, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce "fw";
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [ 1 2 3 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth3";
            };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Build a bridge (br0 <- eth1, holding the LAN IP) and a bond (bond0
            # <- eth2, active-backup). ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface br0 type bridge' "
                "'set interface br0 zone lan' "
                "'set interface br0 address 10.0.0.1/24' "
                "'set interface eth1 master br0' "
                "'set interface bond0 type bond' "
                "'set interface bond0 bond-mode active-backup' "
                "'set interface eth2 master bond0' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered the netdevs + member enslavement.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-br0.netdev", timeout=20
            )
            brdev = fw.succeed("cat /run/systemd/network/10-sentinel-br0.netdev")
            assert "Kind=bridge" in brdev, brdev
            bonddev = fw.succeed("cat /run/systemd/network/10-sentinel-bond0.netdev")
            assert "Kind=bond" in bonddev, bonddev
            assert "Mode=active-backup" in bonddev, bonddev
            assert "Bridge=br0" in fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "Bond=bond0" in fw.succeed("cat /run/systemd/network/10-sentinel-eth2.network")

            # networkd realised them in the kernel: the bridge holds the LAN
            # address and switches eth1; the bond aggregates eth2 in active-backup.
            fw.wait_until_succeeds("ip -d link show br0 | grep -q bridge", timeout=30)
            fw.wait_until_succeeds("ip -4 addr show br0 | grep -q '10.0.0.1'", timeout=30)
            fw.wait_until_succeeds("ip link show eth1 | grep -q 'master br0'", timeout=30)
            fw.wait_until_succeeds("ip link show eth2 | grep -q 'master bond0'", timeout=30)
            fw.wait_until_succeeds(
                "grep -qi 'Bonding Mode: fault-tolerance' /proc/net/bonding/bond0", timeout=30
            )
          '';
        };

        # NTP server: a 3-node proof that the box serves time to the LAN. An
        # `upstream` node is an authoritative source (chrony, local stratum 5);
        # the sentinel `fw` syncs to it and serves the LAN; a `client` syncs to
        # the fw. Sentinel renders `[services.ntp]` into a chrony confdir drop-in
        # (`server <up> iburst` + `allow <subnet>`) layered on the image's chrony
        # — no extra unit. The lan zone accepts so the XDP firewall passes udp/123.
        #   nix build .#checks.x86_64-linux.ntp -L
        ntp = pkgs.testers.runNixOSTest {
          name = "sentinel-ntp";
          nodes = {
            upstream =
              { ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.0.0.99";
                      prefixLength = 24;
                    }
                  ];
                };
                # An authoritative source with no upstream: serve its own clock at
                # stratum 5 and allow anyone to query.
                services.chrony = {
                  enable = true;
                  servers = [ ];
                  extraConfig = ''
                    local stratum 5
                    allow all
                  '';
                };
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth1";
              };
            client =
              { ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.0.0.50";
                      prefixLength = 24;
                    }
                  ];
                };
                # Sync only to the fw; poll fast (iburst + low minpoll) and step
                # the clock so the test converges quickly once the fw serves.
                services.chrony = {
                  enable = true;
                  servers = [ ];
                  extraConfig = ''
                    server 10.0.0.1 iburst minpoll 0 maxpoll 4
                    makestep 1 -1
                  '';
                };
              };
          };
          testScript = ''
            start_all()
            upstream.wait_for_unit("chronyd.service")
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Turn on the LAN NTP server on eth1 (static addr + lan accept so XDP
            # passes udp/123), syncing to the upstream node. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 address 10.0.0.1/24' "
                "'set interface eth1 zone lan' "
                "'set firewall zone lan default-action accept' "
                "'set services ntp upstream 10.0.0.99' "
                "'set services ntp serve-on eth1' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered the chrony confdir drop-in: sync to the upstream +
            # allow the LAN subnet (the interface's network, not its host address).
            fw.wait_until_succeeds(
                "test -f /run/sentinel/chrony.d/sentinel.conf", timeout=20
            )
            conf = fw.succeed("cat /run/sentinel/chrony.d/sentinel.conf")
            assert "server 10.0.0.99 iburst" in conf, conf
            assert "allow 10.0.0.0/24" in conf, conf

            # The fw synchronises to the upstream (its Reference ID becomes the
            # upstream's IP) and opens the NTP server socket for the LAN.
            fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q '10.0.0.1'", timeout=30)
            fw.wait_until_succeeds(
                "chronyc -n tracking | grep -q '10.0.0.99'", timeout=120
            )
            fw.wait_until_succeeds("ss -uln | grep -q ':123'", timeout=10)

            # The fw now serves time; (re)start the client's chrony so it bursts
            # against the now-serving fw, then confirm it synchronises through it.
            client.wait_for_unit("chronyd.service")
            client.succeed("systemctl restart chronyd")
            client.wait_until_succeeds(
                "chronyc -n tracking | grep -q '10.0.0.1'", timeout=90
            )
          '';
        };

        # Dual-stack addressing: an interface can carry both a static IPv4
        # `address` and a static IPv6 `address6` (independent fields). Sentinel
        # renders both as networkd `Address=` lines; the kernel binds both. One
        # node, no traffic — pure addressing proof.
        #   nix build .#checks.x86_64-linux.dualstack -L
        dualstack = pkgs.testers.runNixOSTest {
          name = "sentinel-dualstack";
          nodes.fw =
            { lib, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce "fw";
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth1";
            };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Give eth1 both a v4 and a v6 static address. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone lan' "
                "'set interface eth1 address 10.0.0.1/24' "
                "'set interface eth1 address6 2001:db8:1::1/64' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered both address families into eth1's .network.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-eth1.network", timeout=20
            )
            netw = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "Address=10.0.0.1/24" in netw, netw
            assert "Address=2001:db8:1::1/64" in netw, netw

            # The kernel bound both families on eth1.
            fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q '10.0.0.1'", timeout=30)
            fw.wait_until_succeeds(
                "ip -6 addr show eth1 | grep -qi '2001:db8:1::1'", timeout=30
            )
          '';
        };

        # DHCPv6-PD (the German-ISP WAN v6 model): an `upstream` kea-dhcp6 server
        # delegates a /56 out of 2001:db8:d00::/40; the sentinel `fw` requests it
        # on its WAN (`address6 = "dhcp"`) and carves subnet 0 of the delegated
        # prefix onto its LAN (`pd-from`). Sentinel renders `DHCP=ipv6` +
        # `[DHCPv6] WithoutRA=solicit` on the WAN and `DHCPPrefixDelegation` on the
        # LAN. velstra runs on a third, uninvolved NIC so XDP never touches the PD
        # exchange. Proof: the LAN interface binds an address from the delegated
        # prefix.
        #   nix build .#checks.x86_64-linux.dhcp6pd -L
        dhcp6pd = pkgs.testers.runNixOSTest {
          name = "sentinel-dhcp6pd";
          nodes = {
            upstream =
              { ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useNetworkd = true;
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv6.addresses = [
                    {
                      address = "2001:db8:0::1";
                      prefixLength = 64;
                    }
                  ];
                };
                services.kea.dhcp6 = {
                  enable = true;
                  settings = {
                    interfaces-config.interfaces = [ "eth1" ];
                    lease-database = {
                      type = "memfile";
                      persist = false;
                    };
                    subnet6 = [
                      {
                        id = 1;
                        subnet = "2001:db8:0::/64";
                        interface = "eth1";
                        pools = [ { pool = "2001:db8:0::100 - 2001:db8:0::1ff"; } ];
                        pd-pools = [
                          {
                            prefix = "2001:db8:d00::";
                            prefix-len = 40;
                            delegated-len = 56;
                          }
                        ];
                      }
                    ];
                  };
                };
              };
            fw =
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                virtualisation.vlans = [
                  1
                  2
                  3
                ];
                virtualisation.memorySize = 2048;
                services.velstra.interface = lib.mkForce "eth3";
              };
          };
          testScript = ''
            start_all()
            upstream.wait_for_unit("kea-dhcp6-server.service")
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # WAN = eth1 (DHCPv6 client requesting PD); LAN = eth2 (subnet 0 of the
            # delegated prefix). ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone wan' "
                "'set interface eth1 address6 dhcp' "
                "'set firewall zone wan default-action accept' "
                "'set interface eth2 zone lan' "
                "'set interface eth2 pd-from eth1' "
                "'set interface eth2 pd-subnet 0' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered the DHCPv6 client + the delegation downstream.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-eth2.network", timeout=20
            )
            wan = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "DHCP=ipv6" in wan, wan
            assert "WithoutRA=solicit" in wan, wan
            lan = fw.succeed("cat /run/systemd/network/10-sentinel-eth2.network")
            assert "DHCPPrefixDelegation=yes" in lan, lan
            assert "UplinkInterface=eth1" in lan, lan

            # The fw acquired the delegation and bound an address from it onto the
            # LAN interface (proof the whole PD chain worked end to end).
            fw.wait_until_succeeds(
                "ip -6 addr show eth2 | grep -qi '2001:db8:d'", timeout=120
            )
          '';
        };

        # Static IPv6 routes: `[[protocols.static]]` is dual-stack — a v6 prefix
        # with a v6 nexthop compiles into wren.toml and wren programs the kernel
        # IPv6 FIB, exactly like a v4 static. One node: eth1 holds a v6 subnet,
        # and a static route to 2001:db8:beef::/48 via an on-link nexthop must
        # appear in `ip -6 route`.
        #   nix build .#checks.x86_64-linux.staticv6 -L
        staticv6 = pkgs.testers.runNixOSTest {
          name = "sentinel-staticv6";
          nodes.fw =
            { lib, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce "fw";
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth1";
            };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            fw.wait_for_unit("wren.service")

            # eth1 gets a v6 subnet (so the nexthop is on-link), then a v6 static
            # route. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone lan' "
                "'set interface eth1 address6 2001:db8:0::1/64' "
                "'set protocols static 2001:db8:beef::/48 via 2001:db8:0::2' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("wren.service")

            # Sentinel compiled the v6 route into wren's config.
            fw.wait_until_succeeds(
                "grep -q '2001:db8:beef::/48' /run/sentinel/wren.toml", timeout=20
            )
            # wren programmed the kernel IPv6 FIB with it.
            fw.wait_until_succeeds(
                "ip -6 route show | grep -q '2001:db8:beef::/48'", timeout=60
            )
          '';
        };

        # Per-interface link tunables: MTU (jumbo frames / PPPoE) and MAC cloning.
        # Sentinel renders a [Link] section into the interface's .network; networkd
        # applies both to the live link. One node — proof via `ip link`.
        #   nix build .#checks.x86_64-linux.linkopts -L
        linkopts = pkgs.testers.runNixOSTest {
          name = "sentinel-linkopts";
          nodes.fw =
            { lib, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce "fw";
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth1";
            };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Set a jumbo MTU and clone a MAC on eth1. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone lan' "
                "'set interface eth1 mtu 9000' "
                "'set interface eth1 mac 52:54:00:aa:bb:cc' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered a [Link] section with both.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-eth1.network", timeout=20
            )
            netw = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "MTUBytes=9000" in netw, netw
            assert "MACAddress=52:54:00:aa:bb:cc" in netw, netw

            # networkd applied both to the live link.
            fw.wait_until_succeeds("ip link show eth1 | grep -q 'mtu 9000'", timeout=30)
            fw.wait_until_succeeds(
                "ip link show eth1 | grep -qi '52:54:00:aa:bb:cc'", timeout=30
            )
          '';
        };

        # Routing: two Sentinel appliances peer eBGP and each learns the other's
        # network — end-to-end proof that the Wren control plane is wired into the
        # image (packaged, serviced, config-compiled from `set protocols …`) and
        # programs the kernel FIB. bgp1 (AS 65001) originates 10.11.0.0/24, bgp2
        # (AS 65002) originates 10.12.0.0/24; after the session establishes each
        # installs the other's prefix `proto bgp` via the peer.
        bgp =
          let
            node = hostname: addr: {
              lib,
              ...
            }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce hostname;
              networking.firewall.enable = lib.mkForce false;
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = addr;
                  prefixLength = 24;
                }
              ];
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth1";
            };
          in
          pkgs.testers.runNixOSTest {
            name = "sentinel-bgp";
            nodes = {
              bgp1 = node "bgp1" "10.10.0.1";
              bgp2 = node "bgp2" "10.10.0.2";
            };
            testScript = ''
              start_all()
              for m in (bgp1, bgp2):
                  m.wait_for_unit("multi-user.target")
                  m.wait_for_unit("velstra.service")
                  m.wait_for_unit("wren.service")
              bgp1.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.1", timeout=20)
              bgp2.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.2", timeout=20)

              # Configure BGP on each node. default-action accept so the Velstra
              # firewall (attached to eth1) passes the BGP session (tcp/179);
              # zone eth1 so it is a proper firewalled interface.
              def configure(m, myaddr, myas, mynet, peer, peeras):
                  m.succeed(
                      "su admin -c \"printf '%s\\n' "
                      "'set firewall global default-action accept' "
                      "'set interface eth1 zone wan' "
                      f"'set protocols router-id {myaddr}' "
                      f"'set protocols bgp local-as {myas}' "
                      f"'set protocols bgp network {mynet}' "
                      f"'set protocols bgp neighbor {peer} remote-as {peeras}' "
                      "commit save exit "
                      "| sentinel configure\""
                  )
                  m.wait_for_unit("wren.service")

              configure(bgp1, "10.10.0.1", 65001, "10.11.0.0/24", "10.10.0.2", 65002)
              configure(bgp2, "10.10.0.2", 65002, "10.12.0.0/24", "10.10.0.1", 65001)

              # The compiled Wren config carries the BGP block.
              bgp1.succeed("grep -q 'local-as = 65001' /run/sentinel/wren.toml")
              bgp2.succeed("grep -q 'local-as = 65002' /run/sentinel/wren.toml")

              # The headline: each router learns the OTHER's network over BGP and
              # installs it into the kernel FIB (proto bgp) via the peer. BGP takes
              # a little while to establish, so retry generously.
              bgp1.wait_until_succeeds(
                  "ip -4 route show proto bgp | grep -q '10.12.0.0/24'", timeout=90
              )
              bgp2.wait_until_succeeds(
                  "ip -4 route show proto bgp | grep -q '10.11.0.0/24'", timeout=90
              )

              # And the operational `wren show` command works on the box, reporting
              # the established session.
              bgp1.succeed("wren show bgp neighbors | grep -qi established")
            '';
          };

        # Routing: two Sentinel appliances form an OSPFv2 point-to-point adjacency
        # and each learns the other's redistributed network — proof the Wren OSPF
        # path is wired through the same `set protocols …` CLI. ospf1 originates
        # 10.11.0.0/24 (a static, redistributed into OSPF), ospf2 originates
        # 10.12.0.0/24; after the adjacency reaches Full each installs the other's
        # prefix `proto ospf`.
        ospf =
          let
            node = hostname: addr: {
              lib,
              ...
            }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce hostname;
              networking.firewall.enable = lib.mkForce false;
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = addr;
                  prefixLength = 24;
                }
              ];
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth1";
            };
          in
          pkgs.testers.runNixOSTest {
            name = "sentinel-ospf";
            nodes = {
              ospf1 = node "ospf1" "10.10.0.1";
              ospf2 = node "ospf2" "10.10.0.2";
            };
            testScript = ''
              start_all()
              for m in (ospf1, ospf2):
                  m.wait_for_unit("multi-user.target")
                  m.wait_for_unit("velstra.service")
                  m.wait_for_unit("wren.service")
              ospf1.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.1", timeout=20)
              ospf2.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.2", timeout=20)

              # Configure OSPF on each node. default-action accept so the Velstra
              # firewall passes OSPF's multicast (IP proto 89). Each originates a
              # unique network as a static, redistributed into OSPF.
              def configure(m, myaddr, mynet):
                  m.succeed(
                      "su admin -c \"printf '%s\\n' "
                      "'set firewall global default-action accept' "
                      "'set interface eth1 zone wan' "
                      f"'set protocols router-id {myaddr}' "
                      f"'set protocols static {mynet} dev lo' "
                      "'set protocols ospf interface eth1' "
                      "'set protocols ospf area 0.0.0.0' "
                      "'set protocols ospf network-type point-to-point' "
                      "'set protocols ospf redistribute static' "
                      "commit save exit "
                      "| sentinel configure\""
                  )
                  m.wait_for_unit("wren.service")

              configure(ospf1, "10.10.0.1", "10.11.0.0/24")
              configure(ospf2, "10.10.0.2", "10.12.0.0/24")

              # The compiled Wren config carries the OSPF block.
              ospf1.succeed("grep -q '\\[ospf\\]' /run/sentinel/wren.toml")

              # The headline: each router learns the OTHER's network over OSPF and
              # installs it into the kernel FIB (proto ospf). Adjacency + SPF take a
              # little while, so retry generously.
              ospf1.wait_until_succeeds(
                  "ip -4 route show proto ospf | grep -q '10.12.0.0/24'", timeout=120
              )
              ospf2.wait_until_succeeds(
                  "ip -4 route show proto ospf | grep -q '10.11.0.0/24'", timeout=120
              )

              # And the adjacency is Full.
              ospf1.succeed("wren show ospf neighbors | grep -qi full")
            '';
          };

        # Routing: RIPv2 (distance-vector) between two Sentinel appliances — a
        # third protocol paradigm alongside BGP (path-vector) and OSPF (link-
        # state), exercising the same `set protocols …` wiring. Each node
        # redistributes a unique static into RIP; each learns the other's proto rip.
        rip =
          let
            node = hostname: addr: {
              lib,
              ...
            }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce hostname;
              networking.firewall.enable = lib.mkForce false;
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = addr;
                  prefixLength = 24;
                }
              ];
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth1";
            };
          in
          pkgs.testers.runNixOSTest {
            name = "sentinel-rip";
            nodes = {
              rip1 = node "rip1" "10.10.0.1";
              rip2 = node "rip2" "10.10.0.2";
            };
            testScript = ''
              start_all()
              for m in (rip1, rip2):
                  m.wait_for_unit("multi-user.target")
                  m.wait_for_unit("velstra.service")
                  m.wait_for_unit("wren.service")
              rip1.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.1", timeout=20)
              rip2.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.2", timeout=20)

              def configure(m, mynet):
                  m.succeed(
                      "su admin -c \"printf '%s\\n' "
                      "'set firewall global default-action accept' "
                      "'set interface eth1 zone wan' "
                      f"'set protocols static {mynet} dev lo' "
                      "'set protocols rip interface eth1' "
                      "'set protocols rip redistribute static' "
                      "commit save exit "
                      "| sentinel configure\""
                  )
                  m.wait_for_unit("wren.service")

              configure(rip1, "10.11.0.0/24")
              configure(rip2, "10.12.0.0/24")

              # The compiled Wren config carries the RIP block.
              rip1.succeed("grep -q '\\[rip\\]' /run/sentinel/wren.toml")

              # Each router learns the OTHER's network over RIP (proto rip). RIP's
              # 30s update timer means convergence takes a while — retry generously.
              rip1.wait_until_succeeds(
                  "ip -4 route show proto rip | grep -q '10.12.0.0/24'", timeout=120
              )
              rip2.wait_until_succeeds(
                  "ip -4 route show proto rip | grep -q '10.11.0.0/24'", timeout=120
              )
            '';
          };

        # commit-confirm (roadmap C21): apply a change live under a timer that
        # auto-reverts to the saved config unless `confirm`ed — the safety net for
        # editing a firewall over its own link. One node; the hostname is the
        # observable (applied live by apply_live, reverted by the timer).
        #   nix build .#checks.x86_64-linux.commitconfirm -L
        commitconfirm = pkgs.testers.runNixOSTest {
          name = "sentinel-commitconfirm";
          nodes.machine = {
            imports = [ self.nixosModules.sentinel ];
            virtualisation.memorySize = 2048;
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("sentinel-boot.service")
            machine.wait_for_unit("velstra.service")

            # Baseline: a valid config with a known hostname, SAVED so
            # commit-confirm has a known-good config to revert to. Everything but
            # the hostname stays constant across the test, so the hostname alone
            # is the observable of "applied" vs "reverted".
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set firewall global default-action accept' "
                "'set interface eth0 zone wan' 'set interface eth0 address dhcp' "
                "'set system hostname fw-base' "
                "commit save exit "
                "| sentinel configure\""
            )
            machine.succeed("hostname | grep -x fw-base")
            machine.succeed("grep -q 'fw-base' /var/lib/sentinel/appliance.toml")

            # --- commit-confirm + confirm (keep the change) ---------------------
            # A 10-minute window: the new hostname is applied live AND the
            # auto-rollback timer is armed.
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set system hostname fw-c1' 'commit-confirm 10' exit "
                "| sentinel configure\""
            )
            machine.succeed("hostname | grep -x fw-c1")
            machine.succeed("systemctl is-active sentinel-confirm.timer")
            # `confirm` cancels the timer; the change stays live.
            machine.succeed(
                "su admin -c \"printf '%s\\n' confirm exit | sentinel configure\""
            )
            machine.wait_until_fails("systemctl is-active sentinel-confirm.timer", timeout=20)
            machine.succeed("hostname | grep -x fw-c1")
            # commit-confirm never persists: the saved baseline is untouched.
            machine.succeed("grep -q 'fw-base' /var/lib/sentinel/appliance.toml")

            # --- commit-confirm + manual confirm-rollback (revert now) ----------
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set system hostname fw-c2' 'commit-confirm 10' exit "
                "| sentinel configure\""
            )
            machine.succeed("hostname | grep -x fw-c2")
            machine.succeed("systemctl is-active sentinel-confirm.timer")
            # Forcing the revert (the exact command the timer runs) restores the
            # saved config and disarms the timer.
            machine.succeed("sentinel confirm-rollback")
            machine.succeed("hostname | grep -x fw-base")
            machine.wait_until_fails("systemctl is-active sentinel-confirm.timer", timeout=20)

            # --- the real timer fires and auto-reverts (the headline) -----------
            # A 1-minute window with NO confirm: the transient systemd timer runs
            # `sentinel confirm-rollback` on its own and the box returns to the
            # saved config — the lock-yourself-out safety net, proven end to end.
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set system hostname fw-c3' 'commit-confirm 1' exit "
                "| sentinel configure\""
            )
            machine.succeed("hostname | grep -x fw-c3")
            machine.succeed("systemctl is-active sentinel-confirm.timer")
            machine.wait_until_succeeds("hostname | grep -x fw-base", timeout=120)
          '';
        };

        # Config archive + rollback-N (roadmap C21): each `save` archives a
        # timestamped revision; `show system commit` lists them (newest = 0);
        # `rollback <N>` reverts the running system to revision N. One node; the
        # hostname is the observable across three saved revisions.
        #   nix build .#checks.x86_64-linux.confighistory -L
        confighistory = pkgs.testers.runNixOSTest {
          name = "sentinel-confighistory";
          nodes.machine = {
            imports = [ self.nixosModules.sentinel ];
            virtualisation.memorySize = 2048;
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("sentinel-boot.service")
            machine.wait_for_unit("velstra.service")

            # Three saved revisions, each changing only the hostname (the baseline
            # is set once and retained by the loaded draft). commit+save so the
            # live hostname tracks the saved one and each save archives a revision.
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set firewall global default-action accept' "
                "'set interface eth0 zone wan' 'set interface eth0 address dhcp' "
                "'set system hostname rev-a' commit save exit "
                "| sentinel configure\""
            )
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set system hostname rev-b' commit save exit | sentinel configure\""
            )
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set system hostname rev-c' commit save exit | sentinel configure\""
            )
            machine.succeed("hostname | grep -x rev-c")

            # The archive holds >=3 revisions; `show system commit` lists them
            # newest-first (one 'UTC' timestamp per revision row).
            listing = machine.succeed("sentinel show system commit")
            assert listing.count("UTC") >= 3, listing
            machine.succeed(
                "test $(ls /var/lib/sentinel/archive/config-*.toml | wc -l) -ge 3"
            )

            # Revision 0 (newest) is rev-c; revision 1 is the previous save rev-b.
            rev0 = machine.succeed("sentinel show system commit 0")
            assert "rev-c" in rev0, rev0
            rev1 = machine.succeed("sentinel show system commit 1")
            assert "rev-b" in rev1, rev1

            # `compare` against history: the candidate (rev-c) vs revision 1
            # (rev-b) shows the hostname change; revision 0 vs revision 2 too.
            cmp = machine.succeed(
                "su admin -c \"printf '%s\\n' 'compare 1' exit | sentinel configure\" 2>&1"
            )
            assert "rev-b" in cmp and "rev-c" in cmp, cmp
            cmp2 = machine.succeed(
                "su admin -c \"printf '%s\\n' 'compare 0 2' exit | sentinel configure\" 2>&1"
            )
            assert "rev-a" in cmp2 and "rev-c" in cmp2, cmp2

            # rollback 1 reverts the RUNNING system to rev-b (applied live) and
            # re-saves it — the headline.
            machine.succeed(
                "su admin -c \"printf '%s\\n' 'rollback 1' exit | sentinel configure\""
            )
            machine.succeed("hostname | grep -x rev-b")
            machine.succeed("grep -q 'rev-b' /var/lib/sentinel/appliance.toml")
            # The rollback itself archived a new newest revision (rev-b again).
            rev0b = machine.succeed("sentinel show system commit 0")
            assert "rev-b" in rev0b, rev0b

            # An out-of-range rollback is refused cleanly; nothing changes.
            out = machine.succeed(
                "su admin -c \"printf '%s\\n' 'rollback 999' exit | sentinel configure\" 2>&1"
            )
            assert "no revision 999" in out, out
            machine.succeed("hostname | grep -x rev-b")
          '';
        };

        # Firewall groups / aliases (roadmap C15): a rule referencing an
        # address-group and a port-group expands at compile time to the full
        # (sources × ports) product of data-plane rules. One node; proof is the
        # compiled velstra.toml + the agent accepting it + the config render.
        #   nix build .#checks.x86_64-linux.fwgroups -L
        fwgroups = pkgs.testers.runNixOSTest {
          name = "sentinel-fwgroups";
          nodes.machine = {
            imports = [ self.nixosModules.sentinel ];
            virtualisation.memorySize = 2048;
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("sentinel-boot.service")
            machine.wait_for_unit("velstra.service")

            # Define an address-group (2 CIDRs) and a port-group (2 ports), then a
            # single rule that references both.
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set firewall global default-action accept' "
                "'set interface eth0 zone wan' 'set interface eth0 address dhcp' "
                "'set firewall group address-group mgmt address 10.0.0.0/24,192.0.2.5' "
                "'set firewall group port-group webports port 80,443' "
                "'set firewall rule web from wan' 'set firewall rule web to wan' "
                "'set firewall rule web action accept' 'set firewall rule web proto tcp' "
                "'set firewall rule web source-group mgmt' "
                "'set firewall rule web port-group webports' "
                "commit save exit "
                "| sentinel configure\""
            )

            # The compiled config carries the expanded product: 2 sources × 2
            # ports = 4 data-plane port rules, each with its src CIDR and a port.
            velstra = machine.succeed("cat /run/sentinel/velstra.toml")
            assert velstra.count("[[policy.port_rule]]") == 4, velstra
            assert 'src = "10.0.0.0/24"' in velstra, velstra
            assert 'src = "192.0.2.5"' in velstra, velstra
            assert "port = 80" in velstra and "port = 443" in velstra, velstra
            # The agent parses the grouped/expanded config from scratch and stays up.
            machine.succeed("systemctl restart velstra.service")
            machine.wait_for_unit("velstra.service")

            # The saved config + `show configuration` render the aliases and the
            # rule's references to them.
            machine.succeed("grep -q 'mgmt' /var/lib/sentinel/appliance.toml")
            shown = machine.succeed("sentinel show configuration")
            assert "address-group mgmt" in shown, shown
            assert "port-group webports" in shown, shown
            assert "source-group mgmt" in shown, shown

            # A group still referenced by a rule can't be committed away — the rule
            # would dangle, and validation catches it.
            out = machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'delete firewall group address-group mgmt' commit exit "
                "| sentinel configure\" 2>&1"
            )
            assert "not a declared address group" in out, out

            # Dropping the rule first, then the groups, commits cleanly.
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'delete firewall rule web' "
                "'delete firewall group address-group mgmt' "
                "'delete firewall group port-group webports' "
                "commit save exit "
                "| sentinel configure\""
            )
            machine.succeed("! grep -q 'mgmt' /var/lib/sentinel/appliance.toml")
          '';
        };
      };
    };
}
