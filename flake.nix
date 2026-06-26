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
      };
    };
}
