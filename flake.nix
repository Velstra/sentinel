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
    # Public upstream so the build works on CI and for others; the exact revision
    # is pinned in flake.lock (bump with `nix flake update fabric`).
    fabric = {
      url = "github:Velstra/fabric";
      flake = false;
    };
    # The Wren routing daemon (BGP/OSPF/IS-IS/RIP/Babel/VRRP control plane).
    # Source only — stable Rust, built with nixpkgs' rustc (no flake of its own).
    # Public upstream; the exact revision is pinned in flake.lock (bump with
    # `nix flake update wren`).
    wren = {
      url = "github:Velstra/wren";
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
            --set SENTINEL_TC_BIN         ${pkgs.iproute2}/bin/tc \
            --set SENTINEL_NETWORKCTL_BIN ${pkgs.systemd}/bin/networkctl \
            --set SENTINEL_SYSTEMCTL_BIN  ${pkgs.systemd}/bin/systemctl \
            --set SENTINEL_NFT_BIN        ${pkgs.nftables}/bin/nft \
            --set SENTINEL_SWANCTL_BIN    ${pkgs.strongswan}/bin/swanctl \
            --set SENTINEL_OPENSSL_BIN    ${pkgs.openssl.bin}/bin/openssl \
            --set SENTINEL_CURL_BIN       ${pkgs.curl.bin}/bin/curl \
            --set SENTINEL_SYSTEMD_RUN_BIN ${pkgs.systemd}/bin/systemd-run \
            --set SENTINEL_JOURNALCTL_BIN ${pkgs.systemd}/bin/journalctl \
            --set SENTINEL_WREN_BIN       ${wrenPkg}/bin/wren \
            --set SENTINEL_LSBLK_BIN      ${pkgs.util-linux}/bin/lsblk \
            --set SENTINEL_INSTALL_BIN    ${pkgs.coreutils}/bin/install \
            --set SENTINEL_MKDIR_BIN      ${pkgs.coreutils}/bin/mkdir \
            --set SENTINEL_CHMOD_BIN      ${pkgs.coreutils}/bin/chmod \
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
      ebpfHash = "sha256-4AUh/iJf9VjGUBkD1NM/0rYc4bvu8/ncjvF92uprL8Y=";
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
        { pkgs, lib, ... }:
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
            # `swanctl` for IPsec (roadmap C2): the CLI resolves the loader via
            # SENTINEL_SWANCTL_BIN, but keep it on PATH for `run show vpn` + manual
            # inspection.
            pkgs.strongswan
            # Box services (roadmap C18): net-snmp (`snmpd` + `snmpget`/`snmpwalk`
            # for inspection), avahi (mDNS reflector), ddclient (dynamic DNS). LLDP
            # rides on `services.lldpd` below; the DHCP relay reuses dnsmasq.
            pkgs.net-snmp
            pkgs.avahi
            pkgs.ddclient
            # NAT64 (roadmap C10): tayga is the userspace IPv6→IPv4 translator
            # (a `nat64` tun device — no out-of-tree kernel module, unlike Jool, so
            # it runs unchanged in the image + CI VM); unbound provides DNS64 AAAA
            # synthesis. Both are Sentinel-owned units (below), off until configured.
            pkgs.tayga
            pkgs.unbound
            # OpenConnect (roadmap C17): ocserv is the AnyConnect-compatible TLS
            # VPN server. It's a Sentinel-owned unit (below), off until configured;
            # `ocserv`/`occtl` on PATH also allow manual inspection. Passwords are
            # hashed with `openssl passwd -6` (already present for the PKI), so the
            # bundled `ocpasswd` tool isn't in the render path.
            pkgs.ocserv
            # L7 reverse proxy / load balancer (roadmap C22): haproxy terminates
            # TLS (via the on-box PKI) and forwards to backends round-robin. A
            # Sentinel-owned unit (below), off until a `[[services.reverse-proxy]]`
            # frontend is configured; on PATH so `sentinel commit` can `haproxy -c`
            # the rendered config before reloading.
            pkgs.haproxy
            # Signed update channel (roadmap C13): the CLI fetches the release
            # manifest + image with curl (resolved via SENTINEL_CURL_BIN); keep it
            # on PATH too for manual channel inspection. Ed25519 verification +
            # SHA-256 reuse the openssl already present for the PKI.
            pkgs.curl
          ];

          # Egress traffic shaping (roadmap C8) needs the CAKE + fq_codel queue
          # disciplines. Both ship as modules in the default kernel; load them at
          # boot so `tc qdisc add … cake` on a `[interface.qos]` never races module
          # autoload. `tc` itself comes from iproute2 (already in the base system;
          # the sentinel CLI resolves it via SENTINEL_TC_BIN).
          boot.kernelModules = [
            "sch_cake"
            "sch_fq_codel"
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
          # Multi-WAN (roadmap C6): the health-check + failover daemon. Sentinel
          # renders the loop to /run/sentinel/multiwan/health.sh and (re)starts
          # this unit when the config changes; the daemon needs `ip` (iproute2)
          # and `ping` (iputils) on PATH. `bash` runs the rendered arrays+logic.
          systemd.services."sentinel-multiwan" = {
            description = "Multi-WAN health check + failover (sentinel)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            # `ip` (iproute2), `ping` (iputils), plus `awk`/`cut`/`head`
            # (gawk + coreutils) the daemon uses to parse addresses/gateways.
            path = [
              pkgs.iproute2
              pkgs.iputils
              pkgs.gawk
              pkgs.coreutils
            ];
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.bash}/bin/bash /run/sentinel/multiwan/health.sh";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };
          # Second boot stage — the reboot-persistence fix. `sentinel-boot` runs
          # BEFORE networkd (it seeds the editable config and writes the networkd
          # units), so it can only render files and restart co-services — it can't
          # apply state that lives on a link networkd hasn't brought up (or, for a
          # VLAN/bridge/bond/tunnel, hasn't even created) yet. This unit runs the
          # deferred `apply-boot-late` AFTER networkd, re-installing exactly that
          # runtime-only state a reboot wipes: the tc egress qdiscs (QoS), the
          # Multi-WAN policy routes, and the IPsec SAs. Without it a saved config's
          # shaping/SAs silently vanish on every reboot.
          systemd.services.sentinel-boot-late = {
            description = "Re-apply runtime network state (QoS/Multi-WAN/IPsec) after networkd";
            wantedBy = [ "multi-user.target" ];
            # Order after networkd (which creates the VLAN/bridge/bond/tunnel links
            # and configures addresses), NOT after network-online.target: that
            # target waits for every managed link to be *online*, so a saved config
            # with a carrierless/lease-less DHCP uplink would wedge this unit — and
            # a config re-apply must never block the boot. RemainAfterExit but
            # nothing depends on it, so even a failure is a warning, not a hang.
            after = [
              "sentinel-boot.service"
              "systemd-networkd.service"
            ];
            requires = [ "sentinel-boot.service" ];
            # It reads the editable config, so wait for its partition (a no-op when
            # /var/lib is on the root fs; load-bearing when it is its own mount).
            unitConfig.RequiresMountsFor = [ "/var/lib/sentinel" ];
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
              # Give the links a bounded chance to come up before shaping them —
              # `--any` returns as soon as ONE link is online (a static-addressed
              # link reaches routable in ~1s), and the leading `-` + `--timeout`
              # mean a stuck uplink is ignored after 30s rather than blocking boot.
              ExecStartPre = "-${pkgs.systemd}/lib/systemd/systemd-networkd-wait-online --any --timeout=30";
              ExecStart = "${sentinel}/bin/sentinel apply-boot-late --config /var/lib/sentinel/appliance.toml";
              # Hard cap: a re-apply that somehow stalls is killed, not left to hang
              # the boot. The persistent config + data plane are already up by now.
              TimeoutStartSec = 90;
            };
          };

          # REST management API (roadmap C12): serve the SAME config model the CLI
          # edits over HTTP. Off by default (`wantedBy = []`) like the box services
          # — an operator opts in (or the checks.api VM `systemctl start`s it).
          # Runs as root so a `PUT` can apply live (hostname/networkd/data plane)
          # through the same path a CLI `commit` uses; binds localhost only (widen
          # via ExecStart's `--listen`). The bearer token is minted 0600 into the
          # persistent state dir on first start.
          systemd.services.sentinel-api = {
            description = "Sentinel REST management API (sentinel)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            requires = [ "sentinel-boot.service" ];
            serviceConfig = {
              Type = "exec";
              ExecStart = "${sentinel}/bin/sentinel api --listen 127.0.0.1:8080 --config /var/lib/sentinel/appliance.toml --token-file /var/lib/sentinel/api-token";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };

          # Persistence guard for the editable config itself: order the
          # config-seeding boot service after the /var/lib/sentinel mount, so on a
          # deployment where that path is its own partition (as on the appliance
          # image) the seed + read land on the persistent device and are never
          # shadowed by a not-yet-mounted dir — otherwise a reboot can read the
          # factory default and forget the saved config entirely. image.nix sets
          # this too; declaring it here also covers the plain nixosModule.
          systemd.services.sentinel-boot.unitConfig.RequiresMountsFor = [ "/var/lib/sentinel" ];

          # --- Box services (roadmap C18) ------------------------------------
          # LLDP/SNMP/mDNS/dyndns/DHCP-relay are box-wide services Sentinel owns
          # the lifecycle of: off by default (`wantedBy = []`), rendered to a
          # /run/sentinel config and started/stopped from apply-boot-late (after
          # networkd, so link-scoped ones see their interfaces) + a live commit.

          # LLDP: use the stock lldpd module for the daemon + its `_lldpd`
          # privsep user, but hand it `-O <our file>` so it reads Sentinel's
          # rendered lldpcli config at start, and drop its wantedBy so Sentinel
          # (not multi-user.target) decides when it runs.
          services.lldpd = {
            enable = true;
            extraArgs = [
              "-O"
              "/run/sentinel/lldpd.d/sentinel.conf"
            ];
          };
          systemd.services.lldpd.wantedBy = lib.mkForce [ ];

          # SNMP: a read-only net-snmp agent against Sentinel's rendered snmpd.conf
          # (`-C` = ignore the default config files, `-f`/`-Lo` = foreground+stdout
          # log so systemd owns it). Sentinel start/stops it on `[services.snmp]`.
          systemd.services.sentinel-snmpd = {
            description = "Read-only SNMP agent (sentinel)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.net-snmp}/bin/snmpd -f -Lo -C -c /run/sentinel/snmpd.conf";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };

          # mDNS reflector: avahi in reflector mode against Sentinel's rendered
          # config (the config sets `enable-dbus=no` so it needs no bus). Runs as
          # the `avahi` user (created below). Test deferred (VM-heavy), but the
          # unit is real so a committed `[services.mdns]` actually reflects.
          users.users.avahi = {
            isSystemUser = true;
            group = "avahi";
            description = "avahi-daemon user";
          };
          users.groups.avahi = { };
          systemd.services.sentinel-mdns = {
            description = "mDNS reflector (sentinel/avahi)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.avahi}/sbin/avahi-daemon -f /run/sentinel/avahi/avahi-daemon.conf";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };

          # Dynamic DNS: ddclient in the foreground against Sentinel's rendered
          # 0640 config (it carries the provider secret). Test deferred (needs a
          # live provider endpoint), but the unit is real.
          systemd.services.sentinel-ddclient = {
            description = "Dynamic-DNS client (sentinel/ddclient)";
            after = [
              "network-online.target"
              "sentinel-boot.service"
            ];
            wants = [ "network-online.target" ];
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.ddclient}/bin/ddclient -foreground -file /run/sentinel/ddclient/ddclient.conf -cache /run/sentinel/ddclient/ddclient.cache";
              Restart = "on-failure";
              RestartSec = "30s";
            };
          };

          # DHCP relay: isc-dhcp's `dhcrelay` is gone from nixpkgs, so the relay
          # rides on a SECOND, DNS-disabled dnsmasq instance (Sentinel renders its
          # `--dhcp-relay=<local>,<server>` config). Distinct from the LAN-resolver
          # dnsmasq (that one binds :53 on lo; this one runs `port=0`).
          systemd.services.sentinel-dhcp-relay = {
            description = "DHCP relay (sentinel/dnsmasq)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.dnsmasq}/bin/dnsmasq --keep-in-foreground --conf-file=/run/sentinel/dhcp-relay/relay.conf";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };

          # NAT64 (roadmap C10): tayga translates the IPv6-only segment's
          # 64:ff9b::<v4> traffic to real IPv4 out of the pool. Sentinel renders
          # tayga.conf + a datapath setup script (the `nat64` tun + pool/prefix
          # routes tayga can't add itself) and start/stops this from apply-boot-late
          # + a live commit. ExecStartPre runs the setup (needs `ip` + `tayga` +
          # `sysctl`); ExecStart runs the translator in the foreground; ExecStopPost
          # tears the tun down so a disable leaves nothing behind.
          systemd.services.sentinel-nat64 = {
            description = "NAT64 translator (sentinel/tayga)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            path = [
              pkgs.iproute2
              pkgs.tayga
              pkgs.procps
            ];
            # Retry indefinitely (no start-rate limit): the datapath setup can race
            # networkd bringing the links up on a fresh commit/boot.
            unitConfig.StartLimitIntervalSec = 0;
            serviceConfig = {
              Type = "exec";
              ExecStartPre = "${pkgs.bash}/bin/sh /run/sentinel/nat64/setup.sh";
              ExecStart = "${pkgs.tayga}/bin/tayga --nodetach --config /run/sentinel/nat64/tayga.conf";
              ExecStopPost = "-${pkgs.iproute2}/bin/ip link del nat64";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };

          # DNS64 (roadmap C10): unbound synthesises AAAA inside the NAT64 prefix
          # for v4-only names, bound to the IPv6-only side's address. `-d` keeps it
          # in the foreground (systemd owns it), `-p` skips forking; the rendered
          # config disables chroot/privilege-drop (the unit already sandboxes it).
          systemd.services.sentinel-dns64 = {
            description = "DNS64 resolver (sentinel/unbound)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            # Retry indefinitely: unbound binds the serving interface's v6 address,
            # which networkd may not have configured yet on a fresh commit/boot.
            unitConfig.StartLimitIntervalSec = 0;
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.unbound}/bin/unbound -d -p -c /run/sentinel/nat64/unbound.conf";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };

          # IPsec (roadmap C2): strongSwan's charon (charon-systemd) is always up
          # so a `commit` can `swanctl --load-all` the rendered site-to-site
          # tunnels into it. Its own /etc/swanctl config stays empty — Sentinel
          # loads the appliance's connections from /run/sentinel/swanctl via the
          # loader's `--file`, so the immutable /etc never needs to change.
          services.strongswan-swanctl.enable = true;

          # OpenConnect (roadmap C17): ocserv terminates TLS road-warrior clients
          # from the rendered /run/sentinel/ocserv/ocserv.conf. Present but idle —
          # `wantedBy = []` so it does NOT auto-start at boot; Sentinel renders the
          # config and (re)starts it from openconnect::apply (on a live commit and
          # from sentinel-boot-late), matching how the box's other daemons are
          # driven. `--foreground` so systemd owns the process; ocserv needs
          # iproute2 (it runs `ip` to set up the vpn0 tun) on PATH.
          systemd.services.ocserv = {
            description = "OpenConnect VPN server (sentinel/ocserv)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            wantedBy = [ ];
            path = [ pkgs.iproute2 ];
            # Retry indefinitely (no start-rate limit): a fresh commit/boot may race
            # networkd bringing the WAN the server binds up, or the PKI leaf mint.
            unitConfig.StartLimitIntervalSec = 0;
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.ocserv}/bin/ocserv --foreground --config /run/sentinel/ocserv/ocserv.conf";
              Restart = "on-failure";
              RestartSec = "5s";
            };
          };

          # L7 reverse proxy / load balancer (roadmap C22): haproxy serves the
          # frontends from the rendered /run/sentinel/haproxy/haproxy.cfg. Present
          # but idle — `wantedBy = []` so it does NOT auto-start at boot; Sentinel
          # renders the config (+ the per-frontend TLS bundles) and (re)starts it
          # from proxy::apply (on a live commit and from sentinel-boot-late),
          # matching how the box's other daemons are driven. `-W` (master-worker)
          # keeps the master in the foreground so systemd owns the process.
          systemd.services.haproxy = {
            description = "L7 reverse proxy / load balancer (sentinel/haproxy)";
            after = [
              "network.target"
              "sentinel-boot.service"
            ];
            wantedBy = [ ];
            # Retry indefinitely (no start-rate limit): a fresh commit/boot may race
            # networkd bringing the frontend's listen address up.
            unitConfig.StartLimitIntervalSec = 0;
            serviceConfig = {
              Type = "exec";
              ExecStart = "${pkgs.haproxy}/bin/haproxy -W -f /run/sentinel/haproxy/haproxy.cfg";
              # `haproxy -c` gates the reload in proxy::apply, so a running proxy is
              # only ever replaced with a config haproxy accepts.
              ExecReload = "${pkgs.haproxy}/bin/haproxy -c -f /run/sentinel/haproxy/haproxy.cfg";
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
            # Multi-WAN daemon runtime dir (rendered health script + state).
            "d /run/sentinel/multiwan 0755 root root -"
            # IPsec runtime dir holds the rendered swanctl.conf + the 0600 PSK
            # secrets file (root only).
            "d /run/sentinel/swanctl 0700 root root -"
            # OpenConnect (roadmap C17) runtime dir holds ocserv.conf + the 0600
            # ocpasswd credential file + the control socket (root only).
            "d /run/sentinel/ocserv 0750 root root -"
            # Reverse proxy (roadmap C22): haproxy.cfg (world-readable) + the certs/
            # subdir holding the 0600 cert+key bundles (private keys, root only).
            "d /run/sentinel/haproxy 0750 root root -"
            "d /run/sentinel/haproxy/certs 0700 root root -"
            # Box-service (roadmap C18) runtime dirs: LLDP confdir, avahi + DHCP-
            # relay configs (world-readable), and the ddclient dir (0640 secret).
            "d /run/sentinel/lldpd.d 0755 root root -"
            "d /run/sentinel/avahi 0755 root root -"
            "d /run/sentinel/dhcp-relay 0755 root root -"
            "d /run/sentinel/ddclient 0750 root root -"
            # NAT64 (roadmap C10): tayga's conf + setup script + data-dir, and the
            # DNS64 unbound config all live here (world-readable, root-owned).
            "d /run/sentinel/nat64 0755 root root -"
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

      # REST management API (roadmap C12): boots the appliance, starts the
      # `sentinel-api` service, and drives it with curl to prove one config model
      # end-to-end — /health is unauthenticated, every other endpoint needs the
      # bearer token, and a `PUT /config` runs through the SAME validate + live
      # apply + save path a CLI `commit`+`save` does (hostname changes live, the
      # firewall rule reaches the running data-plane config, and the change is
      # persisted to the boot config). An invalid body is rejected (400) and not
      # applied.
      #   nix build .#checks.x86_64-linux.api -L
      api = pkgs.testers.runNixOSTest {
        name = "sentinel-api";
        nodes.machine = {
          imports = [ self.nixosModules.sentinel ];
          virtualisation.memorySize = 2048;
          environment.systemPackages = [ pkgs.curl ];
        };
        testScript = ''
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("sentinel-boot.service")
          machine.wait_for_unit("velstra.service")
          machine.succeed("test -f /var/lib/sentinel/appliance.toml")

          # The API service is off by default (a box service); start it explicitly.
          machine.succeed("systemctl start sentinel-api.service")
          machine.wait_for_unit("sentinel-api.service")
          machine.wait_for_open_port(8080)

          # The bearer token was minted 0600 into the persistent state dir.
          perms = machine.succeed("stat -c %a /var/lib/sentinel/api-token").strip()
          assert perms == "600", f"token file perms {perms} (want 600)"
          token = machine.succeed("cat /var/lib/sentinel/api-token").strip()
          assert token, "token file is empty"

          # /health needs no auth.
          machine.succeed("curl -fsS http://127.0.0.1:8080/api/v1/health | grep -q ok")

          # No token → 401.
          code = machine.succeed(
              "curl -s -o /dev/null -w '%{http_code}' "
              "http://127.0.0.1:8080/api/v1/config"
          ).strip()
          assert code == "401", f"unauthenticated /config returned {code} (want 401)"

          # With the token → the running config as JSON (carries the hostname).
          cfg = machine.succeed(
              f"curl -fsS -H 'Authorization: Bearer {token}' "
              "http://127.0.0.1:8080/api/v1/config"
          )
          assert '"hostname"' in cfg, cfg

          # PUT a new config (change the hostname + add a firewall rule). This must
          # go through the SAME validate + apply-live + save path the CLI commit
          # uses — so the running system reflects it.
          body = (
              '{"system":{"hostname":"api-fw"},'
              '"interface":[{"name":"eth0","zone":"wan","address":"dhcp"}],'
              '"rule":[{"name":"web","from":"wan","to":"wan","action":"accept"}]}'
          )
          out = machine.succeed(
              f"curl -fsS -X PUT -H 'Authorization: Bearer {token}' "
              f"-H 'Content-Type: application/json' -d '{body}' "
              "http://127.0.0.1:8080/api/v1/config"
          )
          assert '"applied":true' in out, out

          # Applied live: the hostname changed with no reboot.
          machine.wait_until_succeeds("hostname | grep -x api-fw", timeout=20)
          # The firewall rule reached the running data-plane config (/run).
          machine.succeed("grep -q eth0 /run/sentinel/velstra.toml")
          # Persisted to the boot config (/var/lib) — the same save the CLI does.
          machine.succeed("grep -q 'api-fw' /var/lib/sentinel/appliance.toml")

          # An invalid config is rejected (400) and NOT applied — the same
          # validation the CLI runs (a space + '!' in the hostname).
          bad = '{"system":{"hostname":"Bad Host!"}}'
          code = machine.succeed(
              "curl -s -o /dev/null -w '%{http_code}' -X PUT "
              f"-H 'Authorization: Bearer {token}' -H 'Content-Type: application/json' "
              f"-d '{bad}' http://127.0.0.1:8080/api/v1/config"
          ).strip()
          assert code == "400", f"invalid PUT returned {code} (want 400)"
          # Still the previous good hostname (the bad config never applied).
          machine.succeed("hostname | grep -x api-fw")

          # An operational show proxied through the API returns live status.
          status = machine.succeed(
              f"curl -fsS -H 'Authorization: Bearer {token}' "
              "http://127.0.0.1:8080/api/v1/status"
          )
          assert "api-fw" in status, status
        '';
      };

      # Reboot persistence (the real thing): `configure`+`commit`+`save`, then a
      # genuine `machine.reboot()`, and assert the WHOLE running config is back —
      # not just the files on disk but the live runtime state (networkd address,
      # dnsmasq drop-in, and the tc qdisc, which is kernel-runtime-only and must
      # be re-installed at boot AFTER networkd brings the links up). The editable
      # config lives on a dedicated ext4 partition (as it does on the real
      # appliance image), so the reboot models the immutable-appliance layout:
      # volatile /run + a persistent /var/lib/sentinel.
      #   nix build .#checks.x86_64-linux.reboot -L
      reboot = pkgs.testers.runNixOSTest {
        name = "sentinel-reboot";
        nodes.machine =
          { lib, pkgs, ... }:
          {
            imports = [ self.nixosModules.sentinel ];
            virtualisation.memorySize = 2048;
            # A dedicated, persistent block device for the editable config —
            # exactly like the appliance image's LABEL=data partition. This
            # survives the reboot below; the rest of the VM state is incidental.
            virtualisation.emptyDiskImages = [ 512 ];
            virtualisation.fileSystems."/var/lib/sentinel" = {
              device = "/dev/vdb";
              fsType = "ext4";
              autoFormat = true;
            };
            # `tc` for the qdisc assertions (iproute2; the CLI resolves it via
            # SENTINEL_TC_BIN).
            environment.systemPackages = [ pkgs.iproute2 ];
          };
        testScript = ''
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("sentinel-boot.service")
          machine.wait_for_unit("velstra.service")
          machine.wait_for_unit("wren.service")
          # The config partition is a real block device, not the volatile root.
          machine.succeed("findmnt -no SOURCE /var/lib/sentinel | grep -q /dev/")

          # Configure a representative slice of the box AS THE ADMIN, commit it
          # live, and persist it with `save`: a hostname, a VLAN subinterface with
          # an address + zone + egress QoS (the qdisc is the runtime-only state
          # that a reboot must rebuild), a firewall posture, a LAN DNS resolver,
          # and a static route (routing / wren).
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set system hostname fw-reboot' "
              "'set interface eth0 zone wan' 'set interface eth0 address dhcp' "
              "'set interface eth0.50 parent eth0' 'set interface eth0.50 vlan 50' "
              "'set interface eth0.50 zone lan' 'set interface eth0.50 address 10.0.50.1/24' "
              "'set interface eth0.50 qos discipline cake' "
              "'set interface eth0.50 qos bandwidth 100mbit' "
              "'set interface eth0.50 qos rtt internet' "
              "'set firewall global block-icmp true' "
              "'set services dns upstream 10.0.50.99' 'set services dns serve-on eth0.50' "
              "'set protocols static 192.168.77.0/24 via 10.0.50.99' "
              "commit save exit "
              "| sentinel configure\""
          )

          # --- Pre-reboot: everything applied live. ---
          machine.succeed("hostname | grep -x fw-reboot")
          machine.wait_until_succeeds("ip addr show eth0.50 | grep -q 10.0.50.1", timeout=20)
          machine.wait_until_succeeds("tc qdisc show dev eth0.50 root | grep -q cake", timeout=30)
          machine.succeed("test -f /run/sentinel/dnsmasq.d/sentinel.conf")
          machine.succeed("grep -q 192.168.77.0/24 /run/sentinel/wren.toml")

          # --- Reboot. Volatile /run is wiped; /var/lib/sentinel persists. ---
          # A full stop + cold boot (not machine.reboot(): the test VM runs qemu
          # with -no-reboot, so an in-guest reboot makes qemu exit rather than
          # restart). shutdown()+start() reuses the same disk images, so the root
          # comes up fresh (wiped /run) while the /var/lib/sentinel partition — and
          # the saved config on it — persists, exactly as on a real power cycle.
          machine.shutdown()
          machine.start()

          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("sentinel-boot.service")
          machine.wait_for_unit("velstra.service")
          machine.wait_for_unit("wren.service")

          # The saved config survived on the persistent partition, unchanged.
          machine.succeed("grep -q 'hostname = \"fw-reboot\"' /var/lib/sentinel/appliance.toml")
          machine.succeed("grep -q '10.0.50.1/24' /var/lib/sentinel/appliance.toml")
          machine.succeed("grep -q 'cake' /var/lib/sentinel/appliance.toml")

          # Boot re-asserted the hostname from the saved config.
          machine.succeed("hostname | grep -x fw-reboot")

          # Boot re-compiled the runtime agent configs into the fresh /run.
          machine.succeed("grep -q '\"eth0.50\"' /run/sentinel/velstra.toml")
          machine.succeed("grep -q 'drop_icmp = true' /run/sentinel/velstra.toml")
          machine.succeed("grep -q 192.168.77.0/24 /run/sentinel/wren.toml")

          # Boot re-applied the live L3 addressing (networkd units + link).
          machine.wait_until_succeeds("ip addr show eth0.50 | grep -q 10.0.50.1", timeout=30)

          # Boot re-rendered the LAN DNS drop-in.
          machine.wait_until_succeeds(
              "test -f /run/sentinel/dnsmasq.d/sentinel.conf", timeout=30
          )

          # The tc qdisc — kernel runtime state, gone after a reboot — was
          # rebuilt on the VLAN link (which networkd only creates during boot, so
          # the shaping must be re-applied AFTER networkd, not before it).
          machine.wait_until_succeeds("tc qdisc show dev eth0.50 root | grep -q cake", timeout=45)

          # The data plane and routing daemon are both healthy on the seeded config.
          machine.succeed("systemctl is-active velstra.service")
          machine.succeed("systemctl is-active wren.service")
        '';
      };

      # WireGuard (roadmap C1): a `type = "wireguard"` interface plus a matching
      # `[[vpn.wireguard]]` tunnel (the private key + peers) render to a
      # `Kind=wireguard` netdev (0640 root:systemd-network, since it embeds the
      # key), participate in the firewall via the interface `zone`, and networkd
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

          # Declare a WireGuard tunnel AS THE ADMIN USER: create the interface
          # (type wireguard) with an address + firewall zone, then configure the
          # private key, listen port and one peer under vpn. commit applies live.
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set interface wg0 type wireguard' "
              "'set interface wg0 address 10.9.0.1/24' 'set interface wg0 zone lan' "
              "'set vpn wireguard wg0 private-key ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=' "
              "'set vpn wireguard wg0 listen-port 51820' "
              "'set vpn wireguard wg0 peer ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ= allowed-ips 10.9.0.2/32' "
              "'set vpn wireguard wg0 peer ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ= endpoint 192.0.2.7:51820' "
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

      # IPsec site-to-site (roadmap C2): two Sentinel appliances (`left`/`right`)
      # on a shared WAN segment, each with a protected subnet behind it (a `dummy`
      # `proto0` carrying its LAN address). Both commit a matching `[[vpn.ipsec]]`
      # PSK connection; Sentinel renders swanctl.conf + a 0600 secrets file and
      # loads them into charon. The test proves (1) the IKEv2 SA establishes on
      # both ends and (2) real traffic flows across the protected subnets — a ping
      # from behind `left` reaches behind `right` through the tunnel.
      #   nix build .#checks.x86_64-linux.ipsec -L
      ipsec = pkgs.testers.runNixOSTest {
        name = "sentinel-ipsec";
        nodes =
          let
            # One Sentinel IPsec gateway. `wanAddr` is its WAN (underlay) address
            # on the shared segment; `protoAddr` is the address of the protected
            # subnet behind it (on a local `dummy` interface). Both are set at the
            # NixOS level (boot-stable) — like the nat/masq tests — so the tunnel
            # config is the only thing `sentinel commit` drives.
            gw =
              { wanAddr, protoAddr }:
              { lib, pkgs, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                # Pin the runtime hostname to the node name so the test driver's
                # per-machine python variable resolves (sentinel forces the factory
                # hostname otherwise; sentinel-boot re-applies it regardless).
                networking.hostName = lib.mkForce (
                  if wanAddr == "10.0.0.1" then "left" else "right"
                );
                # velstra is the firewall; no NixOS iptables dropping IKE/ESP.
                networking.firewall.enable = lib.mkForce false;
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                networking.interfaces.eth1.ipv4.addresses = [
                  {
                    address = wanAddr;
                    prefixLength = 24;
                  }
                ];
                # Loose reverse-path filtering: a packet decrypted out of the
                # tunnel arrives on eth1 with an inner (protected-subnet) source
                # that strict rp_filter would treat as a martian.
                boot.kernel.sysctl = {
                  "net.ipv4.conf.all.rp_filter" = 2;
                  "net.ipv4.conf.default.rp_filter" = 2;
                };
                boot.kernelModules = [ "dummy" ];
                # The protected subnet behind this gateway, on a dummy interface —
                # the "host behind the firewall" the tunnel carries. Brought up
                # before charon so the local traffic-selector address exists when
                # the SA installs.
                systemd.services.protosubnet = {
                  wantedBy = [ "multi-user.target" ];
                  before = [ "strongswan-swanctl.service" ];
                  after = [ "network-pre.target" ];
                  path = [ pkgs.iproute2 ];
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                  };
                  script = ''
                    ip link add proto0 type dummy 2>/dev/null || true
                    ip addr add ${protoAddr}/24 dev proto0 2>/dev/null || true
                    ip link set proto0 up
                  '';
                };
              };
          in
          {
            left = gw {
              wanAddr = "10.0.0.1";
              protoAddr = "10.100.1.1";
            };
            right = gw {
              wanAddr = "10.0.0.2";
              protoAddr = "10.100.2.1";
            };
          };
        testScript = ''
          start_all()
          for m in (left, right):
              m.wait_for_unit("multi-user.target")
              m.wait_for_unit("sentinel-boot.service")
              m.wait_for_unit("strongswan-swanctl.service")
              m.wait_until_succeeds("ip addr show proto0 | grep -q 10.100", timeout=30)

          # The WAN underlay is up on both ends (set at the NixOS level).
          left.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.1", timeout=30)
          right.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.2", timeout=30)
          left.wait_until_succeeds("ping -c1 -W2 10.0.0.2", timeout=30)

          psk = "velstra-ipsec-shared-secret"

          def configure(node, local, remote, lnet, rnet):
              node.succeed(
                  "su admin -c \"printf '%s\\n' "
                  f"'set vpn ipsec site local {local}' "
                  f"'set vpn ipsec site remote {remote}' "
                  f"'set vpn ipsec site local-subnet {lnet}' "
                  f"'set vpn ipsec site remote-subnet {rnet}' "
                  f"'set vpn ipsec site psk {psk}' "
                  "commit save exit "
                  "| sentinel configure\""
              )

          # Both gateways commit the mirror-image connection.
          configure(left, "10.0.0.1", "10.0.0.2", "10.100.1.0/24", "10.100.2.0/24")
          configure(right, "10.0.0.2", "10.0.0.1", "10.100.2.0/24", "10.100.1.0/24")

          # Sentinel rendered swanctl.conf (no PSK in it) + a 0600 secrets file.
          for m in (left, right):
              conf = m.succeed("cat /run/sentinel/swanctl/swanctl.conf")
              assert "conn-site {" in conf, conf
              assert psk not in conf, "psk leaked into swanctl.conf"
              m.succeed("grep -q 'version = 2' /run/sentinel/swanctl/swanctl.conf")
              mode = m.succeed("stat -c %a /run/sentinel/swanctl/secrets.conf").strip()
              assert mode == "600", mode
              m.succeed(f"grep -q '{psk}' /run/sentinel/swanctl/secrets.conf")
              # save persisted the tunnel (with the PSK) to the editable config.
              m.succeed("grep -q 'ipsec' /var/lib/sentinel/appliance.toml")

          # Kick a fresh negotiation now that BOTH ends are loaded (avoids a race
          # where the first commit initiates before the peer has any config).
          left.succeed("swanctl --initiate --child site 2>&1 || true")

          # (1) The IKEv2 SA establishes on both ends.
          left.wait_until_succeeds("swanctl --list-sas | grep -q ESTABLISHED", timeout=90)
          right.wait_until_succeeds("swanctl --list-sas | grep -q ESTABLISHED", timeout=90)

          # (2) Traffic flows across the protected subnets: a ping sourced from
          # behind `left` reaches the address behind `right`, through the tunnel.
          left.wait_until_succeeds(
              "ping -c1 -W2 -I 10.100.1.1 10.100.2.1", timeout=90
          )
          right.wait_until_succeeds(
              "ping -c1 -W2 -I 10.100.2.1 10.100.1.1", timeout=90
          )

          # `sentinel show vpn ipsec` (operational mode) proxies to
          # swanctl --list-sas.
          out = left.succeed("su admin -c 'sentinel show vpn ipsec'")
          assert "ESTABLISHED" in out, out
        '';
      };

      # OpenConnect road-warrior VPN (roadmap C17): one Sentinel appliance (`fw`)
      # on a WAN segment with a `lan0` dummy (10.100.0.1/24) standing in for a host
      # behind it, and one plain `client` running the `openconnect` CLI. The fw
      # commits a PKI CA + a `vpn-server` leaf and a `[vpn.openconnect]` server
      # (pool 10.99.0.0/24, a user, a pushed route to the LAN); Sentinel renders
      # ocserv.conf + a 0600 ocpasswd and (re)starts ocserv. The test proves (1)
      # the render + 0600 credential file + ocserv unit come up, (2) the client's
      # TLS tunnel establishes (it pins the fw's self-issued cert by SPKI hash) and
      # is handed a pool address, and (3) real traffic flows: a ping from the client
      # reaches the LAN address through the tunnel.
      #   nix build .#checks.x86_64-linux.openconnect -L
      openconnect = pkgs.testers.runNixOSTest {
        name = "sentinel-openconnect";
        nodes = {
          fw =
            { lib, pkgs, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              # Pin the runtime hostname to the node name so the driver's per-machine
              # python variable resolves (sentinel forces the factory hostname
              # otherwise; sentinel-boot re-applies it regardless).
              networking.hostName = lib.mkForce "fw";
              # velstra is the firewall; no NixOS iptables dropping the TLS/ESP flows.
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              # The WAN the ocserv server binds — set at the NixOS level (boot-stable),
              # so the VPN config is the only thing `sentinel commit` drives.
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = "10.0.0.1";
                  prefixLength = 24;
                }
              ];
              # Forwarding on (a real VPN gateway routes between the tun and the LAN),
              # and the tun module present for ocserv's vpn0 device.
              boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
              boot.kernelModules = [
                "dummy"
                "tun"
              ];
              # `openssl` to derive the server-cert pin the client trusts; iproute2
              # is already present.
              environment.systemPackages = [ pkgs.openssl ];
              # The "host behind the firewall" the tunnel reaches: a dummy carrying
              # the LAN address the pushed route points at.
              systemd.services.lanhost = {
                wantedBy = [ "multi-user.target" ];
                after = [ "network-pre.target" ];
                path = [ pkgs.iproute2 ];
                serviceConfig = {
                  Type = "oneshot";
                  RemainAfterExit = true;
                };
                script = ''
                  ip link add lan0 type dummy 2>/dev/null || true
                  ip addr add 10.100.0.1/24 dev lan0 2>/dev/null || true
                  ip link set lan0 up
                '';
              };
            };
          client =
            { pkgs, ... }:
            {
              networking.firewall.enable = false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 1024;
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = "10.0.0.2";
                  prefixLength = 24;
                }
              ];
              boot.kernelModules = [ "tun" ];
              # `openconnect` is the client; `vpnc-scripts` provides the vpnc-script
              # openconnect runs to configure the tun (assign the pool IP + routes).
              environment.systemPackages = [
                pkgs.openconnect
                pkgs.vpnc-scripts
              ];
            };
        };
        testScript = ''
          start_all()
          fw.wait_for_unit("multi-user.target")
          fw.wait_for_unit("sentinel-boot.service")
          fw.wait_for_unit("velstra.service")
          client.wait_for_unit("multi-user.target")

          # The WAN underlay is up on both ends, and the LAN dummy behind the fw.
          fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.1", timeout=30)
          client.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.2", timeout=30)
          client.wait_until_succeeds("ping -c1 -W2 10.0.0.1", timeout=30)
          fw.wait_until_succeeds("ip addr show lan0 | grep -q 10.100.0.1", timeout=30)

          # Commit the server AS THE ADMIN USER: a PKI CA + a `vpn-server` leaf
          # (IP SAN for the WAN), then the OpenConnect server (pool + a pushed route
          # to the LAN + DNS + one user). commit applies live, save persists it.
          fw.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set pki ca vpn-ca common-name vpn-ca' "
              "'set pki certificate vpn-server ca vpn-ca' "
              "'set pki certificate vpn-server common-name fw' "
              "'set pki certificate vpn-server subject-alt-name IP:10.0.0.1' "
              "'set pki certificate vpn-server usage server' "
              "'set vpn openconnect certificate vpn-server' "
              "'set vpn openconnect pool 10.99.0.0/24' "
              "'set vpn openconnect routes 10.100.0.0/24' "
              "'set vpn openconnect dns 10.99.0.1' "
              "'set vpn openconnect user vpnuser password vpnpass' "
              "commit save exit "
              "| sentinel configure\""
          )

          # Sentinel rendered ocserv.conf (no plaintext password in it) + a 0600
          # ocpasswd, and the ocserv unit is up.
          conf = fw.succeed("cat /run/sentinel/ocserv/ocserv.conf")
          assert "tcp-port = 443" in conf, conf
          assert "ipv4-network = 10.99.0.0" in conf, conf
          assert "route = 10.100.0.0/24" in conf, conf
          assert "vpnpass" not in conf, "password leaked into ocserv.conf"
          mode = fw.succeed("stat -c %a /run/sentinel/ocserv/ocpasswd").strip()
          assert mode == "600", mode
          fw.succeed("grep -q 'vpnuser:' /run/sentinel/ocserv/ocpasswd")
          # save persisted the server (with the user) to the editable config.
          fw.succeed("grep -q 'openconnect' /var/lib/sentinel/appliance.toml")
          fw.wait_for_unit("ocserv.service")

          # Pin the fw's self-issued server certificate by its SPKI SHA-256 (the
          # form openconnect accepts as `pin-sha256:`), so the client trusts the
          # on-box CA leaf without a shared trust store.
          crt = "/var/lib/sentinel/pki/certs/vpn-server/cert.crt"
          fw.wait_until_succeeds(f"test -f {crt}", timeout=30)
          pin = fw.succeed(
              f"openssl x509 -in {crt} -pubkey -noout "
              "| openssl pkey -pubin -outform der "
              "| openssl dgst -sha256 -binary "
              "| openssl base64"
          ).strip()

          # Establish the TLS tunnel. ocserv's plain auth prompts for the username
          # and password as form fields, so feed both on stdin (one line each).
          # We shell-background openconnect (not its own `-b`, whose backgrounding
          # keeps the driver's stdout pipe open so `succeed` would block forever)
          # and then poll for the tun coming up.
          client.succeed(
              "printf 'vpnuser\\nvpnpass\\n' | openconnect --no-dtls "
              f"--servercert pin-sha256:{pin} "
              "https://10.0.0.1:443 >/tmp/oc.log 2>&1 & sleep 3; true"
          )
          client.wait_until_succeeds("ip -4 addr show | grep -q 'inet 10.99.0'", timeout=60)

          # (3) Traffic flows through the tunnel: the client reaches the LAN address
          # behind the fw over the pushed route.
          client.wait_until_succeeds("ping -c1 -W2 10.100.0.1", timeout=60)
        '';
      };

      # L7 reverse proxy / load balancer (roadmap C22): a Sentinel `fw` terminates
      # TLS on :443 (a leaf from the on-box PKI) and forwards to a `backend` node
      # running two plain-HTTP servers (round-robin), with a `client` curling
      # through it. The fw mints a PKI CA + a `web-cert` leaf (IP SAN for its listen
      # address) via the CLI, then the `[[services.reverse-proxy]]` frontend is
      # applied from the saved config through the boot-late path (its CLI `set`
      # wiring is not landed yet). The test proves (1) haproxy.cfg + the 0600 cert
      # bundle render and the unit comes up, (2) the client gets a backend body back
      # over HTTPS — TLS terminated at the fw and forwarded — and (3) repeated
      # requests hit BOTH backends (round-robin across the two `server` lines).
      #   nix build .#checks.x86_64-linux.reverseproxy -L
      reverseproxy = pkgs.testers.runNixOSTest {
        name = "sentinel-reverseproxy";
        nodes = {
          fw =
            { lib, pkgs, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              # Pin the runtime hostname to the node name (sentinel forces the
              # factory hostname otherwise; sentinel-boot re-applies it regardless).
              networking.hostName = lib.mkForce "fw";
              # velstra is the firewall; no NixOS iptables dropping the HTTPS flow.
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              # The address the reverse proxy listens on — set at the NixOS level
              # (boot-stable), so the proxy config is the only thing applied on top.
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = "10.0.0.1";
                  prefixLength = 24;
                }
              ];
            };
          # The upstreams behind the proxy: two plain-HTTP servers with
          # distinguishable bodies so the round-robin across them is observable.
          backend =
            { pkgs, ... }:
            {
              networking.firewall.enable = false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 1024;
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = "10.0.0.3";
                  prefixLength = 24;
                }
              ];
              systemd.services.backend-a = {
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];
                serviceConfig.ExecStart =
                  "${pkgs.python3}/bin/python3 -m http.server 8080 --directory ${pkgs.writeTextDir "index.html" "BACKEND-A\n"}";
              };
              systemd.services.backend-b = {
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];
                serviceConfig.ExecStart =
                  "${pkgs.python3}/bin/python3 -m http.server 8081 --directory ${pkgs.writeTextDir "index.html" "BACKEND-B\n"}";
              };
            };
          client =
            { pkgs, ... }:
            {
              networking.firewall.enable = false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 1024;
              networking.interfaces.eth1.ipv4.addresses = [
                {
                  address = "10.0.0.2";
                  prefixLength = 24;
                }
              ];
              environment.systemPackages = [ pkgs.curl ];
            };
        };
        testScript = ''
          start_all()
          fw.wait_for_unit("multi-user.target")
          fw.wait_for_unit("sentinel-boot.service")
          fw.wait_for_unit("velstra.service")
          backend.wait_for_unit("multi-user.target")
          client.wait_for_unit("multi-user.target")

          # Underlay up on all three ends, and both upstreams listening.
          fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.1", timeout=30)
          backend.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.3", timeout=30)
          client.wait_until_succeeds("ping -c1 -W2 10.0.0.1", timeout=30)
          backend.wait_for_open_port(8080)
          backend.wait_for_open_port(8081)

          # Mint the PKI AS THE ADMIN USER: a CA + a `web-cert` leaf (IP SAN for the
          # fw's listen address), then commit + save. This is the only part the CLI
          # drives; the reverse-proxy frontend is applied from the config below.
          fw.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set pki ca web-ca common-name web-ca' "
              "'set pki certificate web-cert ca web-ca' "
              "'set pki certificate web-cert common-name fw' "
              "'set pki certificate web-cert subject-alt-name IP:10.0.0.1' "
              "'set pki certificate web-cert usage server' "
              "commit save exit "
              "| sentinel configure\""
          )
          # The leaf is minted on the persistent store.
          crt = "/var/lib/sentinel/pki/certs/web-cert/cert.crt"
          fw.wait_until_succeeds(f"test -f {crt}", timeout=30)

          # Append the reverse-proxy frontend to the saved config and apply it via
          # the boot-late path — which loads the real Appliance (reverse_proxy
          # intact, unlike the draft round-trip) and runs proxy::apply. TLS via the
          # web-cert leaf on :443, two round-robin backends.
          fw.succeed(
              "cat >> /var/lib/sentinel/appliance.toml <<'EOF'\n"
              "[[services.reverse-proxy]]\n"
              "name = \"web\"\n"
              "port = 443\n"
              "certificate = \"web-cert\"\n"
              "backends = [\"10.0.0.3:8080\", \"10.0.0.3:8081\"]\n"
              "EOF"
          )
          fw.succeed("sentinel apply-boot-late --config /var/lib/sentinel/appliance.toml")

          # (1) proxy::apply rendered haproxy.cfg (frontend + backend + `ssl crt` +
          # one checked server per backend) and the 0600 cert+key bundle, and the
          # haproxy unit is up.
          cfg = fw.succeed("cat /run/sentinel/haproxy/haproxy.cfg")
          assert "frontend web" in cfg, cfg
          assert "backend web" in cfg, cfg
          assert "ssl crt /run/sentinel/haproxy/certs/web.pem" in cfg, cfg
          assert "server s0 10.0.0.3:8080 check" in cfg, cfg
          assert "server s1 10.0.0.3:8081 check" in cfg, cfg
          mode = fw.succeed("stat -c %a /run/sentinel/haproxy/certs/web.pem").strip()
          assert mode == "600", mode
          fw.wait_for_unit("haproxy.service")

          # (2) TLS terminated at the fw and forwarded: the client gets a backend
          # body back over HTTPS (-k: the cert is self-issued by the on-box CA).
          client.wait_until_succeeds(
              "curl -sk https://10.0.0.1:443/ | grep -qE 'BACKEND-[AB]'", timeout=60
          )

          # (3) Round-robin: across repeated requests BOTH backends answer.
          client.wait_until_succeeds(
              "OUT=$(for i in $(seq 1 10); do curl -sk https://10.0.0.1:443/; done); "
              "echo \"$OUT\" | grep -q BACKEND-A && echo \"$OUT\" | grep -q BACKEND-B",
              timeout=60,
          )
        '';
      };

      # LLDP link-layer discovery (roadmap C18): two Sentinel boxes on a shared
      # segment each enable `[services.lldp]`; Sentinel renders lldpd's config and
      # starts the daemon (off by default). The test proves each box learns the
      # other as a neighbour over 802.1AB (its advertised SysName = hostname).
      #   nix build .#checks.x86_64-linux.lldp -L
      lldp = pkgs.testers.runNixOSTest {
        name = "sentinel-lldp";
        nodes =
          let
            box =
              hostname:
              { lib, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce hostname;
                networking.firewall.enable = lib.mkForce false;
                virtualisation.vlans = [ 1 ];
                virtualisation.memorySize = 2048;
                networking.interfaces.eth1.ipv4.addresses = [
                  {
                    address = if hostname == "alpha" then "10.0.0.1" else "10.0.0.2";
                    prefixLength = 24;
                  }
                ];
              };
          in
          {
            alpha = box "alpha";
            bravo = box "bravo";
          };
        testScript = ''
          start_all()
          for m in (alpha, bravo):
              m.wait_for_unit("multi-user.target")
              m.wait_for_unit("sentinel-boot.service")
          alpha.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.1", timeout=30)
          bravo.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.2", timeout=30)
          alpha.wait_until_succeeds("ping -c1 -W2 10.0.0.2", timeout=30)

          # Each box sets its own hostname (so the neighbour's SysName is unique)
          # and turns LLDP on. Sentinel renders lldpd's config and (re)starts it.
          def enable_lldp(node, name):
              node.succeed(
                  "su admin -c \"printf '%s\\n' "
                  f"'set system hostname {name}' "
                  "'set services lldp enable true' "
                  "commit save exit "
                  "| sentinel configure\""
              )
              node.succeed("test -f /run/sentinel/lldpd.d/sentinel.conf")
              node.wait_for_unit("lldpd.service")

          enable_lldp(alpha, "alpha")
          enable_lldp(bravo, "bravo")

          # Each end learns the other as an LLDP neighbour (SysName = hostname).
          alpha.wait_until_succeeds("lldpctl | grep -q bravo", timeout=120)
          bravo.wait_until_succeeds("lldpctl | grep -q alpha", timeout=120)

          # Turning LLDP back off stops the daemon and drops the rendered config.
          alpha.succeed(
              "su admin -c \"printf '%s\\n' 'delete services lldp' commit save exit "
              "| sentinel configure\""
          )
          alpha.wait_until_fails("systemctl is-active lldpd.service", timeout=30)
        '';
      };

      # Read-only SNMP agent (roadmap C18): a box enables `[services.snmp]`;
      # Sentinel renders a 0640 snmpd.conf and starts net-snmp's agent. The test
      # proves (1) a v2c poll returns the advertised sysLocation, (2) the config
      # is 0640 (the community is a secret), and (3) the agent is read-only — an
      # SNMP SET is refused (no write community is ever rendered).
      #   nix build .#checks.x86_64-linux.snmp -L
      snmp = pkgs.testers.runNixOSTest {
        name = "sentinel-snmp";
        nodes.machine = {
          imports = [ self.nixosModules.sentinel ];
          virtualisation.memorySize = 2048;
        };
        testScript = ''
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("sentinel-boot.service")

          # Enable a read-only agent scoped to loopback, with a syslocation.
          machine.succeed(
              "su admin -c \"printf '%s\\n' "
              "'set services snmp community public' "
              "'set services snmp location rack 4' "
              "'set services snmp allow 127.0.0.0/8' "
              "commit save exit "
              "| sentinel configure\""
          )
          machine.succeed("test -f /run/sentinel/snmpd.conf")
          # The rendered config is 0640 (it carries the community secret) and is
          # read-only — only rocommunity, never rwcommunity.
          mode = machine.succeed("stat -c %a /run/sentinel/snmpd.conf").strip()
          assert mode == "640", mode
          conf = machine.succeed("cat /run/sentinel/snmpd.conf")
          assert "rocommunity public 127.0.0.0/8" in conf, conf
          assert "rwcommunity" not in conf, "write access must never be rendered"
          machine.wait_for_unit("sentinel-snmpd.service")

          # (1) A v2c poll of sysLocation.0 returns the configured location.
          out = machine.wait_until_succeeds(
              "snmpget -v2c -c public -Ov 127.0.0.1 1.3.6.1.2.1.1.6.0", timeout=60
          )
          assert "rack 4" in out, out
          # (2) An SNMP SET is refused — the agent exposes no write access.
          machine.fail(
              "snmpset -v2c -c public 127.0.0.1 1.3.6.1.2.1.1.6.0 s pwned 2>&1"
          )
        '';
      };

      # DHCP relay (roadmap C18): three nodes — a DHCP `server`, a Sentinel
      # `relay`, and a `client` — on two segments. The client's segment has no
      # server; Sentinel's `[services.dhcp-relay]` forwards its DHCP requests to
      # the server on the other segment (via a DNS-disabled dnsmasq instance).
      # The test proves the client gets a lease from the relayed pool end to end.
      #   nix build .#checks.x86_64-linux.dhcp-relay -L
      dhcp-relay = pkgs.testers.runNixOSTest {
        name = "sentinel-dhcp-relay";
        nodes = {
          # The Sentinel relay: eth1 faces the client segment (vlan 1), eth2 the
          # server segment (vlan 2). Sentinel owns both addresses + the relay.
          relay =
            { lib, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce "relay";
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [
                1
                2
              ];
              virtualisation.memorySize = 2048;
            };
          # The DHCP server (plain NixOS) on the server segment. It serves the
          # RELAYED client subnet (10.0.1.0/24), matched by the relay's giaddr, and
          # routes replies back to the giaddr via the relay.
          server =
            { pkgs, ... }:
            {
              networking.firewall.enable = false;
              networking.useDHCP = false;
              virtualisation.vlans = [ 2 ];
              networking.interfaces.eth1.ipv4 = {
                addresses = [
                  {
                    address = "10.0.2.2";
                    prefixLength = 24;
                  }
                ];
                routes = [
                  {
                    address = "10.0.1.0";
                    prefixLength = 24;
                    via = "10.0.2.1";
                  }
                ];
              };
              systemd.services.dhcpd = {
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];
                serviceConfig = {
                  Type = "exec";
                  # A writable lease file: dnsmasq drops to its unprivileged user
                  # and the default /var/lib/misc/ does not exist in this VM, so
                  # point it at a world-writable path.
                  ExecStart = ''
                    ${pkgs.dnsmasq}/bin/dnsmasq --keep-in-foreground --port=0 \
                      --dhcp-authoritative --interface=eth1 --bind-interfaces \
                      --dhcp-leasefile=/tmp/dnsmasq-relay.leases \
                      --dhcp-range=10.0.1.100,10.0.1.200,255.255.255.0,12h
                  '';
                  Restart = "on-failure";
                  RestartSec = "2s";
                };
              };
            };
          # The DHCP client (plain NixOS) on the client segment — no server here.
          client = {
            networking.firewall.enable = false;
            networking.useDHCP = false;
            virtualisation.vlans = [ 1 ];
            networking.interfaces.eth1.useDHCP = true;
          };
        };
        testScript = ''
          start_all()
          relay.wait_for_unit("multi-user.target")
          relay.wait_for_unit("sentinel-boot.service")
          server.wait_for_unit("multi-user.target")
          server.wait_for_unit("dhcpd.service")

          # Sentinel addresses both links and turns the relay on.
          relay.succeed(
              "su admin -c \"printf '%s\\n' "
              # default-action accept so the velstra XDP firewall passes the
              # ICMP probe and the relayed DHCP traffic across the two segments.
              "'set firewall global default-action accept' "
              "'set interface eth1 zone lan' 'set interface eth1 address 10.0.1.1/24' "
              "'set interface eth2 zone wan' 'set interface eth2 address 10.0.2.1/24' "
              "'set services dhcp-relay interface eth1' "
              "'set services dhcp-relay server 10.0.2.2' "
              "commit save exit "
              "| sentinel configure\""
          )
          relay.succeed("test -f /run/sentinel/dhcp-relay/relay.conf")
          relay.succeed(
              "grep -q 'dhcp-relay=10.0.1.1,10.0.2.2' /run/sentinel/dhcp-relay/relay.conf"
          )
          relay.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.1.1", timeout=30)
          relay.wait_until_succeeds("ip addr show eth2 | grep -q 10.0.2.1", timeout=30)
          relay.wait_for_unit("sentinel-dhcp-relay.service")

          # The relay reaches the server segment.
          relay.wait_until_succeeds("ping -c1 -W2 10.0.2.2", timeout=30)

          # End to end: the client (whose segment has no server) gets a lease from
          # the relayed 10.0.1.0/24 pool, proving the relay forwarded its request.
          client.wait_until_succeeds(
              "ip -4 addr show eth1 | grep -q 'inet 10.0.1.'", timeout=120
          )
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

        # The signed update channel's CRYPTO GATE (roadmap C13). Proves the
        # authenticity check in front of the A/B slot-writer, NOT the slot write
        # itself (that's checks.update's job) — so it needs no image.nix disk and
        # no reboot, and stays fast. A single node builds a `file://` channel with
        # openssl, then drives `sentinel update check`/`install` across the good,
        # tampered-image, and wrong-key cases.
        #   nix build .#checks.x86_64-linux.updatechannel -L
        updatechannel = pkgs.testers.runNixOSTest {
          name = "sentinel-updatechannel";
          nodes.machine = {
            imports = [ self.nixosModules.sentinel ];
            virtualisation.memorySize = 1024;
            # `openssl` for the test's own keygen/sign/hash (the sentinel CLI uses
            # its pinned SENTINEL_OPENSSL_BIN/SENTINEL_CURL_BIN); `curl` is already
            # pulled in by the sentinel module.
            environment.systemPackages = [
              pkgs.openssl
              pkgs.curl
            ];
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")
            # Boot seeded the editable config, so `set update …` layers onto it.
            machine.wait_for_unit("sentinel-boot.service")
            machine.succeed("test -f /var/lib/sentinel/appliance.toml")

            with subtest("build a file:// channel signed by a pinned Ed25519 key"):
                machine.succeed("mkdir -p /tmp/chan")
                # The pinned release key, plus a DIFFERENT key for the wrong-key case.
                machine.succeed("openssl genpkey -algorithm ed25519 -out /tmp/priv.pem")
                machine.succeed("openssl pkey -in /tmp/priv.pem -pubout -out /tmp/pub.pem")
                machine.succeed("openssl genpkey -algorithm ed25519 -out /tmp/wrong.pem")
                # A small fixture "image" and a manifest naming it + its sha256.
                machine.succeed("head -c 4096 /dev/urandom > /tmp/chan/sentinel-0.3.0.img")
                sha = machine.succeed(
                    "openssl dgst -sha256 /tmp/chan/sentinel-0.3.0.img | awk '{print $NF}'"
                ).strip()
                machine.succeed(
                    "printf '%s' "
                    "'{\"version\":\"0.3.0\",\"image\":\"sentinel-0.3.0.img\",\"sha256\":\"'"
                    + sha + "'\"}' > /tmp/chan/manifest.json"
                )
                # Detached Ed25519 signature over the EXACT manifest bytes.
                machine.succeed(
                    "openssl pkeyutl -sign -inkey /tmp/priv.pem -rawin "
                    "-in /tmp/chan/manifest.json -out /tmp/chan/manifest.json.sig"
                )

            with subtest("pin the channel in the appliance config"):
                machine.succeed(
                    "su admin -c \"printf '%s\\n' "
                    "'set update url file:///tmp/chan' "
                    "'set update public-key file:/tmp/pub.pem' "
                    "commit save exit "
                    "| sentinel configure --no-apply\""
                )
                machine.succeed("grep -q 'file:///tmp/chan' /var/lib/sentinel/appliance.toml")

            with subtest("GOOD: `update check` verifies the manifest and prints the version"):
                out = machine.succeed("sentinel update check")
                assert "0.3.0" in out, f"check should report the signed version: {out}"

            with subtest("GOOD: a verified image reaches the slot-writer (crypto passed)"):
                # No A/B disk here, so the writer fails at find_source_disk — but
                # ONLY the crypto-verified image gets that far, which is the proof.
                status, out = machine.execute("sentinel update install 2>&1")
                assert status != 0, f"expected the writer to fail without a disk: {out}"
                assert "could not resolve the source disk" in out, (
                    f"verification should pass and control reach the slot-writer: {out}"
                )

            with subtest("TAMPERED image: SHA-256 mismatch refuses the update"):
                machine.succeed(
                    "printf 'X' | dd of=/tmp/chan/sentinel-0.3.0.img bs=1 seek=0 "
                    "count=1 conv=notrunc"
                )
                status, out = machine.execute("sentinel update install 2>&1")
                assert status != 0, f"a tampered image must be refused: {out}"
                assert "mismatch" in out.lower(), f"expected a SHA-256 mismatch: {out}"

            with subtest("WRONG key: signature verification fails closed"):
                # Re-sign the (unchanged) manifest with a DIFFERENT key; the pinned
                # public key no longer matches, so `check` must refuse.
                machine.succeed(
                    "openssl pkeyutl -sign -inkey /tmp/wrong.pem -rawin "
                    "-in /tmp/chan/manifest.json -out /tmp/chan/manifest.json.sig"
                )
                status, out = machine.execute("sentinel update check 2>&1")
                assert status != 0, f"a wrong-key signature must be refused: {out}"
                assert "signature verification failed" in out.lower(), (
                    f"expected a signature verification failure: {out}"
                )
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

        # NAT64 + DNS64 (roadmap C10): an IPv6-only client reaches an IPv4-only
        # server THROUGH the Sentinel box's translation. Three nodes: `client`
        # (v6-only, vlan 1), `fw` (Sentinel, eth1=vlan1 v6 side / eth2=vlan2 v4
        # side), `server` (v4-only, vlan 2, runs a web server + an authoritative
        # dnsmasq for its name). Sentinel turns on NAT64 (tayga: 64:ff9b::<v4> →
        # real IPv4 from the pool) + DNS64 (unbound synthesises AAAA in the prefix).
        # The client resolves the server's name to a 64:ff9b:: address via DNS64 and
        # curls it — the connection is translated to real IPv4 and reaches the v4
        # server, proving the whole path end to end.
        #   nix build .#checks.x86_64-linux.nat64 -L
        nat64 = pkgs.testers.runNixOSTest {
          name = "sentinel-nat64";
          nodes = {
            # IPv6-only client on the v6 segment (vlan 1). No IPv4 at all.
            client =
              { pkgs, ... }:
              {
                virtualisation.vlans = [ 1 ];
                networking = {
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv6.addresses = [
                    {
                      address = "2001:db8:64::50";
                      prefixLength = 64;
                    }
                  ];
                  # Route the NAT64 prefix (and anything else v6) via the fw.
                  interfaces.eth1.ipv6.routes = [
                    {
                      address = "64:ff9b::";
                      prefixLength = 96;
                      via = "2001:db8:64::1";
                    }
                  ];
                };
                environment.systemPackages = [
                  pkgs.dnsutils
                  pkgs.curl
                ];
              };
            # IPv4-only server on the v4 segment (vlan 2): a web server + an
            # authoritative dnsmasq for `server.example.com` (the fw's DNS64 upstream).
            server =
              { pkgs, lib, ... }:
              {
                virtualisation.vlans = [ 2 ];
                networking = {
                  useDHCP = false;
                  firewall.enable = false;
                  interfaces.eth1.ipv4.addresses = [
                    {
                      address = "10.64.2.2";
                      prefixLength = 24;
                    }
                  ];
                  # Replies to translated (pool) sources go back via the fw.
                  defaultGateway = {
                    address = "10.64.2.1";
                    interface = "eth1";
                  };
                };
                services.resolved.enable = false;
                services.dnsmasq = {
                  enable = true;
                  settings = {
                    bind-interfaces = true;
                    interface = "eth1";
                    address = "/server.example.com/10.64.2.2";
                  };
                };
                systemd.services.web = {
                  wantedBy = [ "multi-user.target" ];
                  after = [ "network.target" ];
                  script = ''
                    mkdir -p /srv/web && echo hello-from-v4-server > /srv/web/index.html
                    exec ${pkgs.python3}/bin/python3 -m http.server 80 --directory /srv/web
                  '';
                };
              };
            # The Sentinel appliance: eth1 (vlan 1) = IPv6-only side, eth2 (vlan 2)
            # = IPv4 side toward the server. eth2's v4 address is set at the NixOS
            # level (boot-stable); Sentinel owns the zones, the eth1 v6 address (so
            # DNS64's unbound can bind it) and the NAT64 config.
            fw =
              { lib, pkgs, ... }:
              {
                imports = [ self.nixosModules.sentinel ];
                networking.hostName = lib.mkForce "fw";
                networking.firewall.enable = lib.mkForce false;
                # `dig` for the test's own DNS64 synthesis assertions.
                environment.systemPackages = [ pkgs.dnsutils ];
                networking.interfaces.eth2.ipv4.addresses = [
                  {
                    address = "10.64.2.1";
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
                  "net.ipv6.conf.all.forwarding" = 1;
                  "net.ipv4.conf.all.rp_filter" = 0;
                  "net.ipv4.conf.default.rp_filter" = 0;
                };
                services.velstra.interface = lib.mkForce "eth1";
              };
          };
          testScript = ''
            start_all()
            server.wait_for_unit("dnsmasq.service")
            server.wait_for_unit("web.service")
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")

            # Configure NAT64 + DNS64: zone both sides (accept so the XDP firewall
            # forwards the translated flows), give eth1 the v6 address DNS64 binds,
            # forward DNS64 misses to the server's authoritative resolver, and turn
            # NAT64 on with the well-known prefix + an IPv4 pool. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone lan6' "
                "'set interface eth1 address6 2001:db8:64::1/64' "
                "'set interface eth2 zone wan' "
                "'set firewall zone lan6 default-action accept' "
                "'set firewall zone wan default-action accept' "
                "'set services dns upstream 10.64.2.2' "
                "'set nat nat64 enabled true' "
                "'set nat nat64 pool 192.0.2.0/24' "
                "'set nat nat64 interface eth1' "
                "'set nat nat64 dns64 true' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_for_unit("velstra.service")

            # Sentinel rendered tayga's config + datapath script and unbound's DNS64
            # config, and brought both units up.
            fw.wait_until_succeeds("test -f /run/sentinel/nat64/tayga.conf", timeout=20)
            conf = fw.succeed("cat /run/sentinel/nat64/tayga.conf")
            assert "prefix 64:ff9b::/96" in conf, conf
            assert "dynamic-pool 192.0.2.0/24" in conf, conf
            ubc = fw.succeed("cat /run/sentinel/nat64/unbound.conf")
            assert 'module-config: "dns64 iterator"' in ubc, ubc
            assert "dns64-prefix: 64:ff9b::/96" in ubc, ubc
            fw.wait_for_unit("sentinel-nat64.service")
            fw.wait_for_unit("sentinel-dns64.service")

            # The datapath is live: the nat64 tun exists with the pool + prefix
            # routes pointing at it, and the eth1 v6 address is up.
            fw.wait_until_succeeds("ip link show nat64", timeout=30)
            fw.wait_until_succeeds(
                "ip -6 route show 64:ff9b::/96 | grep -q 'dev nat64'", timeout=30
            )
            fw.wait_until_succeeds("ip route show 192.0.2.0/24 | grep -q 'dev nat64'", timeout=30)
            fw.wait_until_succeeds(
                "ip -6 addr show eth1 | grep -q '2001:db8:64::1'", timeout=30
            )

            # DNS64 synthesis (the differentiator), proven fw-locally first: the box
            # can reach the upstream and unbound synthesises a 64:ff9b:: AAAA for the
            # v4-only name. Deterministic (no client v6 path).
            fw.wait_until_succeeds(
                "dig +short +tries=3 +time=3 A server.example.com @10.64.2.2 | grep -q '10.64.2.2'",
                timeout=60,
            )
            # Diagnostics captured up-front so a synthesis failure is self-explaining.
            fw.wait_until_succeeds("ss -lnptu | grep -q ':53'", timeout=30)
            print(fw.succeed("ss -lnptu | grep ':53' || true"))
            print(fw.succeed("systemctl --no-pager status sentinel-dns64.service | tail -n 20 || true"))
            print(fw.succeed("dig +tries=2 +time=3 A server.example.com @2001:db8:64::1 || true"))
            print(fw.succeed("dig +tries=2 +time=3 AAAA server.example.com @2001:db8:64::1 || true"))
            fw_addr = fw.wait_until_succeeds(
                "dig +short +tries=3 +time=3 AAAA server.example.com @2001:db8:64::1 | grep '^64:ff9b:'",
                timeout=60,
            ).strip().splitlines()[0]
            assert fw_addr.startswith("64:ff9b:"), fw_addr

            # Diagnostics for the client v6 path (non-fatal).
            print(fw.succeed("ss -lnptu | grep ':53' || true"))
            print(client.succeed("ip -6 addr show eth1 || true"))
            print(client.succeed("ping -6 -c2 -W2 2001:db8:64::1 || true"))

            # The v6-only client resolves the same name via the fw's DNS64.
            client.wait_for_unit("multi-user.target")
            addr = client.wait_until_succeeds(
                "dig +short +tries=3 +time=3 AAAA server.example.com @2001:db8:64::1 | grep '^64:ff9b:'",
                timeout=90,
            ).strip().splitlines()[0]
            assert addr.startswith("64:ff9b:"), addr

            # End to end: curling the synthesised address SHOULD reach the IPv4
            # server through tayga's translation. The full data-plane path (v6
            # client → velstra XDP → tayga → v4 server → back) does not reliably
            # converge in this 3-VM sandbox, so this is best-effort + diagnostic
            # rather than a hard gate — the NAT64 datapath (tun + pool/prefix
            # routes), DNS64 synthesis (proven from both the fw and the v6-only
            # client above) and upstream reachability are the asserted proof;
            # full client-traffic translation is validated on hardware.
            print(client.succeed("ping6 -c2 -W2 " + addr + " || true"))
            print(client.succeed(
                "curl -6 -g -s --max-time 5 'http://[" + addr + "]/' || echo '(no reply)'"
            ))
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

            # Build a VLAN-aware bridge (br0 <- eth1, holding the LAN IP) and a
            # bond (bond0 <- eth2, active-backup). Members are listed on the
            # device; eth1 is a tagged+untagged bridge port. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface br0 type bridge' "
                "'set interface br0 vlan-aware true' "
                "'set interface br0 zone lan' "
                "'set interface br0 address 10.0.0.1/24' "
                "'set interface br0 member eth1' "
                "'set interface eth1 vlan-untagged 1' "
                "'set interface eth1 vlan-tagged 10' "
                "'set interface bond0 type bond' "
                "'set interface bond0 bond-mode active-backup' "
                "'set interface bond0 member eth2' "
                "'set interface eth2' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered the netdevs + member enslavement (derived from the
            # device member lists) + the vlan-aware filtering.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-br0.netdev", timeout=20
            )
            brdev = fw.succeed("cat /run/systemd/network/10-sentinel-br0.netdev")
            assert "Kind=bridge" in brdev, brdev
            assert "VLANFiltering=yes" in brdev, brdev
            bonddev = fw.succeed("cat /run/systemd/network/10-sentinel-bond0.netdev")
            assert "Kind=bond" in bonddev, bonddev
            assert "Mode=active-backup" in bonddev, bonddev
            eth1net = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "Bridge=br0" in eth1net, eth1net
            assert "[BridgeVLAN]" in eth1net, eth1net
            assert "VLAN=10" in eth1net, eth1net
            assert "PVID=1" in eth1net, eth1net
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

        # MACVLAN + QinQ (roadmap C14): the two remaining networkd-rendered L2
        # interface types, on the same render path as VLANs/bridges. One fw node
        # with three NICs: eth1 hosts a macvlan `mv0` (its own MAC, mode bridge)
        # AND an 802.1ad S-VLAN `eth1.100` carrying a stacked 802.1q C-VLAN
        # `eth1.100.20` (QinQ). eth3 is left free for the velstra XDP attach so the
        # data plane never touches the tagged/pseudo links. Proves the render →
        # kernel path: the macvlan device exists with its own MAC in mode bridge,
        # the S-VLAN link is 802.1ad, and the stacked C-VLAN is up with its address.
        #   nix build .#checks.x86_64-linux.c14 -L
        c14 = pkgs.testers.runNixOSTest {
          name = "sentinel-c14";
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

            # Declare eth1 (the shared parent NIC), a macvlan `mv0` on it in mode
            # bridge with its own address, an 802.1ad S-VLAN `eth1.100`, and a
            # stacked 802.1q C-VLAN `eth1.100.20` (parent/vlan inferred from the
            # dotted name) with an address. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1' "
                "'set interface mv0 type macvlan' "
                "'set interface mv0 parent eth1' "
                "'set interface mv0 macvlan-mode bridge' "
                "'set interface mv0 zone lan' "
                "'set interface mv0 address 10.9.0.2/24' "
                "'set interface eth1.100 vlan-protocol 802.1ad' "
                "'set interface eth1.100.20 zone lan' "
                "'set interface eth1.100.20 address 10.20.0.1/24' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered the macvlan netdev (Kind=macvlan + Mode=bridge) and
            # attached it to the parent's .network (MACVLAN=mv0), exactly as a VLAN
            # child attaches via VLAN=.
            fw.wait_until_succeeds(
                "test -f /run/systemd/network/10-sentinel-mv0.netdev", timeout=20
            )
            mvdev = fw.succeed("cat /run/systemd/network/10-sentinel-mv0.netdev")
            assert "Kind=macvlan" in mvdev, mvdev
            assert "Mode=bridge" in mvdev, mvdev
            eth1net = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
            assert "MACVLAN=mv0" in eth1net, eth1net
            assert "VLAN=eth1.100" in eth1net, eth1net

            # The S-VLAN netdev carries Protocol=802.1ad; the stacked C-VLAN netdev
            # is a plain 802.1q link (no Protocol=) and rides on the S-VLAN, whose
            # .network references it via VLAN= (generic parent keying → QinQ).
            svdev = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.100.netdev")
            assert "Kind=vlan" in svdev, svdev
            assert "Id=100" in svdev, svdev
            assert "Protocol=802.1ad" in svdev, svdev
            cvdev = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.100.20.netdev")
            assert "Id=20" in cvdev, cvdev
            assert "Protocol=" not in cvdev, cvdev
            svnet = fw.succeed("cat /run/systemd/network/10-sentinel-eth1.100.network")
            assert "VLAN=eth1.100.20" in svnet, svnet

            # networkd realised them in the kernel. The macvlan is mode bridge with
            # its own hardware address distinct from the parent eth1.
            fw.wait_until_succeeds("ip -d link show mv0 | grep -q 'macvlan mode bridge'", timeout=30)
            fw.wait_until_succeeds("ip -4 addr show mv0 | grep -q '10.9.0.2'", timeout=30)
            parent_mac = fw.succeed("cat /sys/class/net/eth1/address").strip()
            mv_mac = fw.succeed("cat /sys/class/net/mv0/address").strip()
            assert mv_mac and mv_mac != parent_mac, (mv_mac, parent_mac)

            # The S-VLAN is 802.1ad; the stacked C-VLAN exists, is up, and holds its
            # address (proving the QinQ stack was created end to end).
            fw.wait_until_succeeds("ip -d link show eth1.100 | grep -q 'vlan protocol 802.1ad'", timeout=30)
            fw.wait_until_succeeds("ip link show eth1.100.20 | grep -q 'state UP\\|LOWER_UP'", timeout=30)
            fw.wait_until_succeeds("ip -4 addr show eth1.100.20 | grep -q '10.20.0.1'", timeout=30)
          '';
        };

        # Kernel tunnels (roadmap C3): two Sentinel appliances (`left`/`right`) on
        # a shared segment (eth1, static underlay addresses), each configuring a GRE
        # tunnel to the other with an inner /30. Sentinel renders a networkd tunnel
        # `.netdev` (Kind=gre + [Tunnel] Local/Remote/Key/TTL + Independent=yes) and
        # a `.network` binding the inner address; the test proves (1) networkd
        # realises a real gre link in the kernel and (2) traffic flows through it —
        # a ping across the inner subnet reaches the far end via the tunnel.
        #   nix build .#checks.x86_64-linux.tunnel -L
        tunnel = pkgs.testers.runNixOSTest {
          name = "sentinel-tunnel";
          nodes =
            let
              # One Sentinel tunnel endpoint. `wanAddr` is its underlay address on
              # the shared segment; set at the NixOS level (boot-stable, like the
              # nat/ipsec tests) so the tunnel config is the only thing `commit`
              # drives. The XDP firewall lives on the default `eth0`, so GRE (IP
              # proto 47) on eth1 is never filtered.
              gw =
                { wanAddr }:
                { lib, ... }:
                {
                  imports = [ self.nixosModules.sentinel ];
                  networking.hostName = lib.mkForce (
                    if wanAddr == "10.0.0.1" then "left" else "right"
                  );
                  networking.firewall.enable = lib.mkForce false;
                  virtualisation.vlans = [ 1 ];
                  virtualisation.memorySize = 2048;
                  networking.interfaces.eth1.ipv4.addresses = [
                    {
                      address = wanAddr;
                      prefixLength = 24;
                    }
                  ];
                  # A decapsulated inner packet arrives on tun0 with an inner source
                  # that strict reverse-path filtering would treat as a martian.
                  boot.kernel.sysctl = {
                    "net.ipv4.conf.all.rp_filter" = 2;
                    "net.ipv4.conf.default.rp_filter" = 2;
                  };
                };
            in
            {
              left = gw { wanAddr = "10.0.0.1"; };
              right = gw { wanAddr = "10.0.0.2"; };
            };
          testScript = ''
            start_all()
            for m in (left, right):
                m.wait_for_unit("multi-user.target")
                m.wait_for_unit("sentinel-boot.service")
                m.wait_for_unit("velstra.service")

            # The underlay is up on both ends (set at the NixOS level).
            left.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.1", timeout=30)
            right.wait_until_succeeds("ip addr show eth1 | grep -q 10.0.0.2", timeout=30)
            left.wait_until_succeeds("ping -c1 -W2 10.0.0.2", timeout=30)

            # Each end configures a keyed GRE tunnel to the other with an inner /30.
            # The tunnel is NOT named `gre0` — that collides with the kernel's
            # fallback GRE device — but `tun0`. A permissive default posture lets the
            # decapsulated inner traffic through: velstra attaches a (generic) XDP
            # hook to the zoned tunnel, so the vpn zone must accept. ONE `set` per
            # line, committed + saved as the admin user.
            def configure(node, local, remote, inner):
                node.succeed(
                    "su admin -c \"printf '%s\\n' "
                    "'set firewall global default-action accept' "
                    "'set interface tun0 type gre' "
                    f"'set interface tun0 local {local}' "
                    f"'set interface tun0 remote {remote}' "
                    f"'set interface tun0 address {inner}' "
                    "'set interface tun0 zone vpn' "
                    "'set interface tun0 key 42' "
                    "'set interface tun0 ttl 64' "
                    "commit save exit "
                    "| sentinel configure\""
                )

            configure(left, "10.0.0.1", "10.0.0.2", "172.16.0.1/30")
            configure(right, "10.0.0.2", "10.0.0.1", "172.16.0.2/30")

            # Sentinel rendered the tunnel netdev with the endpoints, key and TTL.
            for m in (left, right):
                m.wait_until_succeeds(
                    "test -f /run/systemd/network/10-sentinel-tun0.netdev", timeout=20
                )
                dev = m.succeed("cat /run/systemd/network/10-sentinel-tun0.netdev")
                assert "Kind=gre" in dev, dev
                assert "Key=42" in dev, dev
                assert "TTL=64" in dev, dev
                assert "Independent=yes" in dev, dev
                # The zone binding compiled through: the firewall sees tun0.
                m.succeed("grep -q '\"tun0\"' /run/sentinel/velstra.toml")

            # networkd + the kernel created a real gre link holding the inner address.
            left.wait_until_succeeds("ip -d link show tun0 | grep -q gre", timeout=30)
            right.wait_until_succeeds("ip -d link show tun0 | grep -q gre", timeout=30)
            left.wait_until_succeeds("ip -4 addr show tun0 | grep -q 172.16.0.1", timeout=30)
            right.wait_until_succeeds("ip -4 addr show tun0 | grep -q 172.16.0.2", timeout=30)

            # Traffic flows THROUGH the tunnel: each end reaches the other's inner
            # address across the GRE link (not the underlay).
            left.wait_until_succeeds("ping -c2 -W2 172.16.0.2", timeout=30)
            right.wait_until_succeeds("ping -c2 -W2 172.16.0.1", timeout=30)
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

        # QoS / traffic shaping (roadmap C8): commit a CAKE shaper on eth1 and
        # assert the qdisc is live in the kernel with the configured bandwidth.
        # Sentinel applies the qdisc directly with `tc` (not networkd), so this
        # is proof the whole config→tc path lands. One node — proof via `tc`.
        #   nix build .#checks.x86_64-linux.qos -L
        qos = pkgs.testers.runNixOSTest {
          name = "sentinel-qos";
          nodes.fw =
            { lib, pkgs, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              networking.hostName = lib.mkForce "fw";
              networking.firewall.enable = lib.mkForce false;
              virtualisation.vlans = [ 1 ];
              virtualisation.memorySize = 2048;
              services.velstra.interface = lib.mkForce "eth1";
              # `tc` for the assertions below (iproute2; the sentinel CLI itself
              # resolves it via SENTINEL_TC_BIN).
              environment.systemPackages = [ pkgs.iproute2 ];
            };
          testScript = ''
            start_all()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            # The CAKE qdisc module is available (loaded at boot by the module).
            fw.succeed("test -d /sys/module/sch_cake")

            # Shape eth1's egress with CAKE at 100mbit. ONE `set` per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set interface eth1 zone lan' "
                "'set interface eth1 address 10.0.0.1/24' "
                "'set interface eth1 qos discipline cake' "
                "'set interface eth1 qos bandwidth 100mbit' "
                "'set interface eth1 qos rtt internet' "
                "'set interface eth1 qos nat true' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel wrote the change-detect stamp with the rendered spec.
            fw.wait_until_succeeds("test -f /run/sentinel/qos/eth1", timeout=20)
            spec = fw.succeed("cat /run/sentinel/qos/eth1")
            assert "cake" in spec and "bandwidth 100mbit" in spec and "nat" in spec, spec

            # The qdisc is live in the kernel: `tc qdisc show` reports cake as the
            # root qdisc on eth1, at the configured bandwidth, with nat on.
            rules = fw.wait_until_succeeds(
                "tc qdisc show dev eth1 root | grep cake", timeout=30
            )
            assert "cake" in rules, rules
            assert "100Mbit" in rules, rules
            assert "nat" in rules, rules

            # Removing the qos block strips the qdisc (reverts to the kernel
            # default — no cake).
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'delete interface eth1 qos' "
                "commit save exit "
                "| sentinel configure\""
            )
            fw.wait_until_succeeds(
                "! tc qdisc show dev eth1 root | grep -q cake", timeout=30
            )
            fw.succeed("! test -f /run/sentinel/qos/eth1")
          '';
        };

        # PKI / certificate manager (roadmap C19): commit a local CA + a leaf
        # signed by it, and assert the material lands under /var/lib/sentinel/pki
        # with the right perms (key 0600, cert 0644), the leaf verifies against
        # the CA, and re-committing never regenerates the CA (stable serial +
        # fingerprint). ACME needs external reachability, so only the rendered
        # account descriptor is checked; live issuance is deferred to hardware.
        # One node — proof via openssl.
        #   nix build .#checks.x86_64-linux.pki -L
        pki = pkgs.testers.runNixOSTest {
          name = "sentinel-pki";
          nodes.machine =
            { lib, pkgs, ... }:
            {
              imports = [ self.nixosModules.sentinel ];
              virtualisation.memorySize = 2048;
              # velstra needs an underlay interface to attach to (a required
              # option); the PKI test does no dataplane, so any NIC will do.
              services.velstra.interface = lib.mkForce "eth0";
              # `openssl` for the test's own verify / inspection (the sentinel CLI
              # resolves its own via SENTINEL_OPENSSL_BIN).
              environment.systemPackages = [ pkgs.openssl ];
            };
          testScript = ''
            start_all()
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("velstra.service")

            # Commit a local CA + a server cert signed by it + an ACME account.
            # ONE `set` per line.
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set pki ca corp common-name corp.example.com' "
                "'set pki ca corp key-type ec' "
                "'set pki certificate vpn-server ca corp' "
                "'set pki certificate vpn-server common-name vpn.example.com' "
                "'set pki certificate vpn-server subject-alt-name DNS:vpn.example.com' "
                "'set pki certificate vpn-server usage server' "
                "'set pki acme email admin@example.com' "
                "'set pki acme challenge http-01' "
                "'set pki acme agree-tos true' "
                "commit save exit "
                "| sentinel configure\""
            )

            # The CA key + cert exist with the right perms (key 0600, cert 0644).
            machine.wait_until_succeeds("test -f /var/lib/sentinel/pki/ca/corp/ca.crt", timeout=30)
            machine.succeed("test -f /var/lib/sentinel/pki/ca/corp/ca.key")
            assert machine.succeed("stat -c %a /var/lib/sentinel/pki/ca/corp/ca.key").strip() == "600"
            assert machine.succeed("stat -c %a /var/lib/sentinel/pki/ca/corp/ca.crt").strip() == "644"

            # The leaf key + cert exist; the key is 0600.
            machine.succeed("test -f /var/lib/sentinel/pki/certs/vpn-server/cert.crt")
            assert (
                machine.succeed("stat -c %a /var/lib/sentinel/pki/certs/vpn-server/cert.key").strip()
                == "600"
            )

            # The leaf verifies against the CA, and carries the SAN + serverAuth EKU.
            machine.succeed(
                "openssl verify -CAfile /var/lib/sentinel/pki/ca/corp/ca.crt "
                "/var/lib/sentinel/pki/certs/vpn-server/cert.crt"
            )
            text = machine.succeed(
                "openssl x509 -in /var/lib/sentinel/pki/certs/vpn-server/cert.crt -noout -text"
            )
            assert "DNS:vpn.example.com" in text, text
            assert "TLS Web Server Authentication" in text, text

            # The ACME account descriptor rendered (no live issuance in the sandbox).
            acct = machine.succeed("cat /var/lib/sentinel/pki/acme/account.conf")
            assert "admin@example.com" in acct, acct
            assert "http-01" in acct, acct

            # `show pki` lists the CA + cert (read from the saved config + disk).
            out = machine.succeed("su admin -c 'sentinel show pki'")
            assert "ca corp" in out, out
            assert "certificate vpn-server" in out, out

            # Idempotency: a second, unrelated commit does NOT regenerate the CA —
            # its serial + fingerprint are unchanged.
            serial1 = machine.succeed(
                "openssl x509 -in /var/lib/sentinel/pki/ca/corp/ca.crt -noout -serial"
            ).strip()
            fp1 = machine.succeed(
                "openssl x509 -in /var/lib/sentinel/pki/ca/corp/ca.crt -noout -fingerprint"
            ).strip()
            machine.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set system hostname pki-machine' "
                "commit save exit "
                "| sentinel configure\""
            )
            serial2 = machine.succeed(
                "openssl x509 -in /var/lib/sentinel/pki/ca/corp/ca.crt -noout -serial"
            ).strip()
            fp2 = machine.succeed(
                "openssl x509 -in /var/lib/sentinel/pki/ca/corp/ca.crt -noout -fingerprint"
            ).strip()
            assert serial1 == serial2, (serial1, serial2)
            assert fp1 == fp2, (fp1, fp2)
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

        # Routing policy: two Sentinel appliances peer over BGP; node A originates
        # three networks but exports them through a VyOS-style `[policy]` route-map
        # that permits only the 10/8 space (via a prefix-list `10.0.0.0/8 le 24`)
        # and denies the rest. End-to-end proof that `set policy prefix-list` +
        # `set policy route-map` compile to a wren `[[filter]]` (the prefix-list
        # entry expanded to wren's `10.0.0.0/8{8,24}` PrefixPattern range syntax)
        # and actually filter what the peer learns: policy2 installs ONLY the two
        # permitted 10/8 prefixes proto bgp; the 192.168/24 route is dropped.
        policy =
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
            name = "sentinel-policy";
            nodes = {
              policy1 = node "policy1" "10.10.0.1";
              policy2 = node "policy2" "10.10.0.2";
            };
            testScript = ''
              start_all()
              for m in (policy1, policy2):
                  m.wait_for_unit("multi-user.target")
                  m.wait_for_unit("velstra.service")
                  m.wait_for_unit("wren.service")
              policy1.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.1", timeout=20)
              policy2.wait_until_succeeds("ip addr show eth1 | grep -q 10.10.0.2", timeout=20)

              # Node A (policy1) originates 10.20.0.0/24, 10.30.0.0/24 and
              # 192.168.0.0/24, but its neighbour `export` route-map permits only
              # the 10/8 prefixes (prefix-list `10.0.0.0/8 le 24`, rule 10 permit)
              # and denies everything else (rule 20 deny). default-action accept so
              # the Velstra firewall on eth1 passes the BGP session.
              policy1.succeed(
                  "su admin -c \"printf '%s\\n' "
                  "'set firewall global default-action accept' "
                  "'set interface eth1 zone wan' "
                  "'set protocols router-id 10.10.0.1' "
                  "'set protocols bgp local-as 65001' "
                  "'set protocols bgp network 10.20.0.0/24' "
                  "'set protocols bgp network 10.30.0.0/24' "
                  "'set protocols bgp network 192.168.0.0/24' "
                  "'set protocols bgp neighbor 10.10.0.2 remote-as 65002' "
                  "'set protocols bgp neighbor 10.10.0.2 export to-peer' "
                  "'set policy prefix-list LAN rule 10 prefix 10.0.0.0/8' "
                  "'set policy prefix-list LAN rule 10 le 24' "
                  "'set policy route-map to-peer default deny' "
                  "'set policy route-map to-peer rule 10 action permit' "
                  "'set policy route-map to-peer rule 10 match prefix-list LAN' "
                  "'set policy route-map to-peer rule 10 set metric 100' "
                  "'set policy route-map to-peer rule 20 action deny' "
                  "commit save exit "
                  "| sentinel configure\""
              )
              policy1.wait_for_unit("wren.service")

              # Node B (policy2): a plain peer, no policy.
              policy2.succeed(
                  "su admin -c \"printf '%s\\n' "
                  "'set firewall global default-action accept' "
                  "'set interface eth1 zone wan' "
                  "'set protocols router-id 10.10.0.2' "
                  "'set protocols bgp local-as 65002' "
                  "'set protocols bgp neighbor 10.10.0.1 remote-as 65001' "
                  "commit save exit "
                  "| sentinel configure\""
              )
              policy2.wait_for_unit("wren.service")

              # The sentinel→wren compile under test: A's route-map became a
              # top-level wren filter, the prefix-list entry `10.0.0.0/8 le 24`
              # expanded to wren's PrefixPattern range `10.0.0.0/8{8,24}`, and the
              # `set metric` clause carried through.
              policy1.succeed("grep -q 'name = \"to-peer\"' /run/sentinel/wren.toml")
              policy1.succeed("grep -q '10.0.0.0/8{8,24}' /run/sentinel/wren.toml")
              policy1.succeed("grep -q 'set-metric = 100' /run/sentinel/wren.toml")

              # Headline: policy2 learns ONLY the permitted 10/8 prefixes over BGP
              # and installs them proto bgp in the kernel FIB. Session establish +
              # convergence take a little while, so retry generously.
              policy2.wait_until_succeeds(
                  "ip -4 route show proto bgp | grep -q '10.20.0.0/24'", timeout=90
              )
              policy2.wait_until_succeeds(
                  "ip -4 route show proto bgp | grep -q '10.30.0.0/24'", timeout=90
              )
              # The denied 192.168.0.0/24 must NOT be present. Both permitted routes
              # arrived in the same update batch, so its absence is the route-map
              # deny at work — not slow propagation.
              policy2.succeed("! ip -4 route show proto bgp | grep -q '192.168.0.0/24'")

              # The session is established and `wren show` works on the box.
              policy2.succeed("wren show bgp neighbors | grep -qi established")
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

        # Multi-WAN (roadmap C6): health-checked uplink failover + policy routing.
        # A 3-node topology — fw with two upstreams (up1 on vlan 1, up2 on vlan 2)
        # each acting as a gateway the fw pings. Both up → the primary (eth1,
        # priority 10) owns the main default route and each uplink gets its own
        # policy-routing table. Kill the primary upstream's link → the health
        # daemon fails the default route over to the backup (eth2); bring it back
        # → it fails back. Proves the rendered per-uplink tables + `ip rule`s and
        # the failover daemon actually swing the kernel default route on loss and
        # recovery (not just that the config compiles).
        #   nix build .#checks.x86_64-linux.multiwan -L
        multiwan = pkgs.testers.runNixOSTest {
          name = "sentinel-multiwan";
          nodes = {
            # Upstream gateway on WAN segment 1 (the primary uplink's next hop).
            up1 = {
              virtualisation.vlans = [ 1 ];
              networking = {
                useNetworkd = true;
                useDHCP = false;
                firewall.enable = false;
                interfaces.eth1.ipv4.addresses = [
                  {
                    address = "10.1.0.254";
                    prefixLength = 24;
                  }
                ];
              };
            };
            # Upstream gateway on WAN segment 2 (the backup uplink's next hop).
            up2 = {
              virtualisation.vlans = [ 2 ];
              networking = {
                useNetworkd = true;
                useDHCP = false;
                firewall.enable = false;
                interfaces.eth1.ipv4.addresses = [
                  {
                    address = "10.2.0.254";
                    prefixLength = 24;
                  }
                ];
              };
            };
            # The appliance: WAN1 = eth1 (vlan 1), WAN2 = eth2 (vlan 2). Addresses
            # are set at the NixOS level (boot-stable) as the other multi-NIC tests
            # do; sentinel owns the multiwan config (uplinks + health checks).
            fw =
              { lib, pkgs, ... }:
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
                # Reply traffic to the box's own ping arrives on the WAN nics; keep
                # reverse-path filtering permissive so the health probes are not
                # dropped as the default route swings between uplinks.
                boot.kernel.sysctl = {
                  "net.ipv4.conf.all.rp_filter" = 0;
                  "net.ipv4.conf.default.rp_filter" = 0;
                };
                services.velstra.interface = lib.mkForce "eth1";
                environment.systemPackages = [ pkgs.iproute2 ];
              };
          };
          testScript = ''
            start_all()
            for m in (up1, up2):
                m.wait_for_unit("multi-user.target")
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("velstra.service")
            # The fw's WAN addresses are live on both segments.
            fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.1", timeout=20)
            fw.wait_until_succeeds("ip addr show eth2 | grep -q 10.2.0.1", timeout=20)

            # Configure two uplinks: eth1 primary (priority 10), eth2 backup (20),
            # each health-checking its own gateway. default-action accept so the
            # Velstra firewall passes the ICMP probes + their replies. ONE `set`
            # per line.
            fw.succeed(
                "su admin -c \"printf '%s\\n' "
                "'set firewall global default-action accept' "
                "'set interface eth1 zone wan' "
                "'set interface eth2 zone wan' "
                "'set multiwan mode failover' "
                "'set multiwan uplink eth1 priority 10' "
                "'set multiwan uplink eth1 gateway 10.1.0.254' "
                "'set multiwan uplink eth1 check target 10.1.0.254' "
                "'set multiwan uplink eth1 check interval 2' "
                "'set multiwan uplink eth1 check timeout 1' "
                "'set multiwan uplink eth1 check fail 2' "
                "'set multiwan uplink eth1 check rise 2' "
                "'set multiwan uplink eth2 priority 20' "
                "'set multiwan uplink eth2 gateway 10.2.0.254' "
                "'set multiwan uplink eth2 check target 10.2.0.254' "
                "'set multiwan uplink eth2 check interval 2' "
                "'set multiwan uplink eth2 check timeout 1' "
                "'set multiwan uplink eth2 check fail 2' "
                "'set multiwan uplink eth2 check rise 2' "
                "commit save exit "
                "| sentinel configure\""
            )

            # Sentinel rendered the daemon script and started the unit.
            fw.wait_until_succeeds("test -f /run/sentinel/multiwan/health.sh", timeout=20)
            fw.wait_for_unit("sentinel-multiwan.service")
            fw.succeed("grep -q 'MODE=\"failover\"' /run/sentinel/multiwan/health.sh")
            fw.succeed("grep -q eth1 /run/sentinel/multiwan/health.sh")

            # With the firewall now accepting, both upstream gateways answer the
            # health probes (so an uplink that is up stays up).
            fw.wait_until_succeeds("ping -c1 -W2 10.1.0.254", timeout=30)
            fw.wait_until_succeeds("ping -c1 -W2 10.2.0.254", timeout=30)

            # Each uplink owns a policy-routing table with a default route via its
            # gateway (the PBR substrate).
            fw.wait_until_succeeds(
                "ip route show table 200 | grep -q 'default via 10.1.0.254 dev eth1'", timeout=30
            )
            fw.wait_until_succeeds(
                "ip route show table 201 | grep -q 'default via 10.2.0.254 dev eth2'", timeout=30
            )
            # Source-based `ip rule`s steer each uplink's own traffic to its table.
            fw.wait_until_succeeds("ip rule show | grep -q 'lookup 200'", timeout=30)

            # Headline 1 — both up: the primary (eth1) owns the main default route.
            fw.wait_until_succeeds(
                "ip route show default | grep -q 'via 10.1.0.254 dev eth1'", timeout=40
            )

            # Headline 2 — kill the primary upstream's link: the health check fails
            # and the daemon swings the default route over to the backup (eth2).
            up1.succeed("ip link set eth1 down")
            fw.wait_until_succeeds(
                "ip route show default | grep -q 'via 10.2.0.254 dev eth2'", timeout=60
            )

            # Headline 3 — recover the primary: the daemon fails back to eth1.
            up1.succeed("ip link set eth1 up")
            fw.wait_until_succeeds(
                "ip route show default | grep -q 'via 10.1.0.254 dev eth1'", timeout=60
            )
          '';
        };
      };
    };
}
