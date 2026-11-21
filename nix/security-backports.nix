# Runtime security fixes that the pinned nixpkgs does not carry yet (IMG-04,
# ENT-05), applied to the SHIPPED closure only: nixosConfigurations.sentinel-
# image imports this module, as do the checks that verify it.
#
# Overriding these packages in nixpkgs would rebuild everything built with
# them: zlib, libcap and libxcrypt sit under stdenv, and the enterprise overlay
# that did that planned 2538 derivations from source (IMG-13). Instead each
# fixed package is built once, against the ordinary package set, and
# `system.replaceDependencies` rewrites the references to the old store path
# throughout the system closure. The names keep their length (same pname, a
# same-length version), which that rewrite requires.
#
# Remove an entry when the nixpkgs pin carries the fix: every entry asserts
# the exact version it was written for, so a bump fails evaluation here
# instead of silently keeping or dropping a backport.
#
# Not covered: the initrd inside the UKI is assembled before this rewrite and
# keeps the original libraries. It runs before any network or account exists.
{ config, lib, pkgs, ... }:
let
  cfg = config.velstra.securityBackports;

  # Net-SNMP SMUX: unauthenticated peers could hold the agent (CVE-2026-89147).
  net-snmp = assert pkgs.net-snmp.version == "5.9.5.2";
    pkgs.net-snmp.overrideAttrs (old: {
      patches = (old.patches or [ ]) ++ [ ./security-patches/net-snmp-CVE-2026-89147.patch ];
    });

  # libcap 2.78 contains the cap_set_file TOCTOU fix (CVE-2026-4878) and the
  # recipe's only patch.
  libcap = assert pkgs.libcap.version == "2.77";
    pkgs.libcap.overrideAttrs (old: {
      version = "2.78";
      src = pkgs.fetchurl {
        url = "https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.78.tar.xz";
        sha256 = "0d621e562fd932ccf67b9660fb018e468a683d7b827541df27813228c996bb11";
      };
      patches = [ ];
      meta = old.meta // {
        identifiers = (old.meta.identifiers or { }) // {
          cpeParts = lib.meta.cpeFullVersionWithVendor "libcap_project" "2.78";
        };
      };
    });

  # Suricata parses hostile traffic. 8.0.3 carried 3 critical and 22 high
  # advisories in the 8b6181 scan; 8.0.4 still left 20 (fixed in 8.0.5-8.0.7),
  # so ship 8.0.7, the newest 8.0 release.
  suricata = assert pkgs.suricata.version == "8.0.3";
    pkgs.suricata.overrideAttrs (old: {
      version = "8.0.7";
      src = pkgs.fetchurl {
        url = "https://www.openinfosecfoundation.org/download/suricata-8.0.7.tar.gz";
        sha256 = "135s2g04g99dv4492abnb2cdms58m72w5v7kdn51zs20iyf6mm59";
      };
    });

  # Go dependencies of the ACME client and the encrypted-DNS forwarder: lego
  # 4.35.2 is the newest release and still pins golang.org/x/crypto 0.50.0
  # (7 critical), x/net 0.53.0, x/text 0.36.0, grpc 1.80.0 and go-jose 4.1.4;
  # dnsproxy 0.81.4 the same x/crypto, x/net and x/text. The patches are the
  # go.mod/go.sum change of `go get` to the newest patch releases plus
  # `go mod tidy` (x/crypto 0.59.0, x/net 0.63.0, x/text 0.44.0, grpc 1.85.0,
  # go-jose 4.1.9); no source file changes. The versions stay, so the store
  # names keep their length.
  goDeps = name: patch: hash: assert lib.elem pkgs.${name}.version [ "4.35.2" "0.81.4" ];
    pkgs.${name}.overrideAttrs (old: {
      patches = (old.patches or [ ]) ++ [ patch ];
      vendorHash = hash;
    });
  lego = goDeps "lego" ./security-patches/lego-deps.patch "sha256-XIdb2zwdjXKEpOzYiP2qQ3Yh4u6+lw23uAmwmNl7NIo=";
  dnsproxy = goDeps "dnsproxy" ./security-patches/dnsproxy-deps.patch "sha256-t5cYzUSx98z9YohZhq+b2PSr/9C/3iv8HFQ/+o16aF8=";

  # SQLite 3.54.1: three High advisories fixed in 3.54.0 (same release the
  # enterprise overlay ships; same-length version string).
  sqlite = assert pkgs.sqlite.version == "3.53.3";
    pkgs.sqlite.overrideAttrs (old: {
      version = "3.54.1";
      # The 3.53.3 recipe's patches are upstream commits that 3.54.1 contains.
      patches = [ ];
      src = pkgs.fetchurl {
        url = "https://sqlite.org/2026/sqlite-src-3540100.zip";
        sha256 = "387e7f6cad4797b17848c07d453dc6606917bb356a6cfe5a3abafd38c240c71b";
      };
      docsrc = pkgs.fetchurl {
        url = "https://sqlite.org/2026/sqlite-doc-3540100.zip";
        sha256 = "e9f634ac28a4c7b48f5c389e4b08c039654ec1487512092b330ccfcfdc0816e0";
      };
      postInstall = ''
        mkdir -p $doc/share/doc
        unzip $docsrc
        mv sqlite-doc-3540100 $doc/share/doc/sqlite
      '';
      meta = old.meta // {
        identifiers = (old.meta.identifiers or { }) // {
          cpeParts = lib.meta.cpeFullVersionWithVendor "sqlite" "3.54.1";
        };
      };
    });

  # Linux-PAM without Berkeley DB: db 4.8 (15 High advisories, fixed only in
  # releases nixpkgs does not ship) is linked solely for pam_userdb, which no
  # PAM stack on the appliance uses. The module is simply not built.
  linux-pam = assert pkgs.linux-pam.version == "1.7.2";
    pkgs.linux-pam.overrideAttrs (old: {
      buildInputs = lib.filter (input: (input.pname or "") != "db") old.buildInputs;
    });

  # Berkeley DB 5.3.28 (the same 15 High advisories) is linked by exactly two
  # packages in the closure; OpenLDAP and GnuPG reach it only through
  # cyrus-sasl. iproute2 uses it for arpd alone (not run on the appliance) and
  # cyrus-sasl for the sasldb password store (no SASL database is configured:
  # LDAP binds are simple binds). Both are built without it, so arpd and the
  # sasldb plugin are not built and db leaves the closure.
  withoutDb = drv: lib.filter (input: (input.pname or "") != "db") drv.buildInputs;
  iproute2 = assert pkgs.iproute2.version == "7.0.0";
    pkgs.iproute2.overrideAttrs (old: { buildInputs = withoutDb old; });
  # SRP (CVE-2026-129483, server authentication bypass in the SRP plugin) is
  # off by upstream default; disabling it explicitly makes its absence a build
  # property, and the install check refuses a build that has the plugin.
  cyrus_sasl = assert pkgs.cyrus_sasl.version == "2.1.28";
    pkgs.cyrus_sasl.overrideAttrs (old: {
      buildInputs = withoutDb old;
      configureFlags = old.configureFlags ++ [ "--with-dblib=none" "--disable-srp" ];
      # stdenv sets nullglob: a pattern that matches nothing expands to
      # nothing, so test each match rather than `ls` the pattern. The PLAIN
      # plugin must be there, or this is looking in the wrong directory.
      postInstall = (old.postInstall or "") + ''
        test -e "$out/lib/sasl2/libplain.so"
        for plugin in "$out"/lib/sasl2/libsrp*; do
          echo "cyrus-sasl: the SRP plugin was built despite --disable-srp: $plugin" >&2
          exit 1
        done
      '';
    });

  # GLib: D-Bus introspection XML parser state confusion, out-of-bounds read
  # (CVE-2026-58016); upstream c9da977c, first released in 2.89.0.
  glib = assert pkgs.glib.version == "2.88.3";
    pkgs.glib.overrideAttrs (old: {
      patches = (old.patches or [ ]) ++ [ ./security-patches/glib-CVE-2026-58016.patch ];
    });

  # sudo: the mailer ran with the invoking user's group (CVE-2026-35535);
  # upstream 3e474c2, which also makes a failed uid/gid/groups change fatal.
  sudo = assert pkgs.sudo.version == "1.9.17p2";
    pkgs.sudo.overrideAttrs (old: {
      patches = (old.patches or [ ]) ++ [ ./security-patches/sudo-CVE-2026-35535.patch ];
    });

  # gzip 1.15 contains the pin's two CVE patches (CVE-2026-41991/-41992, the
  # LZH decoder); the release makes the fix visible to version scanners.
  gzip = assert pkgs.gzip.version == "1.14";
    pkgs.gzip.overrideAttrs (old: {
      version = "1.15";
      src = pkgs.fetchurl {
        url = "mirror://gnu/gzip/gzip-1.15.tar.xz";
        hash = "sha256-mqDMeA3sFWuCgoRIM7NCq3ywjCXSzZoYac3Q3zHe/0g=";
      };
      patches = [ ];
    });

  # MIT krb5 1.22.3: NegoEx parsing (CVE-2026-40355/-40356, the pin's patch),
  # rd_cred NULL dereference (CVE-2026-107778) and 20 further CVEs. The pin's
  # two patches are upstream PRs 1505/1506, both in 1.22.3.
  krb5 = assert pkgs.krb5.version == "1.22.2";
    pkgs.krb5.overrideAttrs (old: {
      version = "1.22.3";
      src = pkgs.fetchurl {
        url = "https://kerberos.org/dist/krb5/1.22/krb5-1.22.3.tar.gz";
        hash = "sha256-/pCvhEGtn6mwZLjlMHfO+3gqlvimgnawMdxUrxeJ/ws=";
      };
      patches = [ ];
    });

  # hostapd 2.12: the pin builds CONFIG_IEEE80211BE (Wi-Fi 7 / MLO), so
  # CVE-2026-58374 (MLO) is reachable; 2.12 fixes it and contains the pin's
  # four security patches (advisory 2026-1, CVE-2025-24912). The OpenWrt
  # no-scan patch, the recipe's first, stays.
  hostapd = assert pkgs.hostapd.version == "2.11" && lib.length pkgs.hostapd.patches == 5;
    pkgs.hostapd.overrideAttrs (old: {
      version = "2.12";
      src = pkgs.fetchurl {
        url = "https://w1.fi/releases/hostapd-2.12.tar.gz";
        hash = "sha256-9DUCVhwoukerd+GOGpc9BzYcaMyLFBeOYZvVeWtw6r0=";
      };
      patches = [ (lib.head old.patches) ];
    });

  # IMG-02: the PAM side of imported password hashes. The management API
  # verifies $1$/$5$/$6$ with the pinned helper, but sshd, login and sudo go
  # through pam_unix and the system libcrypt, which nixpkgs builds with the
  # "strong" set only — an imported sha256crypt hash let its owner into the
  # API and not over SSH. Verification of the two legacy schemes is enabled;
  # new passwords are still hashed with yescrypt (login.defs, the helper).
  libxcrypt = assert pkgs.libxcrypt.version == "4.5.2";
    (pkgs.libxcrypt.override { enableHashes = "strong,md5crypt,sha256crypt"; }).overrideAttrs (old: {
      passthru = old.passthru // {
        enabledCryptSchemeIds = old.passthru.enabledCryptSchemeIds ++ [ "1" "5" ];
      };
    });

  # One replacement per output both sides have, documentation included: a
  # leftover libcap-2.77-man path is still a 2.77 to every scanner. Only dev
  # and pam outputs never reach the closure (they would just draw warnings).
  replace = old: new:
    map (output: { oldDependency = old.${output}; newDependency = new.${output}; })
      (lib.subtractLists [ "dev" "pam" ] (lib.intersectLists old.outputs new.outputs));
in
{
  options.velstra.securityBackports.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = ''
      Rewrite the system closure to the backported libcap, Net-SNMP,
      Suricata, lego, dnsproxy, SQLite, Linux-PAM, libxcrypt, iproute2,
      cyrus-sasl, GLib, sudo, gzip, krb5 and hostapd builds. Disable
      only to compare against the unpatched pin.
    '';
  };

  config = lib.mkIf cfg.enable {
    system.replaceDependencies.replacements =
      replace pkgs.libcap libcap
      ++ replace pkgs.net-snmp net-snmp
      ++ replace pkgs.libxcrypt libxcrypt
      ++ replace pkgs.suricata suricata
      ++ replace pkgs.lego lego
      ++ replace pkgs.dnsproxy dnsproxy
      ++ replace pkgs.sqlite sqlite
      ++ replace pkgs.linux-pam linux-pam
      ++ replace pkgs.iproute2 iproute2
      ++ replace pkgs.cyrus_sasl cyrus_sasl
      ++ replace pkgs.glib glib
      ++ replace pkgs.sudo sudo
      ++ replace pkgs.gzip gzip
      ++ replace pkgs.krb5 krb5
      ++ replace pkgs.hostapd hostapd;
    system.build.securityBackports = {
      inherit libcap net-snmp libxcrypt suricata lego dnsproxy sqlite linux-pam iproute2 cyrus_sasl
        glib sudo gzip krb5 hostapd;
    };
    assertions = [ {
      # pam_userdb is not built (see linux-pam above); a stack that names it
      # would fail closed at login, so refuse to build one instead.
      assertion = !lib.any (service: lib.hasInfix "pam_userdb" (service.text or ""))
        (lib.attrValues config.security.pam.services);
      message = "a PAM service uses pam_userdb, which the backported Linux-PAM does not build";
    } ];
  };
}
