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
      Suricata and libxcrypt builds. Disable only to compare against the unpatched pin.
    '';
  };

  config = lib.mkIf cfg.enable {
    system.replaceDependencies.replacements =
      replace pkgs.libcap libcap
      ++ replace pkgs.net-snmp net-snmp
      ++ replace pkgs.libxcrypt libxcrypt
      ++ replace pkgs.suricata suricata;
    system.build.securityBackports = { inherit libcap net-snmp libxcrypt suricata; };
  };
}
