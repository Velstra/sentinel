# Keep integration fixtures declarative too. These tests historically assigned
# the appliance's addresses through NixOS and then committed only firewall zones.
# Seed those fixture addresses into appliance.toml so a real Sentinel reconcile
# owns them, including during an unrelated firewall or routing change.
{ config, lib, pkgs, ... }:
let
  links = lib.filterAttrs (name: i:
    name != "lo" && (i.ipv4.addresses != [] || i.ipv6.addresses != [])
  ) config.networking.interfaces;
  address = a: "${a.address}/${toString a.prefixLength}";
  interfaces = lib.mapAttrsToList (name: i:
    { inherit name; }
    // lib.optionalAttrs (i.ipv4.addresses != []) {
      address = address (builtins.head i.ipv4.addresses);
    }
    // lib.optionalAttrs (i.ipv6.addresses != []) {
      address6 = address (builtins.head i.ipv6.addresses);
    }
  ) links;
in {
  services.velstra.appliance = lib.mkForce ((pkgs.formats.toml {}).generate
    "test-appliance.toml" {
      system.hostname = "sentinel-fw";
      interface = interfaces;
    });
}
