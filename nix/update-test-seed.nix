# Only the immutable donor/update fixture: the real first counted boot must
# already declare a dataplane. Keep the global address-only factory helper as-is.
{ config, lib, pkgs, ... }:
let
  links = lib.filterAttrs (name: i:
    name != "lo" && (i.ipv4.addresses != [] || i.ipv6.addresses != [])
  ) config.networking.interfaces;
  address = a: "${a.address}/${toString a.prefixLength}";
  interfaces = lib.mapAttrsToList (name: i:
    { inherit name; }
    // lib.optionalAttrs (name == "eth1") { zone = "wan"; }
    // lib.optionalAttrs (i.ipv4.addresses != []) {
      address = address (builtins.head i.ipv4.addresses);
    }
    // lib.optionalAttrs (i.ipv6.addresses != []) {
      address6 = address (builtins.head i.ipv6.addresses);
    }
  ) links;
in {
  assertions = [
    {
      assertion = builtins.attrNames links == [ "eth1" ]
        && config.virtualisation.vlans == [ 1 ]
        && builtins.length links.eth1.ipv4.addresses <= 1
        && builtins.length links.eth1.ipv6.addresses <= 1;
      message = "The immutable update fixture requires exactly the addressed eth1 NIC on test VLAN 1, with at most one address per family.";
    }
  ];
  services.velstra.interface = lib.mkForce "eth1";
  services.velstra.appliance = lib.mkForce ((pkgs.formats.toml {}).generate
    "update-test-appliance.toml" {
      system.hostname = "sentinel-fw";
      interface = interfaces;
    });
  environment.etc."sentinel-update-observer.py".source = ./update-test-observer.py;
}
