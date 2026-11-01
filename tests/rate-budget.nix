# Shared budgets are not multiplied by packet-processing CPU count.
{ pkgs, sentinelModule }:
pkgs.testers.runNixOSTest {
  name = "sentinel-rate-budget";
  nodes.machine = {
    imports = [ sentinelModule ];
    networking.hostName = pkgs.lib.mkForce "machine";
    virtualisation.memorySize = 2048;
    virtualisation.cores = 4;
    virtualisation.vlans = [ 1 ];
    environment.systemPackages = [ pkgs.python3 pkgs.bpftools ];
  };
  nodes.peer = {
    networking.hostName = "peer";
    networking.useDHCP = false;
    networking.firewall.enable = false;
    virtualisation.vlans = [ 1 ];
    networking.interfaces.eth1.ipv4.addresses = [ { address = "198.18.90.2"; prefixLength = 24; } ];
    environment.systemPackages = [ pkgs.python3 ];
  };
  testScript = builtins.readFile ./rate-budget.py;
}
