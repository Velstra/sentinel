{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-wren-acknowledged-static-reload";
  globalTimeout = 480;
  nodes = {
    machine = { lib, ... }: {
      imports = [
        self.nixosModules.sentinel
        (self.outPath + "/nix/test-network-seed.nix")
      ];
      virtualisation.memorySize = 2048;
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = lib.mkForce false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "10.10.0.1"; prefixLength = 24; } ];
      services.velstra.interface = lib.mkForce "eth1";
      environment.systemPackages = [ pkgs.python3 ];
    };
    reference = { ... }: {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [
        { address = "10.10.0.2"; prefixLength = 24; }
        { address = "198.19.244.1"; prefixLength = 32; }
        { address = "198.19.244.129"; prefixLength = 32; }
        { address = "198.19.244.200"; prefixLength = 32; }
      ];
    };
  };
  testScript = ''
    start_all()
    reference.wait_for_unit("multi-user.target")
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.wait_for_unit("velstra.service")
    machine.wait_for_unit("wren.service")
    machine.succeed("ping -c 1 -W 2 10.10.0.2")
    try:
        machine.succeed("${pkgs.python3}/bin/python3 -B ${./sentinel-wren-adapter-probe.py}", timeout=360)
    finally:
        machine.copy_from_machine("/run/qa-wren-adapter")
  '';
}
