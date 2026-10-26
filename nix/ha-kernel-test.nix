{ pkgs, velstra-ha-tests }:
pkgs.testers.runNixOSTest {
  name = "sentinel-ha-kernel";
  nodes.machine = {
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ velstra-ha-tests ];
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("velstra-ha-tests --ignored conntrack_sync::secure::tests::kernel_ --nocapture")
  '';
}
