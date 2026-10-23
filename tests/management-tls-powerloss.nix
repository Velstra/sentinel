# Do not let periodic filesystem writeback hide missing durability guarantees.
{ pkgs, sentinelModule }:
pkgs.testers.runNixOSTest {
  name = "sentinel-management-tls-powerloss";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    virtualisation.emptyDiskImages = [ 512 ];
    virtualisation.fileSystems."/var/lib/sentinel" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
      options = [ "commit=600" ];
    };
    environment.systemPackages = [ pkgs.curl pkgs.openssl ];
  };
  testScript = ''
    def start_api():
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot-late.service")
        machine.succeed("systemctl start sentinel-api.service")
        machine.wait_until_succeeds("curl -fsSk https://127.0.0.1:8080/api/v1/health | grep -q ok", timeout=30)

    def certificate():
        return machine.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -noout -fingerprint -sha256").strip()

    start_api()
    first = certificate()
    machine.succeed("test $(stat -c %a /var/lib/sentinel/web-tls/key.pem) = 600")
    # This is an actual abrupt QEMU power loss. No guest sync or shutdown.
    machine.crash()
    machine.start()
    start_api()
    second = certificate()
    assert first == second, "published management certificate changed after abrupt power loss"
    machine.crash()
    machine.start()
    start_api()
    third = certificate()
    assert first == third, "management identity changed after the second power loss"
    print("ACTUAL_MANAGEMENT_TLS_POWERLOSS PASS crashes=2 certificate=stable", flush=True)
  '';
}
