# Do not let periodic filesystem writeback hide missing durability guarantees.
{ pkgs, sentinelModule }:
pkgs.testers.runNixOSTest {
  name = "sentinel-management-tls-powerloss";
  nodes.machine = { lib, ... }: {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    virtualisation.emptyDiskImages = [ 512 ];
    virtualisation.fileSystems."/var/lib/sentinel" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
      options = [ "commit=600" ];
    };
    environment.systemPackages = [ pkgs.curl pkgs.openssl pkgs.strace ];
    systemd.services.sentinel-api.serviceConfig.ExecStart = lib.mkForce "${pkgs.strace}/bin/strace -f -yy -e trace=fsync,fdatasync -o /var/lib/sentinel/tls-publish.trace /run/current-system/sw/bin/sentinel api --listen 127.0.0.1:8080 --config /var/lib/sentinel/appliance.toml --token-file /var/lib/sentinel/api-token";
  };
  testScript = ''
    import re
    def start_api():
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot-late.service")
        machine.succeed("systemctl start sentinel-api.service")
        machine.wait_until_succeeds("curl -fsSk https://127.0.0.1:8080/api/v1/health | grep -q ok", timeout=30)

    def certificate():
        return machine.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -noout -fingerprint -sha256").strip()

    # Another startup may create the directory before this process acquires
    # the generation lock. Existing does not mean its parent entry is durable.
    machine.wait_for_unit("sentinel-boot-late.service")
    machine.succeed("mkdir -p /var/lib/sentinel/web-tls")
    start_api()
    first = certificate()
    trace = machine.succeed("cat /var/lib/sentinel/tls-publish.trace")
    syncs = re.findall(r"fsync\(\d+<([^>]+)>\)\s+= 0", trace)
    published = max(i for i, path in enumerate(syncs) if path == "/var/lib/sentinel/web-tls")
    assert "/var/lib/sentinel" in syncs[published + 1:], "preexisting TLS directory was not anchored durably after publication"
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
