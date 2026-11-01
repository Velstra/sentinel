{ pkgs, sentinelModule }:
let
  serve = pkgs.writeText "rule-context-http.py" ''
    import http.server,socket,threading
    class Server6(http.server.ThreadingHTTPServer):
        address_family=socket.AF_INET6
        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            super().server_bind()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'velstra-rule-context-traffic'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    ipv4=http.server.ThreadingHTTPServer(('0.0.0.0',9088),Handler)
    ipv6=Server6(('::',9088),Handler)
    threading.Thread(target=ipv4.serve_forever,daemon=True).start()
    ipv6.serve_forever()
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-independent-rule-contexts";
  nodes.fw = { lib, ... }: {
    imports = [ sentinelModule ];
    networking.hostName = lib.mkForce "fw";
    networking.firewall.enable = lib.mkForce false;
    virtualisation.memorySize = 2048;
    virtualisation.vlans = [ 1 ];
    environment.systemPackages = [ pkgs.python3 pkgs.curl ];
  };
  nodes.peer = {
    networking.useDHCP = false;
    networking.firewall.enable = false;
    virtualisation.vlans = [ 1 ];
    networking.interfaces.eth1.ipv4.addresses = [ { address = "198.18.84.2"; prefixLength = 24; } ];
    networking.interfaces.eth1.ipv6.addresses = [ { address = "2001:db8:84::2"; prefixLength = 64; } ];
    environment.systemPackages = [ pkgs.python3 pkgs.curl ];
  };
  testScript = ''
    import json,shlex
    start_all()
    for m in (fw,peer):
        m.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot-late.service")
    original_boot=fw.succeed("cat /proc/sys/kernel/random/boot_id").strip()
    commands=["set firewall global default-action accept", "set interface eth1 address 198.18.84.1/24", "set interface eth1 address6 2001:db8:84::1/64", "set interface eth1 zone edge", "set firewall zone edge default-action accept"]
    for context in range(4):
        name=f"context-{context}"
        commands += [f"set firewall rule {name} from edge", f"set firewall rule {name} proto tcp", f"set firewall rule {name} port 9088", f"set firewall rule {name} family {'ipv6' if context & 2 else 'ipv4'}", f"set firewall rule {name} direction {'out' if context & 1 else 'in'}", f"set firewall rule {name} action accept"]
    def configure(lines):
        script="printf '%s\\n' "+" ".join(shlex.quote(x) for x in lines+["commit","save","exit"])+" | sentinel configure 2>&1"
        output=fw.succeed("su admin -c "+shlex.quote(script))
        assert 'commit ok: applied live' in output and 'saved /' in output,output
        fw.wait_until_succeeds("sentinel agent-query status | grep '^Ready$'",timeout=30)
    configure(commands)
    for m in (fw,peer):
        m.succeed("systemd-run --unit=rule-context-http ${pkgs.python3}/bin/python3 ${serve}")
        m.wait_until_succeeds("ss -ltn | grep -q ':9088'",timeout=10)
    checks=[]
    def traffic(context):
        origin,target=(fw,'198.18.84.2') if context & 1 else (peer,'198.18.84.1')
        if context & 2:
            target='[2001:db8:84::2]' if context & 1 else '[2001:db8:84::1]'
        code,body=origin.execute(f"curl --noproxy '*' --silent --fail --max-time 1 http://{target}:9088/")
        if code==0:assert body=='velstra-rule-context-traffic',body
        return code==0
    for pattern in range(16):
        configure([f"set firewall rule context-{context} action {'accept' if pattern & (1 << context) else 'drop'}" for context in range(4)])
        for context in range(4):
            passed=traffic(context)
            assert passed==bool(pattern & (1 << context)),(pattern,context,passed)
            checks.append(dict(pattern=pattern,context=context,passed=passed))
    # An explicit IPv4 /0 is still an IPv4 constraint, not a dual-stack wildcard.
    configure([f"delete firewall rule context-{context}" for context in range(4)]+["set firewall rule zero-v4 from edge", "set firewall rule zero-v4 proto tcp", "set firewall rule zero-v4 port 9088", "set firewall rule zero-v4 source 0.0.0.0/0", "set firewall rule zero-v4 action drop"])
    assert [traffic(c) for c in range(4)]==[False,False,True,True]
    configure(["delete firewall rule zero-v4"]+commands[5:])
    # Delete one context and retain all other default-deny rules on this matcher.
    configure([f"set firewall rule context-{context} action drop" for context in range(4)]+["delete firewall rule context-3"])
    assert [traffic(c) for c in range(4)]==[False,False,False,True]
    fw.shutdown()
    fw.start()
    fw.wait_for_unit("sentinel-boot-late.service")
    fw.wait_until_succeeds("sentinel agent-query status | grep '^Ready$'",timeout=30)
    assert fw.succeed("cat /proc/sys/kernel/random/boot_id").strip()!=original_boot
    fw.succeed("systemd-run --unit=rule-context-http ${pkgs.python3}/bin/python3 ${serve}")
    fw.wait_until_succeeds("curl --silent --fail http://127.0.0.1:9088/ | grep -q velstra-rule-context-traffic",timeout=10)
    assert [traffic(c) for c in range(4)]==[False,False,False,True]
    print("ACTUAL_APPLIANCE_RULE_CONTEXTS "+json.dumps(dict(result="PASS",checks=checks,canonicalSave=True,delete=True,coldBoot=True,explicitIpv4Any=True)),flush=True)
  '';
}
