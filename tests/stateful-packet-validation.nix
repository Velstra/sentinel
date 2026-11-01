# Exercise the actual packaged packet entries with declared IP/L4 lengths.
{ pkgs, sentinelModule, velstra }:
let
  config = pkgs.writeText "stateful-packet-policy.toml" ''
    stateful = true
    default_action = "drop"
    [[port_rule]]
    proto = "tcp"
    port = 443
    action = "pass"
    [[port_rule]]
    proto = "udp"
    port = 53
    action = "pass"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-stateful-packet-validation";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.bpftools pkgs.python3 ];
  };
  testScript = ''
    import json
    import struct
    import hashlib
    machine.wait_for_unit("sentinel-boot.service")
    machine.succeed("systemctl stop velstra.service")
    machine.succeed("if test -d /sys/fs/bpf/sentinel; then ${velstra}/bin/velstra detach --datapath-state-dir /sys/fs/bpf/sentinel; fi")
    machine.succeed("systemctl mask --runtime velstra.service")
    machine.succeed("ip link add validate-u type veth peer name validate-p; ip link set validate-u up; ip link set validate-p up")
    machine.succeed("systemd-run --unit=validate-agent ${velstra}/bin/velstra run --iface validate-u --egress --xdp-mode skb --config ${config} --query-socket /run/validate-agent.sock")
    machine.wait_until_succeeds("test -S /run/validate-agent.sock",timeout=30)
    programs=json.loads(machine.succeed("bpftool -j prog show"))
    def prog(name):
        matches=[p['id'] for p in programs if p['name']==name]
        assert len(matches)==1,(name,matches)
        return matches[0]
    ingress=prog("velstra")
    egress=prog("velstra_egress")
    def tcp(sport,dport,flags=2,offset=5,options=b""):
        return struct.pack("!HHIIBBHHH",sport,dport,100,0,offset<<4,flags,65535,0,0)+options
    def checksum(data):
        if len(data)%2: data+=b'\x00'
        value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
        while value>>16: value=(value&65535)+(value>>16)
        return (~value)&65535
    def transport_checksum(payload,proto,source,destination,family):
        if proto not in [6,17] or len(payload)<(20 if proto==6 else 8): return payload
        offset=16 if proto==6 else 6
        pseudo=source+destination+(struct.pack('!BBH',0,proto,len(payload)) if family==4 else struct.pack('!I3xB',len(payload),proto))
        data=bytearray(payload)
        data[offset:offset+2]=b'\x00\x00'
        value=checksum(pseudo+data)
        data[offset:offset+2]=struct.pack('!H',value or 65535)
        return bytes(data)
    def ip4(payload,proto=6,total=None):
        length=20+len(payload) if total is None else total
        head=struct.pack("!BBHHHBBH4s4s",0x45,0,length,0,0,64,proto,0,b"\xc0\x00\x02\x01",b"\xc6\x33\x64\x02")
        head=bytearray(head)
        head[10:12]=struct.pack('!H',checksum(head))
        payload=transport_checksum(payload,proto,head[12:16],head[16:20],4)
        return bytes.fromhex("0200000000020200000000010800")+head+payload
    def ip6(payload,proto=6):
        head=struct.pack("!IHBB16s16s",6<<28,len(payload),proto,64,bytes.fromhex("20010db8000000000000000000000001"),bytes.fromhex("20010db8000000000000000000000002"))
        payload=transport_checksum(payload,proto,head[8:24],head[24:40],6)
        return bytes.fromhex("02000000000202000000000186dd")+head+payload
    def run(program,packet):
        machine.succeed("printf '%s' '"+packet.hex()+"' | ${pkgs.python3}/bin/python3 -c 'import sys;open(\"/run/validate-packet\",\"wb\").write(bytes.fromhex(sys.stdin.read()))'")
        return json.loads(machine.succeed("bpftool -j prog run id "+str(program)+" data_in /run/validate-packet"))['retval']
    # A real accepted request seeds the legacy return-grant path as well.
    assert run(ingress,ip4(tcp(45000,443)))==2
    cases=[]
    def check(name,program,packet,expected):
        actual=run(program,packet)
        cases.append(dict(name=name,actual=actual,expected=expected))
    for name,program,allow,deny in [('ingress',ingress,2,1),('egress',egress,0,2)]:
        check(name+'-valid-v4-tcp',program,ip4(tcp(45001,443)),allow)
        check(name+'-valid-v6-tcp',program,ip6(tcp(45001,443)),allow)
        check(name+'-truncated-v4-tcp',program,ip4(struct.pack('!HH',45002,443)),deny)
        check(name+'-truncated-v6-tcp',program,ip6(struct.pack('!HH',45002,443)),deny)
        check(name+'-short-tcp-offset',program,ip4(tcp(45003,443,offset=4)),deny)
        check(name+'-syn-rst',program,ip4(tcp(45004,443,flags=6)),deny)
        check(name+'-duplicate-window-scale',program,ip4(tcp(45005,443,offset=7,options=b'\x03\x03\x02\x03\x03\x04\x01\x01')),deny)
        check(name+'-maximum-option-padding',program,ip4(tcp(45009,443,offset=15,options=bytes([1])*40)),allow)
        check(name+'-last-window-scale-option',program,ip6(tcp(45010,443,offset=15,options=bytes([1])*37+b'\x03\x03\x0e')),allow)
        check(name+'-window-scale-without-syn',program,ip4(tcp(45011,443,flags=16,offset=6,options=b'\x03\x03\x02\x01')),deny)
        check(name+'-zero-option-length',program,ip6(tcp(45012,443,offset=6,options=b'\x02\x00\x00\x00')),deny)
        udp=struct.pack('!HHHH',45006,53,8,0)
        check(name+'-valid-v4-udp',program,ip4(udp,17),allow)
        check(name+'-valid-v6-udp',program,ip6(udp,17),allow)
        check(name+'-short-udp-length',program,ip4(struct.pack('!HHHH',45007,53,4,0),17),deny)
        check(name+'-udp-beyond-ip',program,ip6(struct.pack('!HHHH',45007,53,100,0),17),deny)
        # Padding is outside the declared IP payload and cannot complete TCP.
        check(name+'-padding-not-tcp',program,ip4(tcp(45008,443),total=24)+bytes(32),deny)
    # Swap the actual address pair and ports of the seeded request. Four TCP
    # bytes must not inherit its return permission, even inside a padded frame.
    reply=bytearray(ip4(struct.pack('!HH',443,45000))+bytes(36))
    reply[26:30],reply[30:34]=reply[30:34],reply[26:30]
    check('malformed-return-grant',ingress,bytes(reply),1)
    failures=[case for case in cases if case['actual']!=case['expected']]
    print('ACTUAL_STATEFUL_PACKET_VALIDATION '+json.dumps(dict(cases=cases,result='FAIL' if failures else 'PASS')),flush=True)
    assert not failures,failures
    # Simulate a nested invocation while the per-CPU parser buffer is owned.
    # bpftool replicates a per-CPU update to every possible CPU. The complete
    # buffer must remain untouched, including the original owner's busy flag.
    maps=json.loads(machine.succeed("bpftool -j map show"))
    def map_by_name(name):
        matches=[m for m in maps if m['name']==name]
        assert len(matches)==1,(name,matches)
        return matches[0]
    scratch=map_by_name('FW_PKT_BUF')
    def update_scratch(value):
        assert len(value)==scratch['bytes_value'],scratch
        machine.succeed('bpftool map update id '+str(scratch['id'])+' key hex 00 00 00 00 value hex '+value.hex(' '))
    def lookup(map_id,key):
        return json.loads(machine.succeed('bpftool -j map lookup id '+str(map_id)+' key hex '+struct.pack('<I',key).hex(' ')))
    def counter_sum(entry):
        def number(value):
            return value if isinstance(value,int) else int.from_bytes(bytes(int(x,16) if isinstance(x,str) else x for x in value),'little')
        return sum(number(v['value']) for v in entry['values'])
    stats=map_by_name('STATS')
    before_count=counter_sum(lookup(stats['id'],46))
    busy=struct.pack('<I',1)+bytes([165])*(scratch['bytes_value']-4)
    update_scratch(busy)
    before_buffer=lookup(scratch['id'],0)
    for program,deny in [(ingress,1),(egress,2)]:
        assert run(program,ip4(tcp(45100,443)))==deny
    assert lookup(scratch['id'],0)==before_buffer,'nested validator changed the owner buffer'
    assert counter_sum(lookup(stats['id'],46))==before_count+2
    update_scratch(bytes(scratch['bytes_value']))
    assert run(ingress,ip4(tcp(45101,443)))==2
    assert run(egress,ip4(tcp(45101,443)))==0
    print('ACTUAL_PACKET_VALIDATION_CONTENTION_PASS',flush=True)
    # Exercise real TCP traffic through the same hooks with veth offloads left
    # enabled, including TC's non-linear skb reads, not only test-run frames.
    machine.succeed("ip address add 192.0.2.1/24 dev validate-u; ip netns add validate-client; ip link set validate-p netns validate-client")
    machine.succeed("ip netns exec validate-client ip link set lo up; ip netns exec validate-client ip link set validate-p up; ip netns exec validate-client ip address add 192.0.2.2/24 dev validate-p")
    machine.succeed("mkdir -p /run/validate-content; ${pkgs.python3}/bin/python3 -c 'open(\"/run/validate-content/data\",\"wb\").write(bytes(range(256))*32768)'")
    machine.succeed("systemd-run --unit=validate-http ${pkgs.python3}/bin/python3 -m http.server 443 --directory /run/validate-content")
    machine.wait_for_open_port(443)
    actual=machine.succeed("ip netns exec validate-client ${pkgs.curl}/bin/curl --fail --max-time 30 -s http://192.0.2.1:443/data | sha256sum").split()[0]
    assert actual==hashlib.sha256(bytes(range(256))*32768).hexdigest(),actual
    print("ACTUAL_STATEFUL_PACKET_TRANSFER_PASS",flush=True)
  '';
}
