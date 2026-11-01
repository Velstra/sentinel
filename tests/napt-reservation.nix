# Actual NAT allocation under subscriber exhaustion and competing senders.
{ pkgs, sentinelModule, sentinel }:
pkgs.testers.runNixOSTest {
  name = "sentinel-napt-reservation";
  nodes.machine = {
    imports = [ sentinelModule ];
    networking.hostName = pkgs.lib.mkForce "machine";
    virtualisation.memorySize = 2048;
    virtualisation.cores = 4;
    virtualisation.vlans = [ 1 ];
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
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
  testScript = ''
    import json
    import shlex
    import re

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot-late.service")
    peer.wait_for_unit("multi-user.target")
    python = "${pkgs.python3}/bin/python3"

    def run(host, source, prefix=""):
        return host.succeed(prefix + python + " -u -c " + shlex.quote(source))

    def apply(*lines):
        source = "\n".join([*lines, "commit", "save", "exit", ""])
        output = machine.succeed("su admin -c " + shlex.quote("printf %s " + shlex.quote(source) + " | ${sentinel}/bin/sentinel configure 2>&1"))
        assert "commit ok: applied live" in output and "saved /" in output, output
        ready = json.loads(machine.succeed("${sentinel}/bin/sentinel agent-query 'interface eth1'"))
        assert ready["ready"] and ready["egress"], ready

    def drops():
        stats = machine.succeed("${sentinel}/bin/sentinel agent-query stats")
        return int(next(line.split()[-1] for line in stats.splitlines() if line.strip().startswith("egress_dropped ")))

    machine.succeed("ip netns add napt-client; ip link add napt-lan type veth peer name napt-end; ip link set napt-end netns napt-client")
    for command in ["ip link set lo up", "ip link set napt-end up", "ip addr add 10.90.0.2/24 dev napt-end", "ip route add default via 10.90.0.1"]:
        machine.succeed("ip netns exec napt-client " + command)
    apply("set interface eth1 address 198.18.90.1/24", "set interface eth1 zone wan", "set interface napt-lan address 10.90.0.1/24", "set interface napt-lan zone lan", "set firewall global default-action accept", "set firewall global stateful true", "set firewall zone wan default-action drop", "set nat source internet zone wan", "set nat source internet cgnat-block-size 1")
    block = machine.succeed("${sentinel}/bin/sentinel show nat cgnat 10.90.0.2")
    match = re.search(r"ports (\d+)-(\d+)", block)
    assert match, block
    first, last = map(int, match.groups())
    assert first == last and first >= 32768, block
    udp = "import socket,json,pathlib; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('198.18.90.2',18091)); pathlib.Path('/run/napt-echo-ready').touch();\nwhile True:\n data,addr=s.recvfrom(2048); pathlib.Path('/run/napt-peer.log').open('a').write(data.decode()+'\\n'); s.sendto(json.dumps({'payload':data.decode(),'source':addr}).encode(),addr)\n"
    peer.succeed("systemd-run --unit=napt-echo " + python + " -u -c " + shlex.quote(udp))
    peer.wait_until_succeeds("test -e /run/napt-echo-ready", timeout=10)
    client = "ip netns exec napt-client "

    with subtest("exhausted UDP allocation drops without escaping the block or replacing the owner"):
        before = drops()
        probe = "import socket,json; sockets=[]; results=[];\nfor port,payload in [(44331,b'first'),(44332,b'second')]:\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.90.0.2',port)); s.settimeout(1); sockets.append(s); s.sendto(payload,('198.18.90.2',18091));\n try: results.append(json.loads(s.recv(2048)))\n except TimeoutError: results.append(None)\nsockets[0].sendto(b'first-again',('198.18.90.2',18091)); results.append(json.loads(sockets[0].recv(2048))); print(json.dumps(results))\n"
        actual = json.loads(run(machine, probe, client))
        assert actual[0] == {"payload":"first", "source":["198.18.90.1",first]}, actual
        assert actual[1] is None, actual
        assert actual[2] == {"payload":"first-again", "source":["198.18.90.1",first]}, actual
        assert drops() > before
        assert peer.succeed("cat /run/napt-peer.log").splitlines() == ["first", "first-again"]

    def per_cpu_counter(slot):
        # Read the actual stable STATS ABI, without assuming packet CPU affinity.
        key = " ".join(format(byte,"02x") for byte in slot.to_bytes(4,"little"))
        result = json.loads(machine.succeed("bpftool -j map lookup name STATS key hex " + key))
        return {entry["cpu"]:int.from_bytes(bytes(int(byte,16) for byte in entry["value"]), "little") for entry in result["values"]}

    with subtest("four pinned senders race for one free port without changing its owner"):
        # A separate remote port gives this race a genuinely empty reverse key.
        udp2 = udp.replace("18091", "18092").replace("napt-peer", "napt-race-peer").replace("napt-echo-ready", "napt-race-ready")
        peer.succeed("systemd-run --unit=napt-race " + python + " -u -c " + shlex.quote(udp2))
        peer.wait_until_succeeds("test -e /run/napt-race-ready", timeout=10)
        race = "import os,socket,json,select,time,multiprocessing as mp; gate=mp.Barrier(4); q=mp.Queue();\ndef worker(cpu):\n os.sched_setaffinity(0,{cpu}); sockets=[]; results={};\n for i in range(8):\n  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.90.0.2',45000+cpu*100+i)); s.setblocking(False); sockets.append((s,('cpu%d-flow%d'%(cpu,i)).encode()))\n gate.wait(timeout=10)\n for round in range(3):\n  for s,payload in sockets: s.sendto(payload,('198.18.90.2',18092))\n  end=time.monotonic()+0.25\n  while time.monotonic()<end:\n   ready,_,_=select.select([s for s,_ in sockets],[],[],0.02)\n   for s in ready:\n    data=json.loads(s.recv(2048)); expected=next(p.decode() for sock,p in sockets if sock is s); assert data['payload']==expected,(data,expected); results[expected]=data\n q.put(results)\nps=[mp.Process(target=worker,args=(cpu,)) for cpu in range(4)]\nfor p in ps: p.start()\nresults=[q.get(timeout=15) for p in ps]\nfor p in ps: p.join(timeout=5); assert p.exitcode==0,p.exitcode\nprint(json.dumps(results))\n"
        before = drops()
        cpu_before = per_cpu_counter(22)
        actual = json.loads(run(machine, race, client))
        cpu_after = per_cpu_counter(22)
        print("OBSERVED_NETWORK_DROP_CPUS", json.dumps({cpu:cpu_after[cpu]-cpu_before[cpu] for cpu in range(4)}))
        winners = [entry for result in actual for entry in result.values()]
        assert len(winners) == 1 and winners[0]["source"] == ["198.18.90.1",first], actual
        assert drops() >= before + 31, (before, drops())
        observed = peer.succeed("cat /run/napt-race-peer.log").splitlines()
        assert len(observed) == 3 and set(observed) == {winners[0]["payload"]}, observed

    with subtest("a freed earlier candidate does not move another live UDP connection"):
        apply("set nat source internet cgnat-block-size 3")
        udp3 = udp.replace("18091", "18094").replace("napt-peer", "napt-reuse-peer").replace("napt-echo-ready", "napt-reuse-ready")
        peer.succeed("systemd-run --unit=napt-reuse " + python + " -u -c " + shlex.quote(udp3))
        peer.wait_until_succeeds("test -e /run/napt-reuse-ready", timeout=10)
        # Choose two source ports with the same first candidate, then observe
        # the actual translations. No translated port is assumed in the check.
        choose = "import json;\ndef seed(port):\n h=0x0a5a0002 ^ 0x5a02c612 ^ (port<<16) ^ 18094; h^=h>>16; h=(h*0x7feb352d)&0xffffffff; h^=h>>15; h=(h*0x846ca68b)&0xffffffff; return h^(h>>16)\nports=[p for p in range(43000,44000) if seed(p)%3==0][:2]; print(json.dumps(ports))\n"
        ports = json.loads(run(machine, choose))
        reuse = "import socket,json,pathlib,time; sockets=[]; results=[];\nfor port in " + repr(ports) + ":\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.90.0.2',port)); s.settimeout(2); sockets.append(s); s.sendto(str(port).encode(),('198.18.90.2',18094)); results.append(json.loads(s.recv(2048)))\npathlib.Path('/run/napt-reuse-state').write_text(json.dumps(results)); end=time.monotonic()+15\nwhile not pathlib.Path('/run/napt-reuse-continue').exists():\n assert time.monotonic()<end; time.sleep(0.02)\nsockets[1].sendto(b'reused',('198.18.90.2',18094)); pathlib.Path('/run/napt-reuse-result').write_text(json.dumps(json.loads(sockets[1].recv(2048))))\n"
        machine.succeed("systemd-run --unit=napt-reuse-client ip netns exec napt-client " + python + " -u -c " + shlex.quote(reuse))
        machine.wait_until_succeeds("test -e /run/napt-reuse-state", timeout=10)
        state = json.loads(machine.succeed("cat /run/napt-reuse-state"))
        assert state[0]["source"] != state[1]["source"], state
        import socket
        import struct
        policy = json.loads(machine.succeed("${sentinel}/bin/sentinel agent-query 'interface eth1'"))["policy"]
        key = struct.pack("<I4s4sHHB3x", policy, socket.inet_aton("198.18.90.2"), socket.inet_aton("198.18.90.1"), 18094, state[0]["source"][1], 17)
        machine.succeed("bpftool map delete name CONNTRACK key hex " + " ".join(format(byte,"02x") for byte in key))
        machine.succeed("touch /run/napt-reuse-continue")
        machine.wait_until_succeeds("test -e /run/napt-reuse-result", timeout=10)
        actual = json.loads(machine.succeed("cat /run/napt-reuse-result"))
        assert actual == {"payload":"reused", "source":state[1]["source"]}, (state, actual)
        machine.wait_until_succeeds("! systemctl is-active --quiet napt-reuse-client", timeout=10)
        machine.succeed("systemctl show napt-reuse-client -p ExecMainStatus --value | grep -x 0")
        apply("set nat source internet cgnat-block-size 1")

    with subtest("TCP exhaustion preserves an established connection and prevents a second handshake"):
        tcp = "import socketserver,json,pathlib;\nclass Handler(socketserver.StreamRequestHandler):\n def handle(self):\n  while data:=self.rfile.readline():\n   pathlib.Path('/run/napt-tcp-peer.log').open('a').write(data.decode()); self.wfile.write((json.dumps({'payload':data.decode().strip(),'source':self.client_address})+'\\n').encode()); self.wfile.flush()\nserver=socketserver.ThreadingTCPServer(('198.18.90.2',18093),Handler); pathlib.Path('/run/napt-tcp-ready').touch(); server.serve_forever()\n"
        peer.succeed("systemd-run --unit=napt-tcp " + python + " -u -c " + shlex.quote(tcp))
        peer.wait_until_succeeds("test -e /run/napt-tcp-ready", timeout=10)
        probe = "import socket,json; s=socket.socket(); s.bind(('10.90.0.2',44351)); s.settimeout(2); s.connect(('198.18.90.2',18093)); f=s.makefile('rb'); s.sendall(b'tcp-first\\n'); first=json.loads(f.readline()); other=socket.socket(); other.bind(('10.90.0.2',44352)); other.settimeout(1);\ntry: other.connect(('198.18.90.2',18093)); second=True\nexcept TimeoutError: second=False\ns.sendall(b'tcp-again\\n'); again=json.loads(f.readline()); print(json.dumps([first,second,again]))\n"
        before = drops()
        actual = json.loads(run(machine, probe, client))
        assert actual == [{"payload":"tcp-first", "source":["198.18.90.1",first]}, False, {"payload":"tcp-again", "source":["198.18.90.1",first]}], actual
        assert drops() > before
        assert peer.succeed("cat /run/napt-tcp-peer.log").splitlines() == ["tcp-first", "tcp-again"]

    with subtest("a failed NAT rewrite returns a counted drop instead of an untranslated packet"):
        programs = json.loads(machine.succeed("bpftool -j prog show"))
        egress = [program for program in programs if program["name"] == "velstra_egress"]
        assert len(egress) == 1, egress
        program_id = egress[0]["id"]
        ifindex = int(machine.succeed("cat /sys/class/net/eth1/ifindex"))
        prepare = "import socket,struct,pathlib;\ndef csum(b):\n s=sum(int.from_bytes(b[i:i+2],'big') for i in range(0,len(b),2)); s=(s&65535)+(s>>16); s=(s&65535)+(s>>16); return (~s)&65535\neth=bytes.fromhex('0200000000020200000000010800'); ip=struct.pack('!BBHHHBBH4s4s',0x45,0,28,91,0,64,17,0,socket.inet_aton('10.90.0.2'),socket.inet_aton('198.18.90.2')); ip=ip[:10]+struct.pack('!H',csum(ip))+ip[12:]; udp=struct.pack('!HHHH',44371,18095,8,0); pathlib.Path('/run/napt-full').write_bytes(eth+ip+udp); pathlib.Path('/run/napt-short').write_bytes(eth+ip+udp[:4]); ctx=bytearray(192); struct.pack_into('<I',ctx,40," + str(ifindex) + "); pathlib.Path('/run/napt-ctx').write_bytes(ctx)"
        run(machine, prepare)
        before = drops()
        positive = json.loads(machine.succeed("bpftool -j prog run id " + str(program_id) + " data_in /run/napt-full ctx_in /run/napt-ctx data_out /run/napt-full-out"))
        assert positive["retval"] == 0 and drops() == before, positive
        run(machine, "import pathlib,socket; packet=pathlib.Path('/run/napt-full-out').read_bytes(); assert socket.inet_ntoa(packet[26:30])=='198.18.90.1',packet.hex()")
        negative = json.loads(machine.succeed("bpftool -j prog run id " + str(program_id) + " data_in /run/napt-short ctx_in /run/napt-ctx data_out /run/napt-short-out"))
        assert negative["retval"] == 2 and drops() == before + 1, negative

    with subtest("controlled kernel invocations reserve ports safely on every CPU"):
        # Real packets above verify forwarding and delivery. Direct test-run
        # executes the same classifier synchronously on each pinned CPU; veth
        # softirq/RPS handoff cannot move it to a different packet-processing CPU.
        programs = json.loads(machine.succeed("bpftool -j prog show"))
        egress = [program for program in programs if program["name"] == "velstra_egress"]
        assert len(egress) == 1, egress
        program_id = egress[0]["id"]
        ifindex = int(machine.succeed("cat /sys/class/net/eth1/ifindex"))
        prepare = "import socket,struct,pathlib;\ndef csum(b):\n s=sum(int.from_bytes(b[i:i+2],'big') for i in range(0,len(b),2)); s=(s&65535)+(s>>16); s=(s&65535)+(s>>16); return (~s)&65535\neth=bytes.fromhex('0200000000020200000000010800'); ip=struct.pack('!BBHHHBBH4s4s',0x45,0,28,91,0,64,17,0,socket.inet_aton('10.90.0.2'),socket.inet_aton('198.18.90.2')); ip=ip[:10]+struct.pack('!H',csum(ip))+ip[12:];\nfor cpu in range(4):\n for trial in range(32):\n  udp=struct.pack('!HHHH',47100+cpu,18100+trial,8,0); pathlib.Path('/run/napt-cpu%d-trial%d'%(cpu,trial)).write_bytes(eth+ip+udp)\nctx=bytearray(192); struct.pack_into('<I',ctx,40," + str(ifindex) + "); pathlib.Path('/run/napt-smp-ctx').write_bytes(ctx)"
        run(machine, prepare)
        before = {slot:per_cpu_counter(slot) for slot in [21,22,23]}
        race = "import concurrent.futures,threading,subprocess,json; gate=threading.Barrier(4);\ndef worker(cpu):\n results=[]\n for trial in range(32):\n  gate.wait(timeout=20); path='/run/napt-cpu%d-trial%d'%(cpu,trial); result=json.loads(subprocess.check_output(['taskset','-c',str(cpu),'bpftool','-j','prog','run','id'," + repr(str(program_id)) + ",'data_in',path,'ctx_in','/run/napt-smp-ctx','data_out',path+'-out'],text=True)); results.append(result['retval'])\n return results\nwith concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool: results=list(pool.map(worker,range(4)))\nprint(json.dumps(results))\n"
        results = json.loads(run(machine, race))
        assert len(results) == 4 and all(len(row) == 32 for row in results), results
        after = {slot:per_cpu_counter(slot) for slot in [21,22,23]}
        for cpu in range(4):
            assert after[21][cpu] - before[21][cpu] >= 32, (cpu,before,after)
            admitted = sum(retval == 0 for retval in results[cpu])
            dropped = sum(retval == 2 for retval in results[cpu])
            assert admitted + dropped == 32, results[cpu]
            assert after[23][cpu] - before[23][cpu] >= admitted, (cpu,before,after)
            assert after[22][cpu] - before[22][cpu] >= dropped, (cpu,before,after)
        policy = json.loads(machine.succeed("${sentinel}/bin/sentinel agent-query 'interface eth1'"))["policy"]
        verify = "import pathlib,socket,struct,json,subprocess; results=" + repr(results) + ";\nfor trial in range(32):\n returns=[results[cpu][trial] for cpu in range(4)]; assert sorted(returns)==[0,2,2,2],(trial,returns); winner=returns.index(0); key=struct.pack('<I4s4sHHB3x'," + str(policy) + ",socket.inet_aton('198.18.90.2'),socket.inet_aton('198.18.90.1'),18100+trial," + str(first) + ",17); entry=json.loads(subprocess.check_output(['bpftool','-j','map','lookup','name','CONNTRACK','key','hex',*[format(byte,'02x') for byte in key]],text=True)); raw=bytes(int(byte,16) for byte in entry['value']); assert raw[:4]==socket.inet_aton('10.90.0.2') and int.from_bytes(raw[8:10],'little')==47100+winner,(trial,winner,raw.hex())\n for cpu in range(4):\n  packet=pathlib.Path('/run/napt-cpu%d-trial%d-out'%(cpu,trial)).read_bytes(); expected='198.18.90.1' if cpu==winner else '10.90.0.2'; assert socket.inet_ntoa(packet[26:30])==expected,(trial,cpu,packet.hex())\nprint('32 actual kernel allocation races have one owner each on four CPUs')\n"
        print(run(machine, verify))
        print("ACTUAL_CONTROLLED_NAT_CPUS", json.dumps({cpu:after[21][cpu]-before[21][cpu] for cpu in range(4)}))
  '';
}
