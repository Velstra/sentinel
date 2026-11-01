{ pkgs, velstra }:
let
 agent = "${velstra}/bin/velstra";
 transfer=pkgs.writeText "startup-continuity-persistent-transfer.py" ''
   import socket,sys,time,json,pathlib,hashlib
   mode=sys.argv[1]
   with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:
       s.settimeout(60)
       if mode=='server':
           s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
           s.bind(('2001:db8:72::2',9106));s.listen(1)
           pathlib.Path('/run/startup-continuity-server-ready').touch()
           with s.accept()[0] as c:
               c.settimeout(60)
               while True:
                   part=c.recv(32768)
                   if not part:break
                   c.sendall(part)
       else:
           s.connect(('2001:db8:72::2',9106))
           port=s.getsockname()[1]
           digest=hashlib.sha256()
           for i in range(400):
               chunk=i.to_bytes(4,'big')*8192
               s.sendall(chunk);reply=bytes()
               while len(reply)<len(chunk):
                   part=s.recv(len(chunk)-len(reply))
                   assert part,'connection was reset or closed'
                   reply+=part
               assert reply==chunk
               digest.update(reply)
               progress=dict(iterations=i+1,bytes=(i+1)*len(chunk),port=port,sha256=digest.hexdigest(),exchanges=i+1)
               if i==63:
                   heartbeat=0
                   while not pathlib.Path('/run/restart-transfer-release').exists():
                       probe=b'continue-on-the-same-connection'
                       s.sendall(probe);received=bytes()
                       while len(received)<len(probe):
                           part=s.recv(len(probe)-len(received));assert part
                           received+=part
                       assert received==probe
                       heartbeat+=1
                       progress.update(exchanges=i+1+heartbeat,heartbeats=heartbeat)
                       progress_path=pathlib.Path('/run/startup-continuity-progress.json')
                       progress_path.with_suffix('.tmp').write_text(json.dumps(progress))
                       progress_path.with_suffix('.tmp').replace(progress_path)
                       time.sleep(.05)
               path=pathlib.Path('/run/startup-continuity-progress.json')
               path.with_suffix('.tmp').write_text(json.dumps(progress))
               path.with_suffix('.tmp').replace(path)
               time.sleep(.05)
           pathlib.Path('/run/startup-continuity-complete.json').write_text(json.dumps(progress))
 '';
 query=pkgs.writeText "startup-continuity-query.py" ''
   import socket
   with socket.socket(socket.AF_UNIX) as s:
       s.connect('/run/startup-continuity-agent.sock');s.sendall(b'status\n');s.shutdown(socket.SHUT_WR)
       print(s.makefile().read())
 '';
 policy=pkgs.writeText "startup-continuity-restart-policy.toml" ''
   stateful=true
   default_action="drop"
   fail_closed=true
 '';
in pkgs.testers.runNixOSTest {
 name="sentinel-agent-startup-continuity";
 nodes.machine={
  virtualisation.memorySize=2048;virtualisation.cores=2;
  environment.systemPackages=[pkgs.python3 pkgs.iproute2 pkgs.bpftools];
 };
 testScript=''
   import json
   machine.wait_for_unit("multi-user.target")
   machine.succeed("ip netns add continuity-peer; ip link add continuity-r type veth peer name continuity-p; ip link set continuity-p netns continuity-peer")
   machine.succeed("ip link set continuity-r address 02:00:00:72:00:01; ip link set continuity-r up; ip -6 addr add 2001:db8:72::1/64 dev continuity-r nodad")
   machine.succeed("ip netns exec continuity-peer ip link set continuity-p address 02:00:00:72:00:02; ip netns exec continuity-peer ip link set continuity-p up; ip netns exec continuity-peer ip link set lo up; ip netns exec continuity-peer ip -6 addr add 2001:db8:72::2/64 dev continuity-p nodad")
   machine.succeed("ip -6 neigh replace 2001:db8:72::2 lladdr 02:00:00:72:00:02 dev continuity-r nud permanent; ip netns exec continuity-peer ip -6 neigh replace 2001:db8:72::1 lladdr 02:00:00:72:00:01 dev continuity-p nud permanent")
   machine.succeed("mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf")
   command="${agent} run --iface continuity-r --egress --xdp-mode skb --config ${policy} --datapath-state-dir /sys/fs/bpf/startup-continuity-restart --query-socket /run/startup-continuity-agent.sock"
   machine.succeed("systemd-run --unit=fresh-verifier-probe ${pkgs.python3}/bin/python3 ${./helpers/pause-datapath-verifier.py} /run/fresh-verifier-test "+command)
   machine.wait_until_succeeds("test -f /run/fresh-verifier-test.paused",timeout=30)
   fresh_gate=json.loads(machine.succeed("bpftool -j map lookup pinned /sys/fs/bpf/startup-continuity-restart/apply-state key hex 00 00 00 00"))
   assert fresh_gate['value']==['0x01','0x00','0x00','0x00'],fresh_gate
   machine.succeed("systemctl kill --signal=KILL fresh-verifier-probe.service")
   machine.wait_until_succeeds("test $(systemctl show fresh-verifier-probe.service -p MainPID --value) -eq 0",timeout=10)
   machine.succeed("systemd-run --unit=startup-continuity-agent1 "+command)
   machine.wait_until_succeeds("${pkgs.python3}/bin/python3 ${query} | grep '^Ready$'",timeout=30)
   machine.fail("ip netns exec continuity-peer ping -6 -c 1 -W 1 2001:db8:72::1")
   machine.succeed("systemd-run --unit=startup-continuity-server ip netns exec continuity-peer ${pkgs.python3}/bin/python3 ${transfer} server")
   machine.wait_until_succeeds("test -f /run/startup-continuity-server-ready",timeout=15)
   machine.succeed("systemd-run --unit=startup-continuity-client ${pkgs.python3}/bin/python3 ${transfer} client")
   machine.wait_until_succeeds("test -f /run/startup-continuity-progress.json",timeout=15)
   before=json.loads(machine.succeed("cat /run/startup-continuity-progress.json"))
   slots=json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/flow-slot-v1"))["id"]
   index_map=json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/flow-index-v1"))["id"]
   xdp_table=json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/ipv6-programs"))["id"]
   tc_table=json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/ipv6-tc-programs"))["id"]
   machine.succeed("systemctl kill --signal=KILL startup-continuity-agent1.service")
   machine.wait_until_succeeds("test $(systemctl show startup-continuity-agent1.service -p MainPID --value) -eq 0",timeout=10)
   machine.sleep(1)
   survived=json.loads(machine.succeed("cat /run/startup-continuity-progress.json"))
   assert survived['exchanges']>before['exchanges'] and survived['port']==before['port'],(before,survived)
   machine.succeed("systemd-run --unit=startup-continuity-agent2 ${pkgs.python3}/bin/python3 ${./helpers/pause-datapath-verifier.py} /run/verifier-test "+command)
   machine.wait_until_succeeds("test -f /run/verifier-test.paused",timeout=30)
   machine.sleep(1)
   paused_before=json.loads(machine.succeed("cat /run/startup-continuity-progress.json"))
   machine.sleep(3)
   paused_after=json.loads(machine.succeed("cat /run/startup-continuity-progress.json"))
   gate=json.loads(machine.succeed("bpftool -j map lookup pinned /sys/fs/bpf/startup-continuity-restart/apply-state key hex 00 00 00 00"))
   print('ACTUAL_PAUSED_VERIFIER_TRAFFIC '+json.dumps(dict(before=paused_before,after=paused_after,gate=gate)),flush=True)
   machine.fail("ip netns exec continuity-peer ping -6 -c 1 -W 1 2001:db8:72::1")
   machine.succeed("touch /run/verifier-test.resume")
   assert gate['value']==['0x00','0x00','0x00','0x00'],gate
   assert paused_after['exchanges']>paused_before['exchanges'], 'existing TCP flow stopped during verifier preflight'

   machine.wait_until_succeeds("${pkgs.python3}/bin/python3 ${query} | grep '^Ready$'",timeout=30)
   assert json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/flow-slot-v1"))["id"]==slots
   assert json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/flow-index-v1"))["id"]==index_map
   assert json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/ipv6-programs"))["id"]==xdp_table
   assert json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/startup-continuity-restart/ipv6-tc-programs"))["id"]==tc_table
   machine.succeed("touch /run/restart-transfer-release")
   machine.wait_until_succeeds("test -f /run/startup-continuity-complete.json",timeout=60)
   after=json.loads(machine.succeed("cat /run/startup-continuity-complete.json"))
   assert after['iterations']==400 and after['port']==before['port'] and after['bytes']==13107200,after
   machine.wait_until_succeeds("test $(systemctl show startup-continuity-client.service -p ExecMainStatus --value) -eq 0",timeout=10)
   machine.succeed("systemctl stop startup-continuity-agent2.service; ${agent} detach --datapath-state-dir /sys/fs/bpf/startup-continuity-restart")
   machine.succeed("test -z $(find /sys/fs/bpf/startup-continuity-restart -type f -print -quit); ip link del continuity-r; ip netns del continuity-peer")
   print("ACTUAL_AGENT_STARTUP_CONTINUITY "+json.dumps(dict(result="PASS",before=before,duringCrash=survived,after=after,defaultDeny=True,connectionUnchanged=True,stateAndStageMapsPreserved=True,cleanup=True)),flush=True)
 '';
}
