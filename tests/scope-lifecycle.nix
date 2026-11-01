{ pkgs, sentinelModule, velstra, controller }:
let config = pkgs.writeText "scope-original.toml" ''
  [[policy]]
  id = 1
  name = "display only"
  state_scope = "zone/b"
  stateful = true
  default_action = "drop"
  [[interface]]
  name = "scope-t"
  policy = 1
'';
in pkgs.testers.runNixOSTest {
  name = "sentinel-state-scope-lifecycle";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.bpftools pkgs.python3 ];
  };
  testScript = ''
    import json
    import time
    machine.wait_for_unit("sentinel-boot.service")
    machine.succeed("systemctl stop velstra.service")
    machine.succeed("if test -d /sys/fs/bpf/sentinel; then ${velstra}/bin/velstra detach --datapath-state-dir /sys/fs/bpf/sentinel; fi")
    machine.succeed("systemctl mask --runtime velstra.service")
    machine.succeed("ip link add scope-t type veth peer name scope-peer")
    machine.succeed("ip link set scope-t up; ip link set scope-peer up")
    machine.succeed("mkdir -p /run/scope-controller; cp ${config} /run/scope-controller/probe.toml")
    machine.succeed("systemd-run --unit=scope-controller ${controller}/bin/velstra-controller serve --listen 127.0.0.1:50051 --config-dir /run/scope-controller --poll-interval 1")
    machine.wait_for_open_port(50051)
    machine.succeed("cat > /run/systemd/system/scope-agent.service <<'UNIT'\n[Service]\nExecStart=${velstra}/bin/velstra run --iface scope-t --xdp-mode skb --node-id probe --controller http://127.0.0.1:50051 --query-socket /run/scope-agent.sock --datapath-state-dir /sys/fs/bpf/scope-pins\nRestart=no\nUNIT")
    machine.succeed("systemctl daemon-reload; systemctl start scope-agent.service")
    def wait_ready():
        machine.wait_until_succeeds("${pkgs.python3}/bin/python3 -c \"import socket;s=socket.socket(socket.AF_UNIX);s.connect('/run/scope-agent.sock');s.sendall(b'status\\n');assert s.recv(4096).decode().strip()=='Ready'\"",timeout=30)
    def scope(policy):
        key=" ".join(f"{value:02x}" for value in policy.to_bytes(4,"little"))
        row=json.loads(machine.succeed("bpftool -j map lookup pinned /sys/fs/bpf/scope-pins/flow-policies-v1 key hex "+key))
        raw=bytes(int(value,16) for value in row['value'])
        return (int.from_bytes(raw[:8],'little'),int.from_bytes(raw[8:16],'little'))
    def map_ids():
        result={}
        for name in ['flow-slot-v1','flow-index-v1','flow-allocator-v1','flow-scope-meta-v1','flow-labels-v1','flow-policies-v1','flow-timeouts-v1']:
            info=json.loads(machine.succeed("bpftool -j map show pinned /sys/fs/bpf/scope-pins/"+name))
            result[name]=(info[0] if isinstance(info,list) else info)['id']
        return result
    def publish(text):
        machine.succeed("cat > /run/scope-controller/probe.next <<'CFG'\n"+text+"\nCFG\nmv /run/scope-controller/probe.next /run/scope-controller/probe.toml")
    def wait_binding(policy, before, equal):
        key=" ".join(f"{value:02x}" for value in policy.to_bytes(4,"little"))
        for attempt in range(100):
            code, text=machine.execute("bpftool -j map lookup pinned /sys/fs/bpf/scope-pins/flow-policies-v1 key hex "+key)
            if code==0:
                row=json.loads(text)
                raw=bytes(int(value,16) for value in row['value'])
                current=(int.from_bytes(raw[:8],'little'),int.from_bytes(raw[8:16],'little'))
                if (current==before)==equal:
                    return current
            time.sleep(0.2)
        raise AssertionError("policy scope did not converge")
    wait_ready()
    first=scope(1)
    ids=map_ids()
    moved="[[policy]]\nid=1\nstate_scope='zone/a'\nstateful=true\n[[policy]]\nid=2\nstate_scope='zone/b'\nstateful=true\n[[interface]]\nname='scope-t'\npolicy=2\n"
    original_pid=machine.succeed("systemctl show scope-agent.service -p MainPID --value").strip()
    publish(moved)
    assert wait_binding(2,first,True)==first and scope(1)!=first
    wait_ready()
    assert machine.succeed("systemctl show scope-agent.service -p MainPID --value").strip()==original_pid
    assert map_ids()==ids,"agent restart replaced persistent state maps"
    # A hard daemon loss retains the maps and namespace as well as enforcement.
    machine.succeed("systemctl kill --signal=KILL scope-agent.service")
    machine.wait_until_fails("systemctl is-active scope-agent.service")
    machine.succeed("rm -f /run/scope-agent.sock; systemctl reset-failed scope-agent.service; systemctl start scope-agent.service")
    wait_ready()
    assert scope(2)==first and map_ids()==ids
    publish("[[policy]]\nid=1\nstate_scope='zone/a'\nstateful=true\n[[interface]]\nname='scope-t'\npolicy=1\n")
    machine.wait_until_fails("bpftool map lookup pinned /sys/fs/bpf/scope-pins/flow-policies-v1 key hex 02 00 00 00",timeout=20)
    wait_ready()
    recovered_pid=machine.succeed("systemctl show scope-agent.service -p MainPID --value").strip()
    publish(moved)
    recreated=wait_binding(2,first,False)
    wait_ready()
    assert recreated[0]>first[0]
    assert machine.succeed("systemctl show scope-agent.service -p MainPID --value").strip()==recovered_pid
    assert map_ids()==ids
    machine.succeed("systemctl stop scope-agent.service")
    machine.succeed("${velstra}/bin/velstra detach --datapath-state-dir /sys/fs/bpf/scope-pins")
    machine.succeed("test -z \"$(ls -A /sys/fs/bpf/scope-pins)\"")
    print("ACTUAL_AGENT_SCOPE_LIFECYCLE_PASS",flush=True)
  '';
}
