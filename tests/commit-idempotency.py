# Appended to the real masquerade fixture: client, fw, server and PYTHON are
# supplied by that test. Hold one acknowledged TCP connection across a commit.
import shlex

server_source = """import socket,time
from pathlib import Path
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',18081))
s.listen()
print('READY',flush=True)
c,peer=s.accept()
assert peer[0]=='10.1.0.1',peer
c.settimeout(15)
f=c.makefile('rb')
for i in range(200):
    if i==5:
        print('QUIET',flush=True)
        deadline=time.monotonic()+15
        while not Path('/run/commit-stream-resume').exists():
            assert time.monotonic()<deadline,'commit did not release stream'
            time.sleep(0.02)
    data=(str(i)+'\\n').encode()
    c.sendall(data)
    assert f.readline()==b'ACK '+data
    time.sleep(0.04)
print('TCP_SERVED_200',flush=True)
"""

client_source = """import socket
from pathlib import Path
c=socket.create_connection(('10.1.0.2',18081),timeout=15)
c.settimeout(15)
f=c.makefile('rb')
for i in range(200):
    data=f.readline()
    assert data==(str(i)+'\\n').encode(),(i,data)
    c.sendall(b'ACK '+data)
    Path('/run/commit-stream-progress').write_text(str(i))
print('TCP_SURVIVED_200',flush=True)
"""

def start_stream(tag, port):
    prefix = "/run/" + tag + "-stream-"
    sources = [
        (server, "server", server_source),
        (client, "client", client_source),
    ]
    for node, role, source in sources:
        source = source.replace("/run/commit-stream-", prefix).replace("18081", str(port))
        node.succeed("printf %s " + shlex.quote(source) + " > " + prefix + role + ".py")
    server.succeed("systemd-run --unit=" + tag + "-stream-server " + PYTHON + " " + prefix + "server.py")
    server.wait_until_succeeds("journalctl -u " + tag + "-stream-server --no-pager -o cat | grep '^READY$'", timeout=10)
    client.succeed("systemd-run --unit=" + tag + "-stream-client " + PYTHON + " " + prefix + "client.py")
    server.wait_until_succeeds("journalctl -u " + tag + "-stream-server --no-pager -o cat | grep '^QUIET$'", timeout=15)
    fw.succeed("sentinel show flows | grep " + str(port))


def finish_stream(tag):
    server.succeed("touch /run/" + tag + "-stream-resume")
    for node, role in [(client, "client"), (server, "server")]:
        node.wait_until_succeeds("! systemctl is-active --quiet " + tag + "-stream-" + role + ".service", timeout=25)
    client_log = client.succeed("journalctl -u " + tag + "-stream-client --no-pager -o cat")
    server_log = server.succeed("journalctl -u " + tag + "-stream-server --no-pager -o cat")
    print(client_log)
    print(server_log)
    assert "TCP_SURVIVED_200" in client_log, client_log
    assert "TCP_SERVED_200" in server_log, server_log


with subtest("an established acknowledged TCP stream crosses masquerade"):
    start_stream("commit", 18081)

with subtest("an unchanged commit preserves connection state and both daemons"):
    agent_pid = fw.succeed("systemctl show -p MainPID --value velstra.service").strip()
    routing_pid = fw.succeed("systemctl show -p MainPID --value wren.service").strip()
    runtime_files = fw.succeed("stat -c '%i:%Y' /run/sentinel/velstra.toml /run/sentinel/wren.toml")
    fw.succeed("su admin -c \"printf '%s\\n' commit save exit | sentinel configure\"")
    finish_stream("commit")
    assert fw.succeed("systemctl show -p MainPID --value velstra.service").strip() == agent_pid
    assert fw.succeed("systemctl show -p MainPID --value wren.service").strip() == routing_pid
    assert fw.succeed("stat -c '%i:%Y' /run/sentinel/velstra.toml /run/sentinel/wren.toml") == runtime_files

with subtest("an existing NAT connection survives a real daemon crash without auto-restart"):
    fw.succeed("mkdir -p /run/systemd/system/velstra.service.d")
    fw.succeed("printf '[Service]\\nRestart=no\\n' > /run/systemd/system/velstra.service.d/crash-test.conf")
    fw.succeed("systemctl daemon-reload")
    try:
        start_stream("crash", 18082)
        fw.succeed("systemctl kill --signal=KILL --kill-whom=main velstra.service")
        fw.wait_until_fails("systemctl is-active --quiet velstra.service", timeout=10)
        fw.succeed("test -e /sys/fs/bpf/sentinel/apply-state")
        finish_stream("crash")
        assert fw.succeed("systemctl show -p MainPID --value velstra.service").strip() == "0"
    finally:
        fw.succeed("rm /run/systemd/system/velstra.service.d/crash-test.conf")
        fw.succeed("systemctl daemon-reload")
        fw.succeed("systemctl start velstra.service")
    fw.wait_until_succeeds("sentinel agent-query status | grep '^Ready$'", timeout=20)
    client.succeed("curl -fsS --max-time 5 http://10.1.0.2:80/ | grep hello-from-server")
