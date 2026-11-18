# Real product reconciler, SSH/PAM and HTTPS sessions, including reboot. No
# direct shadow/group repair or test-only authentication implementation.
{ pkgs, self }:
let
  askpass = pkgs.writeShellScript "fixture-ssh-password" ''
    printf '%s\n' 'lifecycle-test-password'
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-login-lifecycle-and-totp-replay";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
      virtualisation.memorySize = 2048;
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = lib.mkForce false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.1"; prefixLength = 24; }];
      services.velstra.interface = lib.mkForce "eth1";
      # Match real images: a deleted account must not be an autologin target.
      # The module's convenience VM admin autologin would correctly fail PAM
      # after retirement and churn getty instead of offering a login prompt.
      services.getty.autologinUser = lib.mkForce null;
      environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.procps ];
    };
    client = { ... }: {
      virtualisation.vlans = [ 1 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.2"; prefixLength = 24; }];
      };
      environment.systemPackages = [ pkgs.openssh pkgs.util-linux ];
    };
  };
  testScript = ''
    import base64
    import hashlib
    import hmac
    import json
    import os
    from pathlib import Path
    import shlex
    import struct

    start_all()
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    client.wait_for_unit("multi-user.target")

    def configure(commands, user=None, succeeds=True):
        script = "printf '%s\\n' " + " ".join(shlex.quote(command) for command in commands + ["commit", "save", "exit"])
        command = script + " | sentinel configure"
        if user:
            command = "su " + shlex.quote(user) + " -c " + shlex.quote(command)
        command += " 2>&1"
        return fw.succeed(command) if succeeds else fw.fail(command)

    def request(method, path, body=None, token=None):
        command = "curl -ksS --connect-timeout 3 --max-time 20 -o /tmp/lifecycle-reply -w '%{http_code}' -X " + method
        if token:
            command += " -H " + shlex.quote("Authorization: Bearer " + token)
        if body is not None:
            command += " -H 'Content-Type: application/json' --data " + shlex.quote(json.dumps(body))
        status = fw.succeed(command + " https://127.0.0.1:8080" + path).strip()
        return int(status), fw.succeed("cat /tmp/lifecycle-reply")

    def login(user, password="lifecycle-test-password", code=None):
        body = {"username": user, "password": password}
        if code is not None:
            body["code"] = code
        status, text = request("POST", "/api/v1/login", body)
        return status, json.loads(text)

    def ready():
        fw.wait_for_unit("sentinel-api.service")
        fw.wait_until_succeeds("curl -ksSf --connect-timeout 2 --max-time 3 https://127.0.0.1:8080/api/v1/health", timeout=40)

    def ssh(user, command="id -un", password=False):
        # The Nix driver owns stdin; SSH must not consume its protocol markers.
        options = "ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 "
        if password:
            options = "setsid -w env DISPLAY=fixture SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=${askpass} " + options + "-o PubkeyAuthentication=no -o PreferredAuthentications=password "
        else:
            options += "-o BatchMode=yes -i /root/.ssh/id_ed25519 "
        return options + shlex.quote(user + "@10.1.0.1") + " " + shlex.quote(command)

    def groups(user):
        return set(fw.succeed("id -nG " + shlex.quote(user)).split())

    def registry():
        return json.loads(fw.succeed("cat /var/lib/sentinel/login-accounts.json"))

    def retired(user, expected_uid):
        assert int(fw.succeed("id -u " + user)) == expected_uid
        assert "wheel" not in groups(user)
        shadow = fw.succeed("getent shadow " + user).strip().split(":")
        assert shadow[1].startswith("!") and shadow[7] == "1", shadow[0]
        fw.fail("test -e /run/sentinel-ssh/authorized_keys." + user)
        assert registry()["accounts"][user]["active"] is False

    public = client.succeed("mkdir -p /root/.ssh && ssh-keygen -q -t ed25519 -N ''' -f /root/.ssh/id_ed25519 && cat /root/.ssh/id_ed25519.pub").strip()
    # Deliberately unrelated pre-registry identity: preserve its credentials,
    # membership and home rather than guessing ownership from /etc/passwd.
    fw.succeed("useradd -m -u 1200 -G wheel outsider && printf retained > /home/outsider/proof")
    outsider = fw.succeed("getent passwd outsider; getent shadow outsider; id -nG outsider")
    configure([
        "set interface eth1 zone lan",
        "set firewall global default-action accept",
        "set system group operators permission read-write",
        "set system group viewers permission read-only",
        "set services ssh password-authentication true",
        "set services web enable true",
        "set system login admin password lifecycle-test-password",
        "set system login ops group operators",
        "set system login ops password lifecycle-test-password",
        "set system login ops ssh-key " + public,
    ])
    ready()
    fw.wait_for_unit("sshd.service")
    with subtest("configured ungrouped bootstrap admin has matching CLI and API authority"):
        status, signed = login("admin")
        assert status == 200 and signed["permission"] == "read-write", signed
        assert request("GET", "/api/v1/config", token=signed["token"])[0] == 200
    ops_uid = int(fw.succeed("id -u ops"))
    admin_uid = int(fw.succeed("id -u admin"))
    client.wait_until_succeeds(ssh("ops"), timeout=30)
    assert client.succeed(ssh("ops", password=True)).strip() == "ops"
    assert "wheel" in groups("ops")
    assert "outsider" not in registry()["accounts"]
    fw.succeed("printf retained > /home/ops/proof")

    with subtest("self-removal fails before any runtime or persisted mutation"):
        before = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
        refusal = configure(["delete system login ops"], user="ops", succeeds=False)
        assert "account running this commit" in refusal, refusal
        assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml") == before
        client.succeed(ssh("ops", "sudo -n true"))

    with subtest("removal revokes password, keys, wheel, API and existing privileged SSH session"):
        status, signed = login("ops")
        assert status == 200, signed
        token = signed["token"]
        assert request("GET", "/api/v1/config", token=token)[0] == 200
        privileged = "sudo -n sh -c 'echo $$ > /var/lib/sentinel/lifecycle-privileged-pid; exec sleep 300'"
        client.succeed(ssh("ops", privileged) + " >/tmp/held-ssh 2>&1 &")
        fw.wait_until_succeeds("test -s /var/lib/sentinel/lifecycle-privileged-pid", timeout=10)
        pid = int(fw.succeed("cat /var/lib/sentinel/lifecycle-privileged-pid"))
        fw.succeed("kill -0 " + str(pid))
        configure(["delete system login ops"])
        retired("ops", ops_uid)
        fw.wait_until_fails("kill -0 " + str(pid), timeout=10)
        client.fail(ssh("ops"))
        client.fail(ssh("ops", password=True))
        assert login("ops")[0] == 401
        assert request("GET", "/api/v1/config", token=token)[0] == 401
        assert fw.succeed("cat /home/ops/proof").strip() == "retained"

    with subtest("reboot re-enforces tombstones and preserves unrelated identities"):
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-boot.service")
        ready()
        retired("ops", ops_uid)
        client.fail(ssh("ops"))
        assert fw.succeed("getent passwd outsider; getent shadow outsider; id -nG outsider") == outsider
        assert fw.succeed("cat /home/outsider/proof").strip() == "retained"

    with subtest("re-adding a key-only viewer does not revive the old password or sudo grant"):
        configure(["set system login ops group viewers", "set system login ops ssh-key " + public])
        assert int(fw.succeed("id -u ops")) == ops_uid
        assert client.succeed(ssh("ops")).strip() == "ops"
        client.fail(ssh("ops", password=True))
        client.fail(ssh("ops", "sudo -n true"))
        assert "wheel" not in groups("ops")
        assert fw.succeed("cat /home/ops/proof").strip() == "retained"

    with subtest("a live demotion ends old grants and rejects ownership-registry corruption"):
        configure(["set system login ops group operators", "set system login ops password lifecycle-test-password"])
        status, signed = login("ops")
        assert status == 200
        old = signed["token"]
        configure(["set system login ops group viewers"])
        assert request("GET", "/api/v1/config", token=old)[0] == 401
        client.fail(ssh("ops", "sudo -n true"))
        status, signed = login("ops")
        assert status == 200 and signed["permission"] == "read-only"
        fw.succeed("cp -p /var/lib/sentinel/login-accounts.json /tmp/owned-registry && printf '{' > /var/lib/sentinel/login-accounts.json")
        refusal = configure(["set system hostname must-not-apply"], succeeds=False)
        assert "managed-login registry" in refusal, refusal
        fw.succeed("cp -p /tmp/owned-registry /var/lib/sentinel/login-accounts.json")

    with subtest("removing configured bootstrap admin cannot regain wheel on reboot"):
        configure(["delete system login admin"])
        retired("admin", admin_uid)
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-boot.service")
        ready()
        retired("admin", admin_uid)
        assert login("admin")[0] == 401

    with subtest("TOTP is consumed before session issuance and survives API restart and real reboot"):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        configure(["set system login otp group viewers", "set system login otp password lifecycle-test-password", "set system login otp totp " + secret])
        # An explicit controlled guest clock keeps the independently generated
        # code valid after reboot; rejection must be replay protection, not age.
        # Stop, do not disable immutable NixOS units via timedatectl. Repeat
        # after reboot so the same independently generated counter is valid.
        fw.succeed("systemctl stop chronyd.service && date -s @1700000010")
        counter = 1700000010 // 30
        digest = hmac.new(base64.b32decode(secret), struct.pack('!Q', counter), hashlib.sha1).digest()
        offset = digest[-1] & 15
        code = str((struct.unpack('!I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
        assert login("otp", code=code)[0] == 200
        assert login("otp", code=code)[0] == 401
        fw.succeed("systemctl restart sentinel-api.service")
        ready()
        assert login("otp", code=code)[0] == 401
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-boot.service")
        fw.succeed("systemctl stop chronyd.service && date -s @1700000010")
        ready()
        assert login("otp", code=code)[0] == 401
        # A fresh counter must still work: replay refusal alone could otherwise
        # hide a universally broken or unreadable replay store after reboot.
        fw.succeed("date -s @1700000040")
        next_digest = hmac.new(base64.b32decode(secret), struct.pack('!Q', 1700000040 // 30), hashlib.sha1).digest()
        next_offset = next_digest[-1] & 15
        next_code = str((struct.unpack('!I', next_digest[next_offset:next_offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
        assert next_code != code
        assert login("otp", code=next_code)[0] == 200
        # The old counter is still in the normal one-step clock-skew window,
        # but must remain consumed even after the newer code was accepted.
        assert login("otp", code=code)[0] == 401
        assert int(fw.succeed("find /var/lib/sentinel/totp-replay -name '*.json' | wc -l")) == 1

    fw.wait_for_unit("getty@tty1.service")
    fw.fail("systemctl --failed --no-legend | grep .")
    assert fw.succeed("getent passwd outsider; getent shadow outsider; id -nG outsider") == outsider
    with Path(os.environ["out"], "login-lifecycle.json").open("w") as output:
        json.dump({"ssh_password_and_key_revocation": True, "api_session_revocation": True,
                   "live_privileged_session_terminated": True, "homes_and_unrelated_accounts_preserved": True,
                   "retired_bootstrap_not_resurrected": True, "totp_replay_refused_after_reboot": True}, output, indent=2)
  '';
}
