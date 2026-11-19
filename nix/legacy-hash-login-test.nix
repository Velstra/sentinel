# IMG-02: an imported md5crypt ($1$), sha256crypt ($5$) or sha512crypt ($6$)
# hash must let its owner in through BOTH doors — SSH (PAM's pam_unix and the
# system libcrypt) and the management API (the pinned password helper). The
# live audit found the two disagreeing: $1$ passed SSH but not the API, $5$
# passed neither. The vectors are the password helper's own install-check
# vectors, all for the same password.
{ pkgs, self }:
let
  password = "fixture-known-password";
  askpass = pkgs.writeShellScript "fixture-ssh-password" ''
    printf '%s\n' '${password}'
  '';
  hashes = {
    md5user = "$1$salt1234$Wf.nqwASZ/FlosX3JiWwn1";
    sha256user = "$5$salt123456789012$46s4249.s4ZRpbNtgdkvjvoVha8c02t7F7e0Y7EhpK3";
    sha512user = "$6$salt123456789012$mrQIS8eBOuKvq23qeHhMYQGqzyaljxGgVQih9JxYJi7aMYM4TCNknwxRRFgrzIi20LVUXbUyY.j.yJDZCzyaC/";
  };
in
pkgs.testers.runNixOSTest {
  name = "sentinel-legacy-hash-login";
  nodes = {
    fw = { lib, ... }: {
      # The shipped image's backports, including the PAM-side libcrypt.
      imports = [ self.nixosModules.sentinel ./test-network-seed.nix ./security-backports.nix ];
      virtualisation.memorySize = 2048;
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = lib.mkForce false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.1"; prefixLength = 24; }];
      services.velstra.interface = lib.mkForce "eth1";
      environment.systemPackages = [ pkgs.curl ];
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
    import json
    import shlex

    hashes = json.loads(${builtins.toJSON (builtins.toJSON hashes)})
    start_all()
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    client.wait_for_unit("multi-user.target")

    lines = [
        "set interface eth1 zone lan",
        "set firewall global default-action accept",
        "set system group admins permission read-write",
        "set services ssh password-authentication true",
        "set services web enable true",
    ]
    for user, crypt in hashes.items():
        lines += [f"set system login {user} group admins",
                  f"set system login {user} hashed-password {crypt}"]
    script = "printf '%s\\n' " + " ".join(shlex.quote(line) for line in lines + ["commit", "save", "exit"])
    print(fw.succeed(script + " | sentinel configure 2>&1"))
    fw.wait_for_unit("sentinel-api.service")
    fw.wait_until_succeeds("curl -ksSf --max-time 3 https://127.0.0.1:8080/api/v1/health", timeout=40)
    fw.wait_for_unit("sshd.service")

    def api(user):
        body = json.dumps({"username": user, "password": "${password}"})
        return fw.succeed("curl -ksS --max-time 20 -o /dev/null -w '%{http_code}' -X POST "
                          "-H 'Content-Type: application/json' --data " + shlex.quote(body)
                          + " https://127.0.0.1:8080/api/v1/login").strip()

    def ssh(user):
        return client.execute(
            "setsid -w env DISPLAY=fixture SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=${askpass} "
            "ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "
            "-o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password "
            + shlex.quote(user + "@10.1.0.1") + " id -un 2>&1")

    client.wait_until_succeeds("ssh-keyscan -T 3 10.1.0.1 | grep -q ssh-", timeout=60)
    results = {}
    for user in hashes:
        status, out = ssh(user)
        results[user] = {"ssh": status == 0 and out.strip().endswith(user), "ssh_output": out.strip()[-300:],
                         "api": api(user)}
    print("LEGACY_HASH_RESULTS " + json.dumps(results, indent=2), flush=True)
    for user, result in results.items():
        assert result["ssh"], f"{user}: SSH password login refused: {result['ssh_output']}"
        assert result["api"] == "200", f"{user}: API login answered {result['api']}"
    # A wrong password stays wrong through both doors.
    body = json.dumps({"username": "md5user", "password": "wrong-password"})
    assert fw.succeed("curl -ksS --max-time 20 -o /dev/null -w '%{http_code}' -X POST "
                      "-H 'Content-Type: application/json' --data " + shlex.quote(body)
                      + " https://127.0.0.1:8080/api/v1/login").strip() == "401"
  '';
}
