# Independent implementation acceptance: the server is pinned FreeRADIUS, not
# the Python wire peer used by the unit tests. All credentials below are public
# disposable test fixtures, never generated or production signing identities.
{ pkgs, self }:
let
  radiusPackage = pkgs.freeradius;
  shared = "disposable-radius-interoperability-key-32-bytes";
  wrongShared = "disposable-deliberately-mismatched-radius-key";
  users = pkgs.writeText "radius-fixture-users" ''
    radiususer Cleartext-Password := "disposable-radius-password"
  '';
  serverConfig = pkgs.writeText "radius-fixture.conf" ''
    prefix = ${radiusPackage}
    libdir = ${radiusPackage}/lib
    name = radiusd
    logdir = /var/log/radius
    run_dir = /run/freeradius
    pidfile = /run/freeradius/radiusd.pid
    max_request_time = 5
    cleanup_delay = 1
    log {
      destination = stdout
      auth = no
      auth_badpass = no
      auth_goodpass = no
    }
    security {
      require_message_authenticator = yes
      reject_delay = 0
      allow_vulnerable_openssl = no
    }
    client sentinel {
      ipaddr = 10.1.0.1
      proto = udp
      secret = ${shared}
      require_message_authenticator = yes
    }
    modules {
      files {
        filename = ${users}
      }
      pap { }
    }
    server sentinel {
      listen {
        type = auth
        ipaddr = 10.1.0.2
        port = 1812
        proto = udp
      }
      authorize {
        files
        pap
      }
      authenticate {
        Auth-Type PAP {
          pap
        }
      }
    }
  '';
  configDir = pkgs.linkFarm "radius-fixture-config" [
    { name = "radiusd.conf"; path = serverConfig; }
    { name = "dictionary"; path = "${radiusPackage}/etc/raddb/dictionary"; }
  ];
  initial = pkgs.writeText "radius-initial.cli" ''
    set interface eth1 zone lan
    set firewall global default-action accept
    set services web enable true
    set system group directory-viewers permission read-only
    set system aaa default-group directory-viewers
    set system aaa radius 10.1.0.2 secret ${shared}
    set system aaa radius 10.1.0.2 timeout 2
    commit
    save
    exit
  '';
  changeSecret = value: pkgs.writeText "radius-credential-change.cli" ''
    set system aaa radius 10.1.0.2 secret ${value}
    commit
    save
    exit
  '';
  goodRequest = pkgs.writeText "radius-good-login.json" (builtins.toJSON {
    username = "radiususer"; password = "disposable-radius-password";
  });
  badRequest = pkgs.writeText "radius-rejected-login.json" (builtins.toJSON {
    username = "radiususer"; password = "disposable-incorrect-password";
  });
  # Do not put a password or bearer in the logged command line or stdout.
  apiProbe = pkgs.writeText "radius-api-probe.py" ''
    import http.client, json, os, ssl, sys
    mode, source = sys.argv[1:3]
    connection = http.client.HTTPSConnection("127.0.0.1", 8080, timeout=8,
        context=ssl._create_unverified_context())
    if mode == "login":
        with open(source) as request:
            body = json.load(request)
        connection.request("POST", "/api/v1/login", json.dumps(body),
            {"Content-Type": "application/json"})
    else:
        assert mode == "config"
        with open(source) as session:
            token = json.load(session)["token"]
        connection.request("GET", "/api/v1/config", headers={"Authorization": "Bearer " + token})
    response = connection.getresponse()
    payload = json.loads(response.read())
    if mode == "login":
        descriptor = os.open(sys.argv[3], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as session:
            json.dump(payload, session)
    print(json.dumps({"status": response.status, "has_token": "token" in payload,
        "permission": payload.get("permission")}))
  '';
  # A negative CLIENT only. It never answers Sentinel or replaces the server.
  noMessageAuthenticator = pkgs.writeText "radius-without-ma.py" ''
    import hashlib, json, os, socket, struct
    secret = b"${shared}"
    authenticator = os.urandom(16)
    password = b"disposable-radius-password"
    password += bytes((-len(password)) % 16)
    encrypted, previous = bytearray(), authenticator
    for offset in range(0, len(password), 16):
        digest = hashlib.md5(secret + previous).digest()
        previous = bytes(a ^ b for a, b in zip(password[offset:offset + 16], digest))
        encrypted += previous
    username = b"radiususer"
    attributes = bytes([1, len(username) + 2]) + username + bytes([2, len(encrypted) + 2]) + encrypted
    packet = struct.pack("!BBH", 1, 250, 20 + len(attributes)) + authenticator + attributes
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("10.1.0.1", 0))
    client.settimeout(1)
    client.sendto(packet, ("10.1.0.2", 1812))
    try:
        client.recvfrom(4096)
    except socket.timeout:
        print(json.dumps({"missing_ma_silently_discarded": True}))
    else:
        raise AssertionError("real FreeRADIUS answered an unauthenticated request")
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-freeradius-message-authenticator";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
      virtualisation.memorySize = 2048;
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = lib.mkForce false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.1"; prefixLength = 24; }];
      services.velstra.interface = lib.mkForce "eth1";
      services.getty.autologinUser = lib.mkForce null;
      environment.systemPackages = [ pkgs.curl pkgs.python3 ];
    };
    radius = { ... }: {
      virtualisation.vlans = [ 1 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.2"; prefixLength = 24; }];
      };
      services.freeradius = {
        enable = true;
        package = radiusPackage;
        inherit configDir;
        debug = false;
      };
      systemd.services.radius-wire-capture.serviceConfig = {
        ExecStart = "${pkgs.tcpdump}/bin/tcpdump -U -n -i eth1 -w /tmp/radius-wire.pcap udp port 1812";
        KillSignal = "SIGINT";
      };
    };
  };
  testScript = ''
    import base64, hashlib, hmac, json, os, socket, struct
    from pathlib import Path

    start_all()
    for machine in (fw, radius):
        machine.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    radius.wait_for_unit("freeradius.service")
    version = radius.succeed("${radiusPackage}/bin/radiusd -v 2>&1")
    assert "FreeRADIUS Version ${radiusPackage.version}" in version, version
    radius.succeed("systemctl start radius-wire-capture.service")
    radius.wait_until_succeeds("test -s /tmp/radius-wire.pcap", timeout=10)

    def configure(source):
        fw.succeed("sentinel configure < " + source + " 2>&1")
        fw.wait_for_unit("sentinel-api.service")
        fw.wait_until_succeeds("curl -ksSf --max-time 3 https://127.0.0.1:8080/api/v1/health", timeout=30)

    def login(source, session="/tmp/radius-last-session.json"):
        return json.loads(fw.succeed("${pkgs.python3}/bin/python3 ${apiProbe} login " + source + " " + session))

    def config(session):
        return json.loads(fw.succeed("${pkgs.python3}/bin/python3 ${apiProbe} config " + session))["status"]

    configure("${initial}")
    fw.succeed("ping -c1 -W2 10.1.0.2")
    fw.fail("getent passwd radiususer")

    with subtest("real FreeRADIUS PAP accept yields a usable least-privilege directory session"):
        accepted = login("${goodRequest}", "/tmp/radius-accepted-session.json")
        assert accepted == {"status": 200, "has_token": True, "permission": "read-only"}, accepted
        assert config("/tmp/radius-accepted-session.json") == 200

    with subtest("authenticated Access-Reject is a refusal rather than an upstream error"):
        rejected = login("${badRequest}")
        assert rejected["status"] == 401 and not rejected["has_token"], rejected

    with subtest("shared-secret mismatch fails closed and withdraws earlier directory grants"):
        configure("${changeSecret wrongShared}")
        assert config("/tmp/radius-accepted-session.json") == 401
        mismatch = login("${goodRequest}")
        # ask_the_directory deliberately distinguishes an unanswered/untrusted
        # upstream (503) from an authenticated Access-Reject (401).
        assert mismatch["status"] == 503 and not mismatch["has_token"], mismatch

    with subtest("restoring the matching credential recovers actual directory authentication"):
        configure("${changeSecret shared}")
        recovered = login("${goodRequest}", "/tmp/radius-recovered-session.json")
        assert recovered == {"status": 200, "has_token": True, "permission": "read-only"}, recovered
        assert config("/tmp/radius-recovered-session.json") == 200
        assert config("/tmp/radius-accepted-session.json") == 401

    with subtest("real server silently discards a valid PAP request without Message-Authenticator"):
        probe = json.loads(fw.succeed("${pkgs.python3}/bin/python3 ${noMessageAuthenticator}"))
        assert probe == {"missing_ma_silently_discarded": True}, probe

    radius.succeed("systemctl stop radius-wire-capture.service")
    # Inspect actual captured bytes, not server debug output or a fake peer.
    captured = base64.b64decode(radius.succeed("base64 -w0 /tmp/radius-wire.pcap"))
    assert 24 <= len(captured) <= 1024 * 1024
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(captured[:4])
    assert endian, "expected classic pcap"
    assert struct.unpack(endian + "I", captured[20:24])[0] == 1, "expected Ethernet capture"
    pending, counts = {}, {"request_good_ma": 0, "request_mismatched_ma": 0,
        "request_missing_ma": 0, "accept": 0, "reject": 0}
    secrets = [b"${shared}", b"${wrongShared}"]
    position = 24
    while position < len(captured):
        assert position + 16 <= len(captured)
        length = struct.unpack(endian + "I", captured[position + 8:position + 12])[0]
        position += 16
        frame = captured[position:position + length]
        assert len(frame) == length
        position += length
        assert len(frame) >= 42 and frame[12:14] == b"\x08\x00"
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        assert ip[0] >> 4 == 4 and header >= 20 and ip[9] == 17
        udp = ip[header:struct.unpack("!H", ip[2:4])[0]]
        source_port, target_port, udp_length = struct.unpack("!HHH", udp[:6])
        assert udp_length == len(udp)
        packet = udp[8:]
        assert len(packet) >= 20 and struct.unpack("!H", packet[2:4])[0] == len(packet)
        code, identifier = packet[:2]
        attributes, offset = {}, 20
        while offset < len(packet):
            assert offset + 2 <= len(packet)
            kind, size = packet[offset:offset + 2]
            assert kind != 0 and size >= 2 and offset + size <= len(packet)
            attributes.setdefault(kind, []).append((offset + 2, packet[offset + 2:offset + size]))
            offset += size
        if code == 1:
            assert target_port == 1812 and socket.inet_ntoa(ip[12:16]) == "10.1.0.1"
            assert attributes.get(1, [(0, None)])[0][1] == b"radiususer"
            if 80 not in attributes:
                assert identifier == 250
                counts["request_missing_ma"] += 1
                continue
            assert len(attributes[80]) == 1 and len(attributes[80][0][1]) == 16
            mac_offset, actual = attributes[80][0]
            unsigned = bytearray(packet)
            unsigned[mac_offset:mac_offset + 16] = bytes(16)
            matches = [hmac.compare_digest(hmac.new(secret, unsigned, hashlib.md5).digest(), actual) for secret in secrets]
            assert sum(matches) == 1, "request MAC must match exactly one fixture credential"
            index = matches.index(True)
            counts["request_good_ma" if index == 0 else "request_mismatched_ma"] += 1
            pending[(source_port, identifier)] = (packet[4:20], secrets[index], index)
        else:
            assert code in (2, 3) and source_port == 1812 and socket.inet_ntoa(ip[12:16]) == "10.1.0.2"
            request_authenticator, secret, index = pending.pop((target_port, identifier))
            assert index == 0, "a wrong-secret request must never get an authenticated answer"
            assert len(attributes.get(80, [])) == 1 and len(attributes[80][0][1]) == 16
            mac_offset, actual = attributes[80][0]
            expected_response = hashlib.md5(packet[:4] + request_authenticator + packet[20:] + secret).digest()
            assert hmac.compare_digest(expected_response, packet[4:20]), "invalid Response Authenticator"
            unsigned = bytearray(packet)
            unsigned[4:20] = request_authenticator
            unsigned[mac_offset:mac_offset + 16] = bytes(16)
            assert hmac.compare_digest(hmac.new(secret, unsigned, hashlib.md5).digest(), actual), "invalid response Message-Authenticator"
            counts["accept" if code == 2 else "reject"] += 1
    assert counts == {"request_good_ma": 3, "request_mismatched_ma": 1,
        "request_missing_ma": 1, "accept": 2, "reject": 1}, counts
    assert len(pending) == 1 and next(iter(pending.values()))[2] == 1
    radius.succeed("journalctl -u freeradius.service --no-pager | grep -q 'Message-Authenticator'")
    for machine in (fw, radius):
        machine.fail("systemctl --failed --no-legend | grep .")
    with Path(os.environ["out"], "radius-interoperability.json").open("w") as report:
        json.dump({"server": "FreeRADIUS", "version": "${radiusPackage.version}",
            "wire": counts, "verified_response_authenticators": True,
            "directory_session_revocation_and_recovery": True}, report, indent=2)
  '';
}
