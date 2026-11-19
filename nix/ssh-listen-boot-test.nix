# `services ssh listen-address` naming an address the box only holds once its
# DHCP lease arrives. Committed at runtime the address is already there; at boot
# sshd starts before the lease. The authority answers every DISCOVER late on
# purpose, so the cold boot always starts sshd without its address.
#
# The product's own CLI writes the saved config, the shipped sshd unit is the one
# that boots, and the address is never assigned by hand.
{ pkgs, self }:
let
  leased = "10.78.0.11";
  absent = "10.78.0.99";
  checker = "${pkgs.python3}/bin/python3 -I ${./boot-health.py}";
  token = "b4c4c677e22a74fec54fff894e7d47e86a4a4e9539dff596e275ea1a036417ff";
in
pkgs.testers.runNixOSTest {
  name = "sentinel-ssh-listen-address-before-dhcp-lease";
  globalTimeout = 900;
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ./boot-health.nix ];
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 2048;
      networking.firewall.enable = lib.mkForce false;
      networking.useDHCP = false;
      services.velstra.interface = lib.mkForce "eth1";
      # No listen-address yet: the CLI sets and saves it below, as an operator would.
      services.velstra.appliance = lib.mkForce (pkgs.writeText "ssh-listen-boot.toml" ''
        [system]
        hostname = "ssh-listen-boot"
        [system.config-sync]
        secret = "${token}"
        [[interface]]
        name = "eth1"
        zone = "mgmt"
        address = "dhcp"
        [firewall]
        default_action = "drop"
        [[rule]]
        name = "mgmt-ssh"
        from = "mgmt"
        proto = "tcp"
        port = 22
        action = "accept"
        [services.ssh]
        enable = true
      '');
    };
    authority = {
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "10.78.0.1"; prefixLength = 24; } ];
      # One address in the pool, so the lease is the same on every boot, and an
      # OFFER held back long enough that sshd has always started by then.
      systemd.services.qa-slow-dhcp = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pkgs.dnsmasq}/bin/dnsmasq --no-daemon --user=root --port=0 --interface=eth1 --bind-dynamic --dhcp-range=${leased},${leased},255.255.255.0,120s --dhcp-authoritative --dhcp-reply-delay=6 --dhcp-leasefile=/run/qa-slow-dhcp.leases --log-dhcp --log-facility=-";
        };
      };
    };
  };
  testScript = ''
    import json, os, re, shlex
    from pathlib import Path

    LEASED = "${leased}"
    ABSENT = "${absent}"
    KEYSCAN = "${pkgs.openssh}/bin/ssh-keyscan -T 3 -t ed25519 "
    # The fix retries on this cadence; three periods is the allowance after the lease.
    SETTLE = 20
    VERIFY = "${checker} verify --sentinel ${self.packages.x86_64-linux.sentinel}/bin/sentinel --systemctl ${pkgs.systemd}/bin/systemctl --ip ${pkgs.iproute2}/bin/ip --timeout 1"

    def health():
        return json.loads(fw.succeed("${pkgs.curl}/bin/curl --noproxy '*' -fsSk --max-time 10 "
            "-H 'Authorization: Bearer ${token}' https://127.0.0.1:8080/api/v1/system/health"))

    def configure(lines):
        commands = lines + ["commit", "save", "exit"]
        script = "printf '%s\\n' " + " ".join(shlex.quote(line) for line in commands)
        output = fw.succeed(script + " | sentinel configure 2>&1")
        assert "error:" not in output.lower(), output
        return output

    def show(*properties):
        text = fw.succeed("systemctl show sshd.service -p " + ",".join(properties))
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

    def listeners():
        # Every TCP socket listening on the SSH port, whatever address it is bound to.
        return sorted(line.split()[3] for line in
                      fw.succeed("ss -H -ltn 'sport = :22'").splitlines() if line.strip())

    def offered(node, target):
        status, scan = node.execute(KEYSCAN + target + " 2>/dev/null")
        return {fields[2] for line in scan.splitlines()
                if len(fields := line.split()) == 3 and fields[1] == "ssh-ed25519"}

    def host_key():
        return fw.succeed("cut -d' ' -f2 /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").strip()

    def monotonic(pattern, units):
        # Seconds since boot of the first journal line matching, or None.
        text = fw.succeed("journalctl -b -o short-monotonic --no-pager " + units)
        for line in text.splitlines():
            if re.search(pattern, line) and (stamp := re.match(r"\[\s*([0-9.]+)\]", line)):
                return float(stamp.group(1))
        return None

    def wait_lease():
        fw.wait_until_succeeds("ip -o -4 address show dev eth1 | grep -q '" + LEASED + "/'", timeout=120)

    def diagnostics():
        print(fw.execute("systemctl status sshd.service --no-pager -l; "
            "systemctl --failed --plain --no-legend; ip -br address; ss -H -ltn; "
            "cat /run/sentinel-ssh/10-sentinel.conf; "
            "journalctl -b -o short-monotonic --no-pager -u sshd.service -u sentinel-boot.service "
            "-u systemd-boot-check-no-failures.service -u velstra-boot-verify.service; "
            "journalctl -b -o short-monotonic --no-pager -u systemd-networkd.service | grep -i dhcp")[1])
        print(authority.execute("journalctl -u qa-slow-dhcp --no-pager -n 20")[1])

    authority.start()
    authority.wait_for_unit("qa-slow-dhcp.service")
    fw.start()
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    fw.wait_for_unit("sentinel-api.service")
    wait_lease()

    with subtest("control: set at runtime, with the address present, sshd binds exactly that address"):
        fw.wait_for_unit("sshd.service")
        output = configure(["set services ssh listen-address " + LEASED])
        assert "error:" not in output.lower(), output
        fw.wait_until_succeeds("systemctl is-active --quiet sshd.service", timeout=SETTLE)
        fw.succeed("grep -qx 'ListenAddress " + LEASED + "' /run/sentinel-ssh/10-sentinel.conf")
        fw.succeed("grep -q 'listen-address = \"" + LEASED + "\"' /var/lib/sentinel/appliance.toml")
        assert listeners() == [LEASED + ":22"], listeners()
        assert offered(authority, LEASED) == {host_key()}

    original_host_key = host_key()
    observed: dict = {}
    try:
        with subtest("cold boot: the saved listen-address is served once the late lease arrives"):
            fw.shutdown()
            fw.start()
            fw.wait_for_unit("multi-user.target")
            wait_lease()
            # Poll rather than wait_for_unit: collect every fact before judging any.
            fw.execute("for i in $(seq " + str(SETTLE) + "); do systemctl is-active --quiet sshd.service && break; sleep 1; done")
            boot_done = int(fw.succeed(
                "systemctl show sentinel-boot.service -p ExecMainExitTimestampMonotonic --value").strip()) / 1e6
            lease_at = monotonic(r"DHCPv4 address " + re.escape(LEASED) + "/", "-u systemd-networkd.service")
            active_at = int(show("ActiveEnterTimestampMonotonic")["ActiveEnterTimestampMonotonic"]) / 1e6
            observed = {
                "sentinel_boot_finished_s": boot_done,
                "first_bind_refusal_s": monotonic(r"Cannot assign requested address", "-u sshd.service"),
                "lease_acquired_s": lease_at,
                "sshd_active_since_s": active_at or None,
                "sshd": show("ActiveState", "SubState", "Result", "NRestarts"),
                "listeners": listeners(),
                "offered_to_peer": sorted(offered(authority, LEASED)),
                "failed_units_before_boot_complete": fw.succeed("systemctl --failed --plain --no-legend").split("\n"),
                "boot_complete_exit": fw.execute("systemctl start boot-complete.target")[0],
                "failed_units": [line.split()[0] for line in
                    fw.succeed("systemctl --failed --plain --no-legend").splitlines() if line.strip()],
            }
            print("cold boot observation: " + json.dumps(observed, indent=2))
            # The fixture has to have produced the situation, or a pass proves nothing.
            assert lease_at is not None and lease_at - boot_done >= 3, observed
            assert observed["first_bind_refusal_s"] is not None, observed
            assert observed["first_bind_refusal_s"] < lease_at, observed
            assert observed["sshd"]["ActiveState"] == "active", observed
            assert observed["listeners"] == [LEASED + ":22"], observed
            assert observed["offered_to_peer"] == [original_host_key], observed
            assert host_key() == original_host_key, observed
            assert observed["failed_units"] == [], observed
            # What an unblessed first boot runs before systemd-bless-boot.
            assert observed["boot_complete_exit"] == 0, observed
            fw.succeed("systemctl is-active --quiet systemd-boot-check-no-failures.service boot-complete.target")
            observed["healthy_ssh"] = health()["ssh"]
            assert observed["healthy_ssh"]["status"] == "ok", observed

        with subtest("an address the box never holds: not served, not widened, not reported active"):
            refused = configure(["set services ssh listen-address " + ABSENT])
            # The commit that asked for it says the daemon did not come up.
            assert any(line.startswith("warning:") and "sshd.service" in line
                       for line in refused.splitlines()), refused
            fw.succeed("grep -qx 'ListenAddress " + ABSENT + "' /run/sentinel-ssh/10-sentinel.conf")
            fw.sleep(12)
            first = show("ActiveState", "SubState", "Result", "NRestarts")
            fw.sleep(12)
            second = show("ActiveState", "SubState", "Result", "NRestarts")
            observed["absent_address"] = {
                "commit_output": refused.splitlines(),
                "first": first, "second": second, "listeners": listeners(),
                "is_active": fw.execute("systemctl is-active sshd.service")[1].strip(),
                "failed_units": fw.succeed("systemctl --failed --plain --no-legend").splitlines(),
            }
            print("absent address observation: " + json.dumps(observed["absent_address"], indent=2))
            assert first["ActiveState"] != "active" and second["ActiveState"] != "active", observed
            assert listeners() == [], listeners()
            assert offered(authority, LEASED) == set()
            assert offered(fw, "127.0.0.1") == set()
            # Still trying, so the address appearing later is picked up.
            assert int(second["NRestarts"]) > int(first["NRestarts"]), observed
            # Retry is not a failed unit: independent readiness must catch it.
            assert observed["absent_address"]["failed_units"] == [], observed
            status = health()
            observed["absent_address"]["ssh_health"] = status["ssh"]
            assert status["ssh"]["status"] == "warning", status
            assert any(issue["code"] == "ssh-service-inactive" for issue in status["issues"]), status
            failure = fw.fail(VERIFY + " 2>&1")
            assert "sshd.service: not active" in failure, failure
            # Exercise the real boot dependency graph, not just the standalone check.
            fw.succeed("systemctl stop boot-complete.target velstra-boot-verify.service systemd-boot-check-no-failures.service")
            boot_exit, boot_output = fw.execute("systemctl start boot-complete.target 2>&1")
            observed["absent_address"]["boot_complete_exit"] = boot_exit
            assert boot_exit != 0, boot_output
            fw.fail("systemctl is-active --quiet boot-complete.target")
            fw.fail("${checker} trial")
            assert fw.succeed("systemctl show systemd-bless-boot.service -p ExecMainStartTimestampMonotonic --value").strip() in ("", "0")
            fw.succeed("journalctl -b --no-pager -u sshd.service | grep -q '" + ABSENT + ".*Cannot assign requested address'")
            configure(["set services ssh listen-address " + LEASED])
            fw.wait_until_succeeds("systemctl is-active --quiet sshd.service", timeout=SETTLE)
            assert listeners() == [LEASED + ":22"], listeners()
            assert offered(authority, LEASED) == {host_key()}
            fw.succeed(VERIFY)
            # Clear only the deliberately failed gate after proving readiness;
            # never hide the original missing-address signal with reset-failed.
            fw.succeed("systemctl reset-failed velstra-boot-verify.service")
            fw.succeed("systemctl start boot-complete.target")
            fw.succeed("systemctl is-active --quiet boot-complete.target")

        with subtest("a disabled daemon is skipped once, not retried"):
            configure(["set services ssh enable false"])
            fw.succeed("systemctl start sshd.service")
            first = show("ActiveState", "Result", "NRestarts")
            fw.sleep(12)
            second = show("ActiveState", "Result", "NRestarts")
            observed["disabled"] = {"first": first, "second": second}
            assert second["ActiveState"] == "inactive" and second["NRestarts"] == first["NRestarts"], observed
            fw.fail("systemctl is-failed --quiet sshd.service")
            assert listeners() == [], listeners()
            status = health()
            observed["disabled"]["ssh_health"] = status["ssh"]
            assert observed["disabled"]["ssh_health"]["status"] == "disabled", observed
            assert not any(issue["code"].startswith("ssh-service-") for issue in status["issues"]), status
            fw.succeed(VERIFY)
            configure(["set services ssh enable true"])
            fw.wait_until_succeeds("systemctl is-active --quiet sshd.service", timeout=SETTLE)
            assert listeners() == [LEASED + ":22"], listeners()
    finally:
        Path(os.environ["out"], "ssh-listen-boot.json").write_text(json.dumps(observed, indent=2))
        diagnostics()
  '';
}
