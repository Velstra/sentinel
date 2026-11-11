"""Source-level radio regressions; effective unit/radio behavior needs the VM."""
from pathlib import Path
import re
import textwrap
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "flake.nix"


class RadioUnitsTests(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text()

    def template(self, kind):
        return self.source.split(f'systemd.services."sentinel-{kind}@" = {{', 1)[1].split("\n          };", 1)[0]

    def driver(self):
        wireless = self.source.split("      wireless = pkgs.testers.runNixOSTest {", 1)[1]
        return wireless.split("        testScript = ''\n", 1)[1].split("\n        '';", 1)[0]

    def test_all_three_templates_put_rate_policy_in_unit_not_service(self):
        for kind in ("hostapd", "supplicant", "wwan"):
            with self.subTest(kind=kind):
                unit = self.template(kind)
                self.assertEqual(unit.count("unitConfig.StartLimitIntervalSec = 0;"), 1)
                service = unit.split("serviceConfig = {", 1)[1].split("};", 1)[0]
                self.assertNotIn("StartLimitIntervalSec", service)
                self.assertIn('Restart = "on-failure";', service)
                self.assertIn('Type = "exec";', service)

    def test_existing_delays_conditions_and_daemons_are_unchanged(self):
        self.assertIn("RestartSec = 5;", self.template("hostapd"))
        self.assertIn("RestartSec = 5;", self.template("supplicant"))
        self.assertIn("RestartSec = 10;", self.template("wwan"))
        self.assertIn('unitConfig.ConditionPathExists = "/run/sentinel/wireless/%i.conf";', self.template("supplicant"))
        self.assertIn('unitConfig.ConditionPathExists = "/run/sentinel/wwan/%i.sh";', self.template("wwan"))
        for kind, command in (("hostapd", "${pkgs.hostapd}/bin/hostapd"),
                              ("supplicant", "${pkgs.wpa_supplicant}/bin/wpa_supplicant"),
                              ("wwan", "/bin/sh /run/sentinel/wwan/%i.sh")):
            self.assertIn(command, self.template(kind))

    def test_private_reference_paths_exist_before_daemon_and_client(self):
        driver = self.driver()
        creation = driver.index("umask 077; mkdir -m 700 -p /tmp/sta/control /tmp/sta/client")
        daemon = driver.index("ip netns exec sta wpa_supplicant -B")
        client = driver.index("ip netns exec sta wpa_cli -p /tmp/sta/control -s /tmp/sta/client -i wlan1 status")
        self.assertLess(creation, daemon)
        self.assertLess(daemon, client)
        self.assertIn("ctrl_interface=/tmp/sta/control", driver)
        self.assertNotIn("ctrl_interface=/run/wpa_supplicant", driver)
        self.assertEqual(driver.count("wpa_cli"), 2)  # One explanatory comment and one actual client.
        self.assertIn("&& grep -qx 'wpa_state=COMPLETED'", driver)

    def test_actual_property_and_original_traffic_removal_oracles_remain(self):
        driver = self.driver()
        for oracle in ('for kind in ("hostapd", "supplicant", "wwan"):',
                       "--property=StartLimitIntervalUSec --value", 'assert interval == "0"',
                       'assert mode == "600"', 'assert dirmode == "755"',
                       "type AP", "iw phy phy{phy} set netns name sta", "iw dev wlan0 station dump",
                       'assert "Station" in sta', "ip netns exec sta ping -c2 -W2 10.0.10.1",
                       "delete interface wlan0 wireless", "delete interface wlan0 type",
                       "systemctl is-active sentinel-hostapd@wlan0.service", "timeout=90"):
            self.assertIn(oracle, driver)
        self.assertNotIn("reset-failed", driver)
        self.assertNotIn("|| true", driver)

    def test_embedded_driver_remains_valid_python(self):
        # The current wireless driver has no Nix interpolation; ordinary Python
        # f-strings are retained rather than loosely substituted.
        driver = self.driver()
        self.assertIsNone(re.search(r"\$\{", driver))
        compile(textwrap.dedent(driver), "<wireless-vm-driver>", "exec")


if __name__ == "__main__":
    unittest.main()
