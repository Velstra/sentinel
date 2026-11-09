# Product health must be a hard, ordered dependency of boot-complete; merely
# installing the generic systemd check does not enable it.
{ config, lib, pkgs, options, ... }:
let
  checker = "${pkgs.python3}/bin/python3 -I ${./boot-health.py}";
in {
  # The image factory already includes this optional upstream unit. Duplicate
  # entries pass evaluation but fail system-units' symlink construction.
  # Ordinary direct-boot test appliances do not import that factory.
  systemd.additionalUpstreamSystemUnits = lib.optionals (!(options ? velstra.appliance.stateDir)) [
    "systemd-boot-check-no-failures.service"
  ];
  # The factory config deliberately has no zoned NIC. Do not invent eth0 and
  # turn an unprovisioned appliance into a failed-service/reboot loop.
  systemd.services.velstra.serviceConfig.ExecCondition = lib.mkDefault
    "${checker} dataplane-enabled";
  systemd.services.velstra-boot-verify = {
    description = "Verify the appliance before blessing the current UKI";
    requiredBy = [ "boot-complete.target" ];
    before = [ "boot-complete.target" "systemd-bless-boot.service" ];
    after = [ "multi-user.target" "sentinel-boot-late.service" ];
    unitConfig = {
      RequiresMountsFor = "/var/lib/sentinel";
      OnFailure = lib.mkDefault "sentinel-bad-boot.service";
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      TimeoutStartSec = "90s";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    # The private enterprise adapter may provide its own product-specific check.
    # Keep the public image fail-closed without conflicting with that adapter.
    script = lib.mkDefault ''
      exec ${checker} verify --sentinel ${config.services.velstra.sentinel}/bin/sentinel \
        --systemctl ${pkgs.systemd}/bin/systemctl --ip ${pkgs.iproute2}/bin/ip
    '';
  };
  systemd.services.systemd-boot-check-no-failures = {
    overrideStrategy = "asDropin";
    requiredBy = [ "boot-complete.target" ];
    after = [ "velstra-boot-verify.service" ];
    unitConfig.OnFailure = lib.mkDefault "sentinel-bad-boot.service";
  };
  systemd.services.sentinel-bad-boot = {
    description = "Retry an unblessed Sentinel UKI for bounded boot-count fallback";
    serviceConfig = { Type = "oneshot"; };
    script = ''
      if ${checker} trial; then
        ${pkgs.systemd}/bin/systemctl --no-block reboot
      fi
    '';
  };
}
