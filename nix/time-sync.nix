# One owner for the appliance clock. Sentinel renders its complete source list
# into the confdir at boot/commit: custom upstreams replace public defaults.
{ lib, ... }:
{
  services.timesyncd.enable = lib.mkForce false;
  services.chrony = {
    enable = true;
    # Avoid NixOS adding networking.timeServers/initstepslew alongside the
    # runtime source list. Both server and pool retry failed DNS resolution;
    # pool is used by Sentinel only for the rotating public default pools.
    servers = [ ];
    # The NixOS option only accepts positive limits. The appliance needs the
    # explicit unlimited late-network correction below, not two makestep lines.
    makestep.enable = false;
    extraConfig = ''
      # A laptop with an exhausted RTC battery can be years behind even when
      # its uplink arrives late. Permit a large correction once time is known.
      makestep 1.0 -1
      confdir /run/sentinel/chrony.d
    '';
  };
  systemd.services.chronyd = {
    # Never start with an empty source list before Sentinel renders the saved
    # config. No dependency on routability: chronyd retries unavailable sources.
    after = [ "sentinel-boot.service" ];
    wants = [ "sentinel-boot.service" ];
  };
  systemd.tmpfiles.rules = [ "d /run/sentinel/chrony.d 0755 root root -" ];
}
