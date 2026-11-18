# Each sudo rule is an exact immutable executable AND literal argument vector.
# The executable still checks sudo UID, managed ownership and the current grant.
# Never widen this to `show *`, an agent socket, a file path or a tool command.
{ sentinel }:
let
  core = sentinel.unwrapped or sentinel;
in {
  security.sudo.extraRules = [{
    users = [ "ALL" ];
    runAs = "root";
    commands = map (operation: {
      command = "${core}/bin/sentinel observe ${operation}";
      options = [ "NOPASSWD" "NOSETENV" ];
    }) [
      "configuration"
      "configuration-commands"
      "bgp-summary"
      "flows"
      "firewall-statistics"
      "firewall-capacity"
    ];
  }];
}
