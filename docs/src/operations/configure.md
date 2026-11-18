# Apply a change remotely

<a id="configuring-the-appliance"></a>

Complete the first configuration from a local console. For remote edits, start with a saved, known-good configuration and keep a second management session available.

<a id="a-session"></a>

## Preview and apply for two minutes

```sh
sentinel configure
```

In the configuration prompt:

```text
set system hostname branch-a
compare
commit-confirm 2
```

Inspect the diff before applying. If the change prevents a new SSH or HTTPS session, let the timer expire. The CLI returns to the saved configuration.

## Confirm and persist

Reconnect over the path you intend to keep. If it works, enter the following in the configuration session before expiry:

```text
confirm
save
exit
```

For a normal CLI commit-confirm transaction, confirmation cancels the timer and saving persists the configuration. A plain `commit` alone is temporary.

<a id="off-box-editing"></a>

## Validate a file before use

```sh
sentinel config check /var/lib/sentinel/appliance.toml
```

For a separate candidate file, substitute its path. Validation checks the structure; verify reachability and service behavior on the running appliance.

<a id="the-rest-api"></a><a id="the-web-console"></a><a id="staged-then-applied"></a><a id="finding-things"></a><a id="one-object-language"></a><a id="everything-is-a-control"></a><a id="outcomes-not-transcripts"></a><a id="operations-are-not-configuration"></a><a id="packet-capture"></a><a id="debugging"></a><a id="what-it-does-not-do"></a>

## Use the web console

Review the proposed configuration diff, apply it and reconnect. Choose **Keep change** before the displayed deadline. The web transaction has its own confirmation window and worker. Avoid issuing a second change while the first is pending.

## Recover access

Keep a local or serial console, or an independent unzoned management link. Zoned data links wait for the dataplane to attach. Use [interface recovery](../handbook/interfaces.md#zoned-links-stay-down-until-the-firewall-has-them) if an expected port stays down. Use [CLI history](../handbook/cli.md) for inspecting a saved revision.

<a id="one-grammar-no-modes"></a><a id="contexts-edit"></a><a id="the-config-tree"></a><a id="zones-interfaces--vlans"></a><a id="ipv6-addressing--router-advertisements"></a><a id="bridges-bonds--vlan-aware-switching"></a><a id="macvlan--qinq"></a><a id="wireguard"></a><a id="openconnect-road-warrior-vpn"></a><a id="firewall-posture--global-defaults--per-zone-overrides"></a><a id="firewall-rules--zone-to-zone--ports"></a><a id="nat--its-own-top-level-node"></a><a id="nat-source--masquerade"></a><a id="nat-destination--port-forward"></a><a id="hairpin-nat-nat-reflection"></a><a id="load-balancer-load-balancer--the-l4-path"></a><a id="reverse-proxy-services-reverse-proxy--the-l7-path"></a><a id="routing-policy-policy"></a><a id="completion-the-vtysh-feel"></a><a id="operational-show-outside-configure"></a><a id="discovered-interfaces"></a>

## Find the configuration syntax

[Interfaces](../handbook/interfaces.md) · [Firewall and NAT](../handbook/firewall.md) · [Routing](../handbook/routing.md) · [VPN](../handbook/vpn.md) · [Services](../handbook/services.md) · [Worked examples](../handbook/examples.md).
