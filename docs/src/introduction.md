# Sentinel operator guide

<a id="velstra-sentinel"></a><a id="what-makes-it-an-appliance"></a><a id="where-to-start"></a><a id="license"></a>

Sentinel is a firewall and router for x86-64 UEFI systems. Fabric applies packet policy, Wren exchanges routes, and Sentinel turns one appliance configuration into both. Operators make live changes from the CLI or web console. System software arrives as a separate A/B image.

| What do you want to verify? | Start here | What to look for |
|---|---|---|
| Try the appliance on a workstation | [Start a VM](operations/quickstart.md) | Log in and inspect both interfaces. |
| Change a remote firewall safely | [Apply a change remotely](operations/configure.md) | An unconfirmed change returns to the saved configuration. |
| Find the rule that decides a packet | [Trace a packet](handbook/firewall.md#asking-before-you-send-packet-trace) | Follow NAT, the configured route and the matching rule before sending traffic. |
| Choose how an HA pair elects a primary | [Compare the two HA modes](operations/high-availability.md) | Verify the active member and how each mode handles a partition. |
| Review an image before rollout | [Stage an update](operations/update.md) | Verify the offer and distinguish a staged image from a successful boot. |

## First look on an appliance

```sh
sentinel show version
sentinel show interfaces
sentinel show ip route
```

Use the [configuration cookbook](handbook/cli.md) for the next change. The [test catalog](reference/tests.md) identifies which checks exercise the CLI, a development VM or a booted image. This manual tracks the repository’s main branch; match the source revision to your release when evaluating a build.
