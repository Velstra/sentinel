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

## Release status

This documentation describes Sentinel 1.0.0. Read the [release notes](release-notes-1.0.0.md) before upgrading. HA and extended routing features remain experimental; consult the [HA safety guide](handbook/ha.md), [routing qualification status](handbook/routing.md#qualification-status) and [dataplane support matrix](reference/dataplane-support.md). Source-build signing keys are demonstration identities. Source tests cannot replace acceptance and SBOM/CVE review of the final signed image.

The source license is AGPL-3.0. Do not infer additional contributor licensing rights from a proposed CLA or commercial roadmap; see [redistribution notices](building/notices.md).
