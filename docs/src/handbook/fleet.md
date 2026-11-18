# Optional fleet enrollment

Fleet management is optional. With no `[fleet]` configuration, the polling
timer is stopped and the appliance operates locally. The node makes outbound
HTTPS requests; fleet does not add an inbound listener.

## Prepare trust

Obtain these from the controller/PKI, not from the appliance's development keys:

- The controller CA certificate.
- A unique client certificate and private key for this node.
- A private enrollment-token file.
- The independent Ed25519 **public** command-signing key, encoded as base64.

Store files under `/var/lib/sentinel/fleet/`, root-owned with directory mode
0700 and private-key/token mode 0600. A `file:` enrollment token must directly
name a regular file in that directory; symlinks and unrelated root files are
not valid secret sources.

## Enroll

Use **System → Fleet enrollment** in the console, or the `fleet` configuration
tree in `sentinel configure`. The complete TOML fields are:

| Field | Example / requirement |
| --- | --- |
| `controller-url` | `https://fleet.example.com`; HTTPS, without URL credentials or query/fragment. |
| `node-id` | A controller-enrolled unique identifier such as `edge-a`. |
| `enrollment-token` | `file:/var/lib/sentinel/fleet/enrollment-token`. |
| `ca-certificate` | `/var/lib/sentinel/fleet/controller-ca.pem`. |
| `client-certificate` | `/var/lib/sentinel/fleet/client.pem`. |
| `client-key` | `/var/lib/sentinel/fleet/client.key`. |
| `signing-key` | The controller's base64 Ed25519 public command key; required. |
| `poll-interval` | 1–300 seconds, default 5. |
| `flow-telemetry` | Optional per-flow detail; review its privacy impact before enabling. |

The controller must validate both mTLS identity and enrollment credential.
Transport authentication is not a substitute for signed commands. Proxies,
redirects and ambient curl configuration are not supported.

## Verify

```sh
sentinel fleet-poll
systemctl status sentinel-fleet.timer --no-pager
journalctl -u sentinel-fleet.service
```

A successful check-in does not confirm a provisional configuration change.
The controller must confirm the exact revision before its deadline or request
recovery. Validate this with an isolated controller before granting it access
to real appliances.

Replay protection survives reboots in a private per-configuration state file.
Do not delete that record to resolve an error: corrupt state fails closed, and
removing it can erase the command high-water mark. An unavailable controller
must not prevent local boot, configuration or forwarding.

```sh
nix build .#checks.x86_64-linux.fleet -L
```

This check is selected development coverage, not a complete controller
interoperability or final-image certificate. The older controller protocol
notes remain in the [historical documentation index](https://github.com/Velstra/sentinel/blob/main/docs/README.md).
