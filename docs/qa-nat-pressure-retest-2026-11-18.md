# Stateful NAT pressure: fresh-run result

**Release gate: failed.** A clean 16-vCPU, 32-GiB nested-KVM builder reproduced
loss of established firewall state. Increasing test-host resources did not fix
the product. This run does not qualify physical hardware or external networking.

The unchanged normal eBPF object was
`6bab5656e2419e6d54d5a02b8b406851ebe52852d0c9dbb741e744b55236fd6e`;
the guest kernel was 6.12.113. Each test used a new derivation nonce. Logs and
raw failed-test output were archived and every transferred file hash verified.

| Requested | Initial echoes | Held echoes | Firewall entries |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 4 |
| 64 | 64 | 64 | 256 |
| 12,000 | 11,072 | 11,072 | 44,288 |
| 15,000 | 14,072 | 14,072 | 56,288 |
| 16,000 | 15,072 | 15,072 | 60,288 |
| 17,000 | 16,072 | 16,072 | 64,288 |
| 20,000 | 19,072 | 16,319 | 65,286 |

- 928 connections were **not attempted** within the unchanged opening budget,
  first at 12,000. They are not recorded as allocator refusals.
- At 20,000, 2,754 flows still owned NAT state but lacked expected firewall
  records: 2,753 held-echo timeouts and one successful echo. Snapshots are not
  atomic; this is not an exact eviction counter.
- No external tuple aliases were observed. Configuration and map IDs remained
  unchanged across workload phases.
- All admitted lower-load cohorts retained their held echoes in this run.
  Earlier below-capacity failures remain unresolved, not retrospectively waived.

The strict nine-collider test passed. The separate instrumented kernel
publication test passed all 18 cases. The dependency build ran 1,269 Sentinel
unit tests: all passed. None of those results overrides the pressure failure.

Pressure log SHA-256:
`f39ee4f5d3ed37439a3ee866ab0e6dbfaada87dae21c95ccff5bfe0fc9a0a04a`.

## Next work

Safe expiry maintenance is a prerequisite for non-evicting state storage, not
a capacity repair. Four firewall records per connection cannot retain 20,000
live connections in 65,536 entries. Complete-flow admission, a more compact
state representation and an explicit HA compatibility contract remain required.
The fixed workload, time budgets and pass criteria have not been relaxed.
