# OTA boot and journal identity

The update job model distinguishes physical A/B slots from UKI filenames.
Community uses fixed `sentinel-a`/`sentinel-b` entry names. Native Enterprise
uses versioned `sentinel_vMAJOR.MINOR.PATCH-lts` entries; the running physical
slot still comes from the actual verity device, never the versioned filename.

The immutable native-provider build pin selects the extra name grammar; a
runtime environment variable, channel URL or API request cannot enable it.
Names are bounded basenames, versions fit the GPT label limit, and boot counters
must parse as bounded unsigned values. Any counter suffix, including exhausted
`+0-3`, is unassessed. Only a counter-free entry matching the running release/
slot can be permanent. The actual bootctl ESP/type/path, version and verity
observations remain required; a plausible name alone never establishes health.

Saved update results are also validated. A successful stage must retain the
exact expected/offer snapshot, target the opposite physical slot, name the
initial three-attempt entry, contain a SHA-256 UKI identity and distinct nonzero
partition UUIDs that do not alias either active partition. Versioned targets
must name the exact reviewed release. Real sgdisk uppercase UUID readbacks and
native lowercase UUIDs are equivalent identities, not distinct partitions.
Malformed saved results are refused without rewriting the original evidence.

An engine phase may repeat but cannot skip preflight or move backward. Once
Writing or Publishing is acknowledged, a later phase cannot erase its durable
uncertainty. Staging success requires both the local and durable Publishing
observations and a valid typed result. Missing/contradictory results are
recorded as failures; errors after possible writes remain
`write-outcome-unknown`, not an untouched-disk claim. Metadata checks cannot
publish an image result as a successful check.

This is an identity/journal prerequisite, **not** activation of the native Rust
transport. Native builds cannot fall through to the Community RAW writer or
advertise Community staging. The private provider's Prepared/Go exchange,
durable pre-Go authorization, owned child lifecycle/exit, independent live
readback and operational CLI/UI integration must be wired and qualified before
native staging is enabled. No release pin, image, signing trust, appliance or
update channel is changed by this source milestone.

The regression suite includes fixed/native/count/malformed names, both physical
slots, boot-source/hash/version mismatches, active/duplicate/zero UUIDs, corrupted
journals, phase transition combinations and incomplete/contradictory successes.
Host fixtures are not final-image or native-boot certificates. Community OTA,
publication-failure, journal/mutation and automatic fallback VM gates must remain
green after this shared model changes; full native/final-image qualification and
whole-OS SBOM/CVE clearance remain separate release gates.
