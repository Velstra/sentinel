# Direct-image persistent-state growth

## Problem and safety boundary

OSQA-174 was observed on the isolated OpenStack standalone node: a direct RAW
import on a 10 GiB root disk still had the image's 128 MiB data partition.
The installer was not run, so its existing target-disk expansion did not run
either. This observation does not establish a failure of encrypted or RAID
installs.

The shared image factory now supplies `<slotPrefix>-state-grow.service`, ordered
before the persistent-state mount and unlock service. It derives the one target
disk from the kernel's active `/dev/mapper/usr` verity/store pair, not a global
`LABEL=data` lookup. It accepts only the existing six-partition factory layout.
All existing GUIDs, labels, attributes, offsets and protected partition sizes
must survive unchanged; only the final data partition may grow.

The helper writes one definition for **each** existing partition in table order.
This is essential because repeated GPT types are matched by type/order, not by
their labels. The first five sizes are frozen. It never generates formatting,
encryption, reset, copying or new-partition directives. A checked dry-run precedes
fresh kernel-device, partition-table and mount checks, then one approved commit
and exact post-write validation. A mounted data partition refuses the write.
LUKS and RAID members are left to their existing installer-managed paths.

The initial real boot regression exposed a subtle first-growth failure: a
direct read-only Repart plan retained the old GPT usable-end, while the write
path would relocate that header and use the larger capacity. That failed run
is retained; it is not a successful growth test. The helper now plans on a
new private sparse file containing only the original GPT prefix. It relocates
the backup header **on that private regular file only**, checks every copied
entry against the real disk, then requests the full-capacity dry plan there.
The actual disk still receives no writes before the approved, freshly checked
commit. A trailing-capacity guard rejects incomplete plans. Only about 1 MiB
is physically allocated for the copy, not another full appliance image.

An independent installed-target boot additionally caught OSQA-177: an existing
data partition can legitimately end on a 512-byte sector rather than a 4 KiB
boundary. Repart's size rounding can refuse this already-full GPT layout. The
helper performs no partition operation when validated data already reaches
the GPT usable-end within one 4 KiB grain and only normal tail overhead below
2 MiB remains. Missing/impossible bounds refuse. Crucially, an old GPT on a
physically enlarged device does **not** meet that condition and still requires
the complete checked growth plan. Neither a failed command nor a missing mount
is ignored. This behavior has its own pure and actual installed-boot regressions.

References: the exact [systemd v260.5 image-growth algorithm](https://github.com/systemd/systemd/blob/v260.5/man/systemd-repart.xml)
matches repeated types in order; [util-linux v2.42.3 `sfdisk --relocate`](https://github.com/util-linux/util-linux/blob/v2.42.3/disk-utils/sfdisk.8.adoc)
documents backup-header relocation. The pinned binaries and actual failed/
corrected private experiments, not the manuals alone, determine the test verdict.

`x-systemd.growfs` handles the existing ext4 filesystem separately after mounting;
partition growth alone is not reported as filesystem-growth success. There is no
runtime package build/install, new mount mapper, manual blessing or boot-target
repair in this path.

## Verification and limits

`checks.x86_64-linux.state-growth-unit` exercises geometry/identity/order guards,
protected-size/new-partition refusal, dry-run-only execution, mounted/foreign
storage refusal, fresh boot-disk revalidation, explicit LUKS/RAID skipping and
post-write verification. Pure/mocked tests are not block-device evidence.

`checks.x86_64-linux.state-growth` boots the actual signed UKI/verity appliance
from an owned enlarged QEMU overlay. Read-only pre/post witnesses surround the
normal product helper. They compare every byte of all six original partition
regions **within** the growth operation, before the state mount. This includes
ESP bytes; legitimate boot-loader boot-count/bless renames are not mistaken for
growth writes by comparing the ESP across separate boots. The test checks real
partition and ext4 capacities, a pre-existing data marker, normal product health
and automatic first-boot blessing, followed by an idempotent reboot retaining
configuration and SSH identity. No fake mapper or replacement health check is
used. The test's presence is not itself a claim that its execution passed.

The first frozen source/VM execution is tracked separately in the private QA
receipts. Installed-image closure additionally requires a new signed candidate
and native checks. The existing installer/LUKS/fallback regressions must also
remain green; the direct-image test does not certify all their boot states.

OSQA-015 is separate: a complete multi-GiB RAW update still needs adequate
verified staging space. A 10 GiB disk cannot necessarily hold both slots and
another complete RAW file even after this growth. This change neither raises
the installer hardware floor nor claims to solve the download/staging contract.

## Installer interaction (OSQA-176)

The additional `state-growth-install` check grows the source to 16 GiB and then
attempts a genuine install to an owned 8 GB target, which fits the original
factory layout. This caught the installer incorrectly measuring the entire
grown source data entry, even though target data is always recreated. The
failed preflight left the target untouched; increasing the hardware floor is
not a fix.

`InstallLayout` now prepares a small private GPT-only backup using ordered
`sgdisk --pretend` operations. It keeps the five protected entries and caps
fresh data to the normal 128 MiB without enlarging a deliberately smaller
factory floor. Each target is checked with a pretend template load before any
target is erased. The real installation uses that template, retains protected
partition GUIDs, randomizes only the disk GUID and creates fresh data for the
target's capacity. The original source's data and GPT are not modified.

The regression compares both actual source GPT copies across the install,
all protected target partition GUIDs, exact ESP/verity/store payloads and
unchanged source configuration/SSH identity. The ordinary too-small-target,
RAID, LUKS and automatic boot-fallback gates remain separate requirements.
Pure source tests and the private regular-file experiment are not a successful
corrected product install; the actual frozen-candidate execution must pass too.

## Independent encrypted and mirrored boots (OSQA-178)

The additional `install-boot-luks`, `install-boot-raid1` and
`install-boot-raid1-luks` checks install through the actual CLI, power off the
source, and boot only the independently installed target disks twice. Encrypted
cases must answer the real console password request on each boot. They check
the real product health checker, active verity mapping, fresh SSH identity,
source-state isolation, filesystem mount and persistent target configuration.
Mirrored cases additionally require two active and working RAID1 members.
These checks do not establish degraded-array recovery or physical certification.

`install-boot-luks-retry` additionally rejects two real wrong console passwords
and requires the correct third attempt to unlock, followed by a normal second
boot with the same health/identity/persistence checks. It never opens a mapper
from the controller or changes the product's attempt limit.

The first real encrypted boot caught the unlocker treating absent early udev
filesystem properties as evidence of no encryption, although a direct block
probe already recognized the LUKS header. Discovery now uses the direct blkid
property provider on only the active boot disk's data partition and its array
descendants. It distinguishes unreadable signatures from plaintext and waits
boundedly for array assembly. Other attached encrypted volumes are not targets.
See the primary [`lsblk` documentation](https://github.com/util-linux/util-linux/blob/v2.42.3/lsblk-cmd/lsblk.8.adoc)
for property providers and the early-udev warning. Actual frozen-candidate boot
receipts, not documentation or pure chooser tests, determine the verdict.

An initial corrected-image run did prompt and unlock, then exposed a test-only
reference to the full source tree, which is intentionally absent from the
immutable guest. The regression now references the exact individual product
health-check script already in its closure, as the plaintext boot test does.
No health checker, mapper, mount, boot entry or blessing behavior is replaced.

OSQA-179 was then found on a real second RAID1 boot: copied protected GPT
identities allow the verity hash and store to resolve to different mirror legs.
Raw growth still requires exactly one disk. The helper permits only a read-only
installer-managed skip for a valid same-slot pair on two physical boot disks
when both data partitions directly probe as members of the same MD UUID with
distinct member UUIDs. Plaintext, LUKS-only, unrelated arrays and cloned member
identities refuse that exception. It does not select a leg for writes or resize
the array. The failed boot remains retained separately from corrected runs.
