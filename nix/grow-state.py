"""Grow only existing factory state on the disk backing the active verity slot.

Only a verified six-partition factory layout is accepted. Type/order matching
is explicit for EVERY partition; no Format, Encrypt or new-partition request.
"""
from copy import deepcopy
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

ESP = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
HASH = '77ff5f63-e7b6-4633-acf4-1565b864c0e6'
STORE = '8484680c-9521-48c6-9c11-b0720656f69e'
GENERIC = '0fc63daf-8483-4772-8e79-3d69d8477de4'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identifier(value):
    require(isinstance(value,str), 'invalid GPT identity representation')
    parsed = uuid.UUID(value)
    require(parsed.int != 0, 'zero GPT identity is not an existing factory identity')
    return str(parsed)


def number(value):
    require(type(value) is int and 0 <= value <= (1 << 63)-1, 'invalid integer geometry')
    return value


def partition_path(disk, index):
    require(re.fullmatch(r'/dev/[A-Za-z0-9][A-Za-z0-9_.+-]*', disk) is not None, 'not a canonical kernel disk path')
    return disk+('p' if disk[-1].isdigit() else '')+str(index)


def validate_table(raw, disk, disk_bytes):
    require(isinstance(raw, dict), 'missing GPT table')
    require(raw.get('label') == 'gpt' and raw.get('device') == disk, 'not the selected GPT disk')
    require(raw.get('sectorsize') == 512, 'factory image requires512-byte sectors')
    require(raw.get('unit') == 'sectors', 'unknown GPT geometry units')
    disk_bytes = number(disk_bytes)
    require(disk_bytes > 1024**2 and disk_bytes % 512 == 0, 'invalid physical disk capacity')
    parts = raw.get('partitions')
    require(isinstance(parts, list) and len(parts) == 6, 'not the six-partition appliance factory')
    result = {'disk':disk, 'disk_bytes':disk_bytes, 'id':identifier(raw['id']), 'parts':[]}
    previous_end = 1024**2
    seen = set()
    allowed = [{ESP}, {HASH}, {STORE}, {GENERIC,HASH}, {GENERIC,STORE}, {GENERIC}]
    for index, part in enumerate(parts, 1):
        require(isinstance(part, dict) and part.get('node') == partition_path(disk,index), 'noncontiguous/foreign partition number')
        start, size = number(part.get('start')), number(part.get('size'))
        require(size > 0 and start*512 >= previous_end, 'empty or overlapping partition')
        require((start+size)*512 <= disk_bytes-33*512, 'partition exceeds physical GPT capacity')
        kind, identity = identifier(part['type']), identifier(part['uuid'])
        require(kind in allowed[index-1], 'unexpected factory partition type')
        require(identity not in seen, 'duplicate partition identity')
        require(isinstance(part.get('name'),str) and part['name'], 'missing existing GPT label')
        if index == 6:
            require(part['name'] == 'data', 'last partition is not factory data')
        seen.add(identity)
        result['parts'].append({'start':start, 'size':size, 'type':kind, 'uuid':identity,
                                'name':part['name'], 'attrs':part.get('attrs','')})
        previous_end = (start+size)*512
    return result


def definitions(layout):
    result = {}
    for index, part in enumerate(layout['parts'],1):
        size = part['size']*512
        text = '[Partition]\nType='+part['type']+'\nSizeMinBytes='+str(size)+'\n'
        if index < 6:
            text += 'SizeMaxBytes='+str(size)+'\n'
        # Match by type/order; UUID and Label are deliberately NOT match keys.
        # Never format, reset, encrypt, populate or create a partition here.
        result[f'{index:02d}-existing.conf'] = text
    return result


def validate_plan(layout, plan):
    require(isinstance(plan,list) and len(plan) == 6, 'repart would add/remove an entry')
    for index,(part,row) in enumerate(zip(layout['parts'],plan)):
        require(isinstance(row,dict) and type(row.get('partno')) is int and row['partno'] == index, 'repart assignment is not table order')
        require(identifier(row['uuid']) == part['uuid'] and row.get('label') == part['name'], 'repart identity/label assignment changed')
        require(number(row.get('offset')) == part['start']*512, 'repart would move a partition')
        old, new = number(row.get('old_size')), number(row.get('raw_size'))
        require(old == part['size']*512 and new % 512 == 0, 'repart old geometry differs')
        if index < 5:
            require(row.get('activity') == 'unchanged' and new == old, 'repart would resize a protected A/B or ESP partition')
        else:
            require(row.get('activity') in ('unchanged','resize') and new >= old, 'repart would recreate/shrink data')
            require(row['offset']+new <= layout['disk_bytes']-33*512, 'data exceeds device capacity')
    return plan[5]['raw_size']


def validate_after(before, raw_after, planned_data_bytes):
    after = validate_table(raw_after,before['disk'],before['disk_bytes'])
    expected = deepcopy(before)
    require(planned_data_bytes % 512 == 0, 'unaligned final data size')
    expected['parts'][5]['size'] = planned_data_bytes//512
    require(after == expected, 'post-write geometry/UUID/type/attrs differ from the sole approved data-size change')
    return after


def validate_capacity(layout, data_bytes):
    # Do not report success while an old GPT usable-end silently hides almost
    # all of a larger disk. Allow only normal GPT/alignment tail overhead.
    end = layout['parts'][5]['start']*512 + number(data_bytes)
    require(0 < layout['disk_bytes']-end < 2*1024**2,
            'repart plan leaves unused physical capacity; refusing an incomplete growth plan')


def capacity_already_covered(raw, layout):
    # sgdisk-installed data can end on a512-byte sector, with its GPT usable
    # end about1MiB before the physical end. Repart rounds existing sizes UP to
    #4KiB even when no growth is possible, producing ENOSPC. A verified full
    # partition requires NO table operation. Both bounds matter: an enlarged
    # disk with an old GPT usable-end must still go through full-capacity planning.
    last = number(raw.get('lastlba'))
    usable_end = (last+1)*512
    data = layout['parts'][5]
    data_end = (data['start']+data['size'])*512
    require(data_end <= usable_end <= layout['disk_bytes']-33*512,
            'GPT usable end does not contain the existing data partition')
    return usable_end-data_end < 4096 and layout['disk_bytes']-data_end < 2*1024**2


def rebind_shadow_table(raw, shadow, disk):
    """Check the private file's own node names before comparing real geometry."""
    require(isinstance(raw,dict) and raw.get('device') == str(shadow), 'plan copy is not the private file')
    result = deepcopy(raw)
    result['device'] = disk
    require(isinstance(result.get('partitions'),list) and len(result['partitions']) == 6,
            'plan copy changed the partition count')
    for index, part in enumerate(result['partitions'],1):
        require(isinstance(part,dict) and part.get('node') == str(shadow)+str(index),
                'plan copy contains a foreign partition node')
        part['node'] = partition_path(disk,index)
    return result


def parse_boot_parents(entries):
    require(isinstance(entries,list) and len(entries) == 2, 'active /usr is not the factory verity/store pair')
    disks, numbers = set(), set()
    for disk, part in entries:
        require(type(part) is int, 'invalid kernel partition number')
        numbers.add(part)
        partition_path('/dev/'+disk,6)
        disks.add(disk)
    require(numbers in ({2,3},{4,5}), 'active /usr spans foreign slots')
    return tuple('/dev/'+disk for disk in sorted(disks))


def select_boot_parents(entries):
    disks = parse_boot_parents(entries)
    require(len(disks) == 1, 'active /usr spans foreign disks or slots')
    return disks[0]


class SplitBootParents(ValueError):
    """A valid slot pair on two disks permits ONLY a read-only RAID check."""
    def __init__(self, disks):
        super().__init__('active /usr spans multiple disks; raw growth prohibited')
        self.disks = disks


def boot_disk():
    """Derive the ONE disk from the kernel's active verity mapper, not LABEL=data."""
    mapped = os.stat('/dev/mapper/usr')
    require(stat.S_ISBLK(mapped.st_mode), 'active /usr mapper is not a block device')
    root = Path('/sys/dev/block')/f'{os.major(mapped.st_rdev)}:{os.minor(mapped.st_rdev)}'
    slaves = list((root/'slaves').iterdir())
    require(len(slaves) == 2, 'active /usr is not the factory verity/store pair')
    entries = []
    for slave in slaves:
        physical = slave.resolve(strict=True)
        entries.append((physical.parent.name,int((physical/'partition').read_text().strip())))
    disks = parse_boot_parents(entries)
    identities = [physical_disk_identity(disk) for disk in disks]
    if len(disks) != 1:
        raise SplitBootParents(disks)
    return identities[0]


def physical_disk_identity(disk):
    partition_path(disk,6)
    native = os.stat(disk)
    require(stat.S_ISBLK(native.st_mode), 'boot parent is not a physical block device')
    kernel = Path('/sys/class/block')/Path(disk).name
    require(not (kernel/'partition').exists(), 'boot parent is itself a partition')
    require((kernel/'dev').read_text().strip() == f'{os.major(native.st_rdev)}:{os.minor(native.st_rdev)}', 'kernel/device identity differs')
    size = int((kernel/'size').read_text().strip())*512
    require(size > 0, 'empty boot disk')
    return disk, size, native.st_rdev


def split_mirror_report(disks, commands):
    # Installer copies protected partition GUIDs to each bootable mirror leg.
    # udev can legitimately resolve the hash and store to different legs on a
    # later boot. NEVER choose one leg for raw repartitioning in that case.
    require(len(disks) == 2 and len(set(disks)) == 2, 'ambiguous split boot parents')
    members = [commands.filesystem(partition_path(disk,6)) for disk in disks]
    require(all(member.get('TYPE') == 'linux_raid_member' for member in members),
            'split boot parents are not installer-managed RAID members')
    arrays = {identifier(member.get('UUID')) for member in members}
    member_ids = {identifier(member.get('UUID_SUB')) for member in members}
    require(len(arrays) == 1 and len(member_ids) == 2,
            'split boot parents belong to different arrays or duplicate members')
    return {'status':'installer-managed-storage','type':'linux_raid_member',
            'disks':list(disks),'array_uuid':arrays.pop(),'writes':False,
            'raw_data_growth_applicable':False}


def mounted_device(device):
    number = os.stat(device).st_rdev
    target = f'{os.major(number)}:{os.minor(number)}'
    return any(line.split()[2] == target for line in Path('/proc/self/mountinfo').read_text().splitlines())


class Commands:
    def __init__(self, args):
        self.args = args

    def run(self, tool, *args):
        command = [getattr(self.args,tool),*map(str,args)]
        out = subprocess.run(command,check=False,capture_output=True,text=True,timeout=45,
                             env={'PATH':'/run/current-system/sw/bin','LANG':'C.UTF-8',
                                  'SYSTEMD_COLORS':'0','SYSTEMD_PAGER':'cat'})
        require(out.returncode == 0, tool+' refused the verified boot-disk operation: '+out.stderr[-2000:])
        require(len(out.stdout) <= 1024**2, 'oversized '+tool+' response')
        return out.stdout

    def table(self, disk):
        return json.loads(self.run('sfdisk','--json',disk))['partitiontable']

    def filesystem(self, device):
        text = self.run('blkid','-p','-o','export',device)
        result = {}
        for line in text.splitlines():
            key, separator, value = line.partition('=')
            require(separator and key not in result, 'malformed filesystem identity')
            result[key] = value
        return result

    def repart(self, disk, directory, apply):
        text = self.run('repart','--empty=refuse','--factory-reset=no','--discard=no',
                        '--offline=yes','--dry-run='+('no' if apply else 'yes'),
                        '--json=short','--pretty=no','--definitions='+str(directory),disk)
        return json.loads(text)

    def plan(self, disk, directory, layout, device_identity):
        # libfdisk read-only mode retains an enlarged disk's OLD GPT usable-end,
        # while read/write mode relocates that header before planning. A direct
        # dry-run therefore is NOT the eventual write plan. Relocate ONLY a
        # header-only, private sparse regular copy, then validate every copied
        # entry against the real disk before asking repart for its dry plan.
        # No partition payload is copied and no real GPT is repaired here.
        shadow = directory/'plan.raw'
        with os.fdopen(os.open(disk,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as source:
            native = os.fstat(source.fileno())
            require(stat.S_ISBLK(native.st_mode) and native.st_rdev == device_identity,
                    'plan source no longer is the verified boot block device')
            prefix = source.read(1024**2)
            require(len(prefix) == 1024**2, 'short factory GPT prefix')
        with os.fdopen(os.open(shadow,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600),'wb') as output:
            output.truncate(layout['disk_bytes'])
            output.write(prefix)
        meta = shadow.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_size == layout['disk_bytes'],
                'planning destination is not the newly created private sparse file')
        self.run('sfdisk','--lock=yes','--wipe=never','--wipe-partitions=never',
                 '--relocate','gpt-bak-std',shadow)
        copied = rebind_shadow_table(self.table(str(shadow)),shadow,disk)
        require(validate_table(copied,disk,layout['disk_bytes']) == layout,
                'private planning copy differs from the verified real GPT entries')
        return self.repart(str(shadow),directory,False)


def run(args):
    require(os.geteuid() == 0, 'boot-state growth/inspection requires root')
    commands = Commands(args)
    try:
        disk, size, identity = boot_disk()
    except SplitBootParents as split:
        return split_mirror_report(split.disks,commands)
    data = partition_path(disk,6)
    filesystem = commands.filesystem(data)
    if filesystem.get('TYPE') in ('crypto_LUKS','linux_raid_member'):
        # Those installs already grow their members in the installer. Never
        # resize encryption/RAID mappings or format them as plaintext here.
        return {'status':'installer-managed-storage','type':filesystem['TYPE'],
                'disk':disk,'writes':False,'raw_data_growth_applicable':False}
    raw = commands.table(disk)
    before = validate_table(raw,disk,size)
    covered = capacity_already_covered(raw,before)
    require(filesystem.get('TYPE') == 'ext4' and filesystem.get('LABEL') == 'data', 'raw state is not the existing data ext4 filesystem')
    filesystem_id = identifier(filesystem['UUID'])
    if args.apply:
        require(not mounted_device(data), 'data is already mounted; growth belongs before the state mount')
        require((Path('/sys/class/block')/Path(disk).name/'ro').read_text().strip() == '0', 'boot disk is read-only')
    if covered:
        # Preserve the valid installer geometry exactly; do not resize/shrink,
        # ignore a failed repart, or create a substitute plaintext filesystem.
        current = before['parts'][5]['size']*512
        return {'status':'unchanged','disk':disk,'data':data,'old_bytes':current,'planned_bytes':current,
                'writes':False,'protected_partitions_unchanged':True,
                'planning':'existing data already covers verified GPT usable capacity within normal tail overhead',
                'filesystem_growth':'separate x-systemd.growfs mount step; not asserted by this helper'}
    with tempfile.TemporaryDirectory(prefix='appliance-data-growth-',dir='/run') as temporary:
        directory = Path(temporary)
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'definitions are not private')
        for name, text in definitions(before).items():
            with (directory/name).open('x') as output:
                output.write(text)
        plan = commands.plan(disk,directory,before,identity)
        wanted = validate_plan(before,plan)
        validate_capacity(before,wanted)
        changed = wanted != before['parts'][5]['size']*512
        if args.apply and changed:
            # Re-read all geometry, kernel identity and mount state immediately
            # before the only mutating command. No label-based target discovery.
            require(boot_disk() == (disk,size,identity), 'boot device changed during preflight')
            require(validate_table(commands.table(disk),disk,size) == before, 'GPT changed after dry-run')
            require(not mounted_device(data), 'data mounted after preflight')
            applied = commands.repart(disk,directory,True)
            require(validate_plan(before,applied) == wanted, 'committed plan differs from approved dry-run')
            commands.run('udevadm','settle','--timeout=20')
            validate_after(before,commands.table(disk),wanted)
            kernel_size = int((Path('/sys/class/block')/Path(data).name/'size').read_text().strip())*512
            require(kernel_size == wanted, 'kernel did not accept the data-partition growth')
            require(identifier(commands.filesystem(data)['UUID']) == filesystem_id, 'data filesystem identity changed')
    return {'status':'partition-grown' if args.apply and changed else 'unchanged' if not changed else 'dry-run',
            'disk':disk,'data':data,'old_bytes':before['parts'][5]['size']*512,'planned_bytes':wanted,
            'writes':bool(args.apply and changed),'protected_partitions_unchanged':True,
            'planning':'verified header-only private sparse copy; no source GPT write before approval',
            'filesystem_growth':'separate x-systemd.growfs mount step; not asserted by this helper'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true',help='Grow only approved existing data partition before it is mounted')
    for tool in ('sfdisk','blkid','repart','udevadm'):
        executable = 'systemd-repart' if tool == 'repart' else tool
        parser.add_argument('--'+tool,default='/run/current-system/sw/bin/'+executable)
    try:
        print(json.dumps(run(parser.parse_args())))
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        parser.exit(1,'appliance data growth refused: '+str(error)+'\n')
