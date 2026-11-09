"""Pure safety contracts only. Native boot integration is separately required."""
from copy import deepcopy
import unittest
import uuid
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("grow_state", Path(__file__).with_name("grow-state.py"))
grow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grow)


def fixture():
    kinds=[grow.ESP,grow.HASH,grow.STORE,grow.GENERIC,grow.GENERIC,grow.GENERIC]
    parts=[]
    start=2048
    for i,kind in enumerate(kinds,1):
        parts.append({'node':'/dev/vda'+str(i),'start':start,'size':8192,
                      'type':kind,'uuid':str(uuid.UUID(int=i)),'name':'data' if i==6 else 'reserved-'+str(i)})
        start+=8192
    return {'label':'gpt','device':'/dev/vda','unit':'sectors','sectorsize':512,
            'lastlba':128*1024**2//512-34,
            'id':str(uuid.UUID(int=100)),'partitions':parts}


def plan_for(table):
    return [{'partno':i,'label':p['name'],'uuid':p['uuid'],'offset':p['start']*512,
             'old_size':p['size']*512,'raw_size':p['size']*512,
             'activity':'unchanged'} for i,p in enumerate(table['partitions'])]


class GrowthGuards(unittest.TestCase):
    def setUp(self):
        self.table=fixture()
        self.bytes=128*1024**2
        self.layout=grow.validate_table(self.table,'/dev/vda',self.bytes)
        self.plan=plan_for(self.table)

    def test_repeated_generic_types_keep_every_existing_definition_in_order(self):
        defs=grow.definitions(self.layout)
        self.assertEqual(len(defs),6)
        self.assertEqual(list(defs),[f'{i:02d}-existing.conf' for i in range(1,7)])
        self.assertEqual(sum(grow.GENERIC in v for v in defs.values()),3)
        self.assertTrue(all('SizeMaxBytes=' in v for v in list(defs.values())[:5]))
        self.assertNotIn('SizeMaxBytes=',list(defs.values())[5])
        for text in defs.values():
            for prohibited in ('Format=','FactoryReset=','Encrypt=','CopyBlocks=','CopyFiles=','Label=','UUID='):
                self.assertNotIn(prohibited,text)

    def test_data_only_growth_and_idempotent_plan(self):
        self.assertEqual(grow.validate_plan(self.layout,self.plan),4194304)
        self.plan[-1].update(activity='resize',raw_size=64*1024**2)
        size=grow.validate_plan(self.layout,self.plan)
        after=deepcopy(self.table)
        after['partitions'][-1]['size']=size//512
        result=grow.validate_after(self.layout,after,size)
        self.assertEqual(result['parts'][:5],self.layout['parts'][:5])

    def test_updated_or_partially_retyped_B_is_preserved_not_reinterpreted(self):
        for hash_type,store_type in [(grow.HASH,grow.STORE),(grow.HASH,grow.GENERIC),(grow.GENERIC,grow.STORE)]:
            data=deepcopy(self.table)
            data['partitions'][3]['type']=hash_type
            data['partitions'][4]['type']=store_type
            grow.validate_table(data,'/dev/vda',self.bytes)

    def test_uuid_representation_case_is_not_a_different_identity(self):
        self.plan[0]['uuid']=self.plan[0]['uuid'].upper()
        grow.validate_plan(self.layout,self.plan)

    def test_kernel_verity_pair_selects_one_parent_not_a_global_data_label(self):
        self.assertEqual(grow.select_boot_parents([('vda',2),('vda',3)]),'/dev/vda')
        self.assertEqual(grow.select_boot_parents([('nvme0n1',5),('nvme0n1',4)]),'/dev/nvme0n1')
        self.assertEqual(grow.partition_path('/dev/nvme0n1',6),'/dev/nvme0n1p6')
        self.assertEqual(grow.partition_path('/dev/sda',6),'/dev/sda6')

    def test_foreign_missing_or_cross_slot_kernel_parents_refused(self):
        for entries in [[],[('vda',2)],[('vda',2),('sda',3)],
                        [('vda',2),('vda',5)],[('vda',2),('vda',2)],
                        [('vda',2),('vda',3),('vda',4)],
                        [('vda/../sda',2),('vda/../sda',3)],
                        [('vda',True),('vda',3)]]:
            with self.assertRaises(ValueError):
                grow.select_boot_parents(entries)

    def test_bad_uuid_values_refuse_cleanly(self):
        for value in (None,True,123,'not-a-guid','00000000-0000-0000-0000-000000000000'):
            with self.assertRaises(ValueError):
                grow.identifier(value)

    def test_wrong_selected_disk_and_nonfactory_layout_refused(self):
        for modify in [lambda x:x.update(device='/dev/sda'),lambda x:x.update(label='dos'),
                       lambda x:x.update(sectorsize=4096),lambda x:x['partitions'].append(deepcopy(x['partitions'][-1])),
                       lambda x:x['partitions'][5].update(name='someone-else'),
                       lambda x:x['partitions'][2].update(type=grow.GENERIC),
                       lambda x:x['partitions'][0].update(node='/dev/sda1'),
                       lambda x:x['partitions'][1].update(uuid=x['partitions'][0]['uuid']),
                       lambda x:x['partitions'][1].update(start=1),
                       lambda x:x['partitions'][0].update(size=True)]:
            data=deepcopy(self.table);modify(data)
            with self.assertRaises((ValueError,KeyError)):
                grow.validate_table(data,'/dev/vda',self.bytes)

    def test_dry_plan_any_protected_change_or_new_partition_refused(self):
        mutations=[lambda x:x.append(deepcopy(x[-1])),lambda x:x[0].update(partno=True),
                   lambda x:x[3].update(uuid=str(uuid.UUID(int=999))),lambda x:x[2].update(label='new'),
                   lambda x:x[1].update(offset=0),lambda x:x[4].update(raw_size=8192),
                   lambda x:x[0].update(activity='create'),lambda x:x[5].update(activity='create'),
                   lambda x:x[5].update(raw_size=1),lambda x:x[5].update(raw_size=self.bytes),
                   lambda x:x[5].update(raw_size=False)]
        for mutate in mutations:
            data=deepcopy(self.plan);mutate(data)
            with self.assertRaises((ValueError,KeyError)):
                grow.validate_plan(self.layout,data)

    def test_postwrite_unexpected_metadata_is_never_waived(self):
        for key,value in [('uuid',str(uuid.UUID(int=999))),('name','changed'),('attrs','GUID:59'),('size',8193),('start',2049)]:
            data=deepcopy(self.table);data['partitions'][0][key]=value
            with self.assertRaises((ValueError,KeyError)):
                grow.validate_after(self.layout,data,self.plan[-1]['raw_size'])

    def test_incomplete_old_GPT_capacity_plan_is_not_success(self):
        old = self.layout['parts'][5]['size']*512
        with self.assertRaisesRegex(ValueError, 'unused physical capacity'):
            grow.validate_capacity(self.layout,old)
        wanted = self.bytes - self.layout['parts'][5]['start']*512 - 20480
        grow.validate_capacity(self.layout,wanted)

    def test_full_sector_aligned_installer_end_needs_no_partition_operation(self):
        table = deepcopy(self.table)
        # GPT fdisk can reserve a1MiB tail and use its last512-byte sector.
        table['lastlba'] = self.bytes//512-2048
        table['partitions'][5]['size'] = table['lastlba']+1-table['partitions'][5]['start']
        layout = grow.validate_table(table,'/dev/vda',self.bytes)
        self.assertNotEqual(layout['parts'][5]['size']*512 % 4096,0)
        self.assertTrue(grow.capacity_already_covered(table,layout))
        # The SAME old header on a larger real disk is NOT already covered.
        larger = grow.validate_table(table,'/dev/vda',self.bytes*2)
        self.assertFalse(grow.capacity_already_covered(table,larger))

    def test_unknown_or_impossible_GPT_end_is_not_a_full_disk_exception(self):
        for last in (None,True,1,self.bytes//512):
            table = deepcopy(self.table)
            table['lastlba'] = last
            with self.assertRaises(ValueError):
                grow.capacity_already_covered(table,self.layout)

    def test_private_copy_must_have_its_own_exact_nodes_before_rebinding(self):
        shadow = Path('/run/private/plan.raw')
        data = deepcopy(self.table)
        data['device'] = str(shadow)
        for index,p in enumerate(data['partitions'],1):
            p['node'] = str(shadow)+str(index)
        self.assertEqual(grow.rebind_shadow_table(data,shadow,'/dev/vda'),self.table)
        data['partitions'][2]['node'] = '/dev/vda3'
        with self.assertRaisesRegex(ValueError, 'foreign partition node'):
            grow.rebind_shadow_table(data,shadow,'/dev/vda')


class ExecutionGuards(unittest.TestCase):
    def setUp(self):
        self.table = fixture()
        self.plan = plan_for(self.table)
        wanted = 128*1024**2-self.table['partitions'][5]['start']*512-20480
        self.plan[-1].update(activity='resize', raw_size=wanted)
        self.after = deepcopy(self.table)
        self.after['partitions'][-1]['size'] = wanted//512
        self.events = []
        self.filesystem = {'TYPE':'ext4','LABEL':'data','UUID':str(uuid.UUID(int=200))}
        owner = self

        class FakeCommands:
            def __init__(self, args):
                self.tables = 0

            def filesystem(self, device):
                owner.events.append(('filesystem', device))
                return owner.filesystem

            def table(self, disk):
                self.tables += 1
                owner.events.append(('table', disk))
                return owner.after if self.tables == 3 else owner.table

            def repart(self, disk, directory, apply):
                owner.events.append(('repart', apply))
                assert sorted(p.name for p in directory.glob('*.conf')) == [f'{i:02d}-existing.conf' for i in range(1,7)]
                return owner.plan

            def plan(self, disk, directory, layout, identity):
                assert layout['disk'] == disk and identity == 123
                return self.repart(disk,directory,False)

            def run(self, tool, *args):
                owner.events.append((tool, *args))

        self.fake = FakeCommands
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        original_temp = tempfile.TemporaryDirectory
        self.addCleanup(patch.stopall)
        patch.object(grow, 'Commands', self.fake).start()
        patch.object(grow, 'boot_disk', return_value=('/dev/vda',128*1024**2,123)).start()
        patch.object(grow.os, 'geteuid', return_value=0).start()
        patch.object(grow, 'mounted_device', return_value=False).start()
        patch.object(grow.tempfile, 'TemporaryDirectory',
                     side_effect=lambda **kwargs: original_temp(dir=self.temporary.name)).start()
        original_read = Path.read_text

        def read(path, *args, **kwargs):
            if str(path) == '/sys/class/block/vda/ro':
                return '0'
            if str(path) == '/sys/class/block/vda6/size':
                return str(wanted//512)
            return original_read(path, *args, **kwargs)

        patch.object(Path, 'read_text', read).start()

    def test_dry_run_has_no_mutating_command(self):
        report = grow.run(SimpleNamespace(apply=False))
        self.assertEqual(report['status'], 'dry-run')
        self.assertFalse(report['writes'])
        self.assertEqual([v for v in self.events if v[0]=='repart'], [('repart',False)])

    def test_approved_commit_rechecks_then_verifies_exact_postwrite_state(self):
        report = grow.run(SimpleNamespace(apply=True))
        self.assertEqual(report['status'], 'partition-grown')
        self.assertTrue(report['writes'])
        self.assertEqual([v for v in self.events if v[0]=='repart'], [('repart',False),('repart',True)])
        self.assertEqual(len([v for v in self.events if v[0]=='table']), 3)
        self.assertIn(('udevadm','settle','--timeout=20'), self.events)

    def test_mounted_data_blocks_even_the_repart_dry_run(self):
        with patch.object(grow, 'mounted_device', return_value=True):
            with self.assertRaisesRegex(ValueError, 'already mounted'):
                grow.run(SimpleNamespace(apply=True))
        self.assertFalse(any(v[0]=='repart' for v in self.events))

    def test_luks_and_raid_members_are_never_treated_as_plain_ext4(self):
        for kind in ('crypto_LUKS','linux_raid_member'):
            self.events.clear()
            self.filesystem = {'TYPE':kind}
            report = grow.run(SimpleNamespace(apply=True))
            self.assertEqual(report['status'], 'installer-managed-storage')
            self.assertFalse(report['writes'])
            self.assertEqual(self.events, [('filesystem','/dev/vda6')])

    def test_split_verity_mirror_is_only_inspected_and_never_repartitioned(self):
        common = str(uuid.UUID(int=201))
        members = [{'TYPE':'linux_raid_member','UUID':common,'UUID_SUB':str(uuid.UUID(int=202+i))} for i in range(2)]
        with patch.object(grow,'boot_disk',side_effect=grow.SplitBootParents(('/dev/vda','/dev/vdb'))), \
             patch.object(self.fake,'filesystem',side_effect=members) as probe:
            report = grow.run(SimpleNamespace(apply=True))
        self.assertFalse(report['writes'])
        self.assertEqual(report['array_uuid'],common)
        self.assertEqual([c.args for c in probe.call_args_list],[('/dev/vda6',),('/dev/vdb6',)])
        self.assertEqual(self.events,[])

    def test_split_plain_crypto_foreign_array_or_cloned_member_never_bypasses_the_guard(self):
        good = {'TYPE':'linux_raid_member','UUID':str(uuid.UUID(int=201)),'UUID_SUB':str(uuid.UUID(int=202))}
        cases = [{'TYPE':'ext4'},{'TYPE':'crypto_LUKS'},
                 {**good,'UUID':str(uuid.UUID(int=999)),'UUID_SUB':str(uuid.UUID(int=203))},
                 good,{**good,'UUID_SUB':None},{**good,'UUID':None}]
        for other in cases:
            with self.subTest(other=other), \
                 patch.object(grow,'boot_disk',side_effect=grow.SplitBootParents(('/dev/vda','/dev/vdb'))), \
                 patch.object(self.fake,'filesystem',side_effect=[good,other]):
                with self.assertRaises(ValueError):
                    grow.run(SimpleNamespace(apply=True))
        self.assertEqual(self.events,[])

    def test_split_mirror_inspection_still_requires_one_valid_slot_pair(self):
        self.assertEqual(grow.parse_boot_parents([('vda',2),('vdb',3)]),('/dev/vda','/dev/vdb'))
        with self.assertRaises(ValueError):
            grow.parse_boot_parents([('vda',2),('vdb',5)])
        # The ordinary single-disk selector remains strict; it MUST NOT select
        # an arbitrary member for writes, even when the slot pair is valid.
        with self.assertRaises(ValueError):
            grow.select_boot_parents([('vda',2),('vdb',3)])

    def test_foreign_filesystem_and_unsafe_plan_never_reach_writer(self):
        self.filesystem['LABEL'] = 'foreign'
        with self.assertRaisesRegex(ValueError, 'existing data ext4'):
            grow.run(SimpleNamespace(apply=True))
        self.filesystem['LABEL'] = 'data'
        self.plan[4]['raw_size'] += 4096
        with self.assertRaisesRegex(ValueError, 'protected'):
            grow.run(SimpleNamespace(apply=True))
        self.assertNotIn(('repart',True), self.events)

    def test_changed_boot_disk_after_dry_run_blocks_writer(self):
        with patch.object(grow, 'boot_disk', side_effect=[('/dev/vda',128*1024**2,123),('/dev/sda',128*1024**2,124)]):
            with self.assertRaisesRegex(ValueError, 'boot device changed'):
                grow.run(SimpleNamespace(apply=True))
        self.assertNotIn(('repart',True), self.events)

    def test_non_root_never_discovers_or_writes_storage(self):
        with patch.object(grow.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(ValueError, 'requires root'):
                grow.run(SimpleNamespace(apply=True))
        self.assertEqual(self.events, [])

    def test_already_full_installer_partition_never_calls_repart(self):
        self.table['lastlba'] = 128*1024**2//512-2048
        self.table['partitions'][5]['size'] = self.table['lastlba']+1-self.table['partitions'][5]['start']
        report = grow.run(SimpleNamespace(apply=True))
        self.assertEqual(report['status'],'unchanged')
        self.assertFalse(report['writes'])
        self.assertEqual(self.events,[('filesystem','/dev/vda6'),('table','/dev/vda')])


if __name__=='__main__':
    unittest.main(verbosity=2)
