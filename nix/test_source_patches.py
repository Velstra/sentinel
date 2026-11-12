"""Exercise the actual build helper; never patch a customer or checkout tree."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BASH = os.environ.get('BASH_BIN', '/usr/bin/bash')
PATCH = os.environ.get('PATCH_BIN', '/usr/bin/patch')
HELPER = Path(os.environ.get('SOURCE_PATCHES_SCRIPT', Path(__file__).with_name('apply-source-patches.sh'))).resolve()
DIFF = '''diff --git a/first b/first
--- a/first
+++ b/first
@@ -1,3 +1,3 @@
 context before
-old value
+new value
 context after
diff --git a/second b/second
--- a/second
+++ b/second
@@ -1,3 +1,3 @@
 context before
-old value
+new value
 context after
'''


class SourcePatchGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='source-patch-test-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.patch = self.directory/'fixture.patch'
        self.patch.write_text(DIFF)
        for name in ('first','second'):
            self.write(name,'old value')

    def write(self,name,value):
        (self.directory/name).write_text('context before\n'+value+'\ncontext after\n')

    def contents(self):
        return {name:(self.directory/name).read_bytes() for name in ('first','second')}

    def run_helper(self):
        return subprocess.run([BASH,str(HELPER),PATCH,str(self.patch)],cwd=self.directory,
                              capture_output=True,timeout=10)

    def test_complete_forward_application_and_repeat_are_idempotent(self):
        result=self.run_helper()
        self.assertEqual(result.returncode,0,result.stderr)
        after=self.contents()
        self.assertTrue(all(b'new value' in value for value in after.values()))
        result=self.run_helper()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'Exact complete source patch already present',result.stdout)
        self.assertEqual(after,self.contents())

    def test_either_partial_direction_refuses_without_writes(self):
        for changed in ('first','second'):
            for name in ('first','second'):
                self.write(name,'new value' if name==changed else 'old value')
            before=self.contents()
            result=self.run_helper()
            self.assertEqual(result.returncode,1,result.stdout+result.stderr)
            self.assertIn(b'incomplete or incompatible',result.stderr)
            self.assertEqual(before,self.contents())

    def test_legacy_batch_reverse_is_an_explicit_negative_control(self):
        self.write('first','new value')
        before=self.contents()
        legacy=subprocess.run([PATCH,'--batch','--reverse','--dry-run','--fuzz=0','-p1',
                               '--input='+str(self.patch)],cwd=self.directory,capture_output=True,timeout=10)
        self.assertEqual(legacy.returncode,0,legacy.stdout+legacy.stderr)
        self.assertIn(b'Ignoring -R',legacy.stdout)
        self.assertEqual(before,self.contents())
        self.assertNotEqual(self.run_helper().returncode,0)

    def test_incompatible_context_and_missing_patch_refuse(self):
        self.write('second','unrelated change')
        before=self.contents()
        self.assertNotEqual(self.run_helper().returncode,0)
        self.assertEqual(before,self.contents())
        self.patch.unlink()
        self.assertNotEqual(self.run_helper().returncode,0)
        self.assertEqual(before,self.contents())

    def test_empty_invocation_is_not_reported_as_patched(self):
        result=subprocess.run([BASH,str(HELPER),PATCH],cwd=self.directory,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,2)

    def test_empty_comment_only_or_hunkless_patch_is_not_a_successful_noop(self):
        for text in ('', '# placeholder\n', '--- a/first\n+++ b/first\n'):
            self.patch.write_text(text)
            before=self.contents()
            result=self.run_helper()
            self.assertEqual(result.returncode,1,result.stdout+result.stderr)
            self.assertEqual(before,self.contents())


if __name__=='__main__':
    unittest.main(verbosity=2)
