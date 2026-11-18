import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "image_runtime", Path(__file__).resolve().parents[1] / "scripts/check_image_runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class ImageRuntimeTest(unittest.TestCase):
    COMPLETION = "# gcc(1) completion -*- shell-script -*-\n_comp_cmd_gcc()\n{\n    :\n}\ncomplete -F _comp_cmd_gcc gcc g++\n"

    def test_transitive_tools_not_only_system_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            system = Path(tmp) / "system"
            dependency = Path(tmp) / "transitive"
            system.mkdir()
            (dependency / "bin").mkdir(parents=True)
            tool = dependency / "bin/nix"
            tool.write_text("not executed")
            self.assertEqual(runtime.inspect([system, dependency]), [str(tool)])

    def test_missing_or_empty_closure_refused(self):
        with self.assertRaises(ValueError):
            runtime.inspect([])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                runtime.inspect([Path(tmp) / "missing"])

    def test_runtime_libraries_and_perl_are_not_compilers(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            (package / "lib").mkdir()
            (package / "lib/libgcc_s.so.1").touch()
            (package / "bin").mkdir()
            (package / "bin/perl").touch()
            self.assertEqual(runtime.inspect([package]), [])

    def test_sbin_and_dangling_tool_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            (package / "sbin").mkdir()
            tool = package / "sbin/nix-daemon"
            tool.symlink_to(package / "missing")
            self.assertEqual(runtime.inspect([package]), [str(tool)])

    def test_tool_families_and_nested_paths_cannot_hide_executables(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            names = ["bin/nix-instantiate", "bin/x86_64-unknown-linux-gnu-gcc",
                     "libexec/nix", "tools/llvm/bin/clang-20", "private/rustc"]
            for name in names:
                tool = package / name
                tool.parent.mkdir(parents=True, exist_ok=True)
                tool.touch()
                tool.chmod(0o755)
            self.assertEqual(runtime.inspect([package]), sorted(str(package / name) for name in names))

    def test_nonexecutable_documentation_is_not_a_runtime_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            (package / "share/doc").mkdir(parents=True)
            (package / "share/doc/gcc").touch()
            self.assertEqual(runtime.inspect([package]), [])

    def test_nonexecutable_gcc_completion_aliases_are_data_not_compilers(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            completion = package / "share/bash-completion/completions"
            completion.mkdir(parents=True)
            target = completion / "gcc"
            target.write_text(self.COMPLETION)
            target.chmod(0o444)
            for name in ("cc", "c++", "g++", "gcc-8", "g++-8"):
                (completion / name).symlink_to("gcc")
            self.assertEqual(runtime.inspect([package]), [])
            # A compiler elsewhere in the same closure still fails.
            tool = package / "private/toolchain/bin/gcc"
            tool.parent.mkdir(parents=True)
            tool.touch()
            self.assertEqual(runtime.inspect([package]), [str(tool)])

    def test_completion_links_to_executable_binary_invalid_or_unknown_data_are_refused(self):
        variants = (
            (self.COMPLETION.encode(), 0o555),
            (b"\x7fELF\x00compiler", 0o444),
            (b"\xff", 0o444),
            ((self.COMPLETION + "\x00").encode(), 0o444),
            (b"# unrelated script\necho compiler\n", 0o444),
            ((self.COMPLETION + "#" * 65536).encode(), 0o444),
        )
        for data, mode in variants:
            with self.subTest(mode=mode, data=data[:20]), tempfile.TemporaryDirectory() as tmp:
                package = Path(tmp)
                completion = package / "share/bash-completion/completions"
                completion.mkdir(parents=True)
                target = completion / "gcc"
                target.write_bytes(data)
                target.chmod(mode)
                alias = completion / "g++"
                alias.symlink_to("gcc")
                self.assertIn(str(alias), runtime.inspect([package]))

    def test_completion_links_cannot_escape_the_same_subtree_or_hide_dangling_targets(self):
        for destination in ("missing", "../../../doc/gcc", "subdirectory/gcc"):
            with self.subTest(destination=destination), tempfile.TemporaryDirectory() as tmp:
                package = Path(tmp)
                completion = package / "share/bash-completion/completions"
                completion.mkdir(parents=True)
                if destination != "missing":
                    target = completion / destination
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(self.COMPLETION)
                    target.chmod(0o444)
                alias = completion / "g++"
                alias.symlink_to(destination)
                self.assertIn(str(alias), runtime.inspect([package]))

    def test_completion_looking_links_in_bin_are_still_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp)
            completion = package / "share/bash-completion/completions"
            completion.mkdir(parents=True)
            target = completion / "gcc"
            target.write_text(self.COMPLETION)
            target.chmod(0o444)
            (package / "bin").mkdir()
            alias = package / "bin/cc"
            alias.symlink_to(target)
            self.assertEqual(runtime.inspect([package]), [str(alias)])

    def test_individual_store_outputs_and_dangling_aliases_are_inspected(self):
        with tempfile.TemporaryDirectory() as tmp:
            compiler = Path(tmp) / ("0" * 32 + "-gcc")
            compiler.write_bytes(b"compiler")
            compiler.chmod(0o755)
            alias = Path(tmp) / ("1" * 32 + "-nix-shell")
            alias.symlink_to("/missing")
            data = Path(tmp) / ("2" * 32 + "-gcc")
            data.write_bytes(b"non-executable document")
            data.chmod(0o644)
            self.assertEqual(runtime.inspect([compiler, alias, data]),
                             sorted(map(str, [compiler, alias])))

    def test_directory_tool_links_are_inspected_without_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "package"
            outside = Path(tmp) / "outside"
            package.mkdir()
            outside.mkdir()
            (outside / "rustc").touch()
            alias = package / "gcc"
            alias.symlink_to(outside, target_is_directory=True)
            (package / "unrelated").symlink_to(outside, target_is_directory=True)
            self.assertEqual(runtime.inspect([package]), [str(alias)])

    def test_special_closure_outputs_and_walk_errors_are_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "unsupported"):
                runtime.inspect([fifo])
            def denied(*args, **kwargs):
                kwargs["onerror"](PermissionError("unreadable closure"))
                return iter(())
            with patch.object(runtime.os, "walk", side_effect=denied):
                with self.assertRaisesRegex(PermissionError, "unreadable"):
                    runtime.inspect([Path(tmp)])


if __name__ == "__main__":
    unittest.main()
