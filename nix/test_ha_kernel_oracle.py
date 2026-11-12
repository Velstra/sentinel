"""Negative controls for the actual embedded kernel-result assertions.

No VM operations are executed here. The real privileged tests still run only
in ha-kernel-test.nix; these fixtures prevent an exit-zero/zero-tests pass.
"""
import ast
from pathlib import Path
import textwrap
import unittest

SOURCE = Path(__file__).with_name("ha-kernel-test.nix")
SCRIPT = SOURCE.read_text().split("testScript = ''", 1)[1].rsplit("'';", 1)[0]
TREE = ast.parse(textwrap.dedent(SCRIPT))


def assignment(node, names):
    return isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id in names for target in node.targets
    )


def references(node, names):
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def validator(kind):
    selected = {"listed"} if kind == "listing" else {"passed", "output"}
    nodes = [node for node in TREE.body if
             isinstance(node, ast.Import)
             or assignment(node, {"prefix", "expected"} | (selected - {"output"}))
             or isinstance(node, ast.Assert) and references(node, selected)]
    if any(isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
           and node.value.id == "machine" for parent in nodes for node in ast.walk(parent)):
        raise RuntimeError("Oracle unit tests must never execute VM operations")
    # Keep the real driver's assertions even when host CI uses python -O.
    return compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec", optimize=0)


scope = {}
exec(compile(ast.Module(body=[node for node in TREE.body if assignment(node, {"prefix", "expected"})],
                        type_ignores=[]), str(SOURCE), "exec", optimize=0), scope)
NAMES = sorted(scope["expected"])
LISTING = "\n".join(name + ": test" for name in NAMES) + "\n7 tests, 0 benchmarks\n"
OUTPUT = "\n".join("test " + name + " ... ok" for name in NAMES)
OUTPUT += "\ntest result: ok. 7 passed; 0 failed; 0 ignored; 10 filtered out; finished in 1s\n"


class KernelOracleTests(unittest.TestCase):
    def test_all_seven_named_successes_are_accepted(self):
        self.assertEqual(len(NAMES), 7)
        exec(validator("listing"), {"listing": LISTING})
        exec(validator("results"), {"output": OUTPUT})

    def test_listing_cannot_silently_select_zero_or_the_wrong_tests(self):
        for bad in ("", "0 tests, 0 benchmarks\n", LISTING.replace(NAMES[0], "wrong"),
                    LISTING + NAMES[0] + ": test\n"):
            with self.subTest(listing=bad), self.assertRaises(AssertionError):
                exec(validator("listing"), {"listing": bad})

    def test_exit_zero_is_not_sufficient_execution_evidence(self):
        for bad in ("", "test result: ok. 0 passed; 0 failed; 0 ignored;",
                    OUTPUT.replace(NAMES[0], "wrong"), OUTPUT.replace("7 passed", "6 passed"),
                    OUTPUT.replace("0 ignored", "1 ignored"),
                    OUTPUT.replace("test " + NAMES[0] + " ... ok\n", ""),
                    OUTPUT + "test " + NAMES[0] + " ... ok\n"):
            with self.subTest(output=bad), self.assertRaises(AssertionError):
                exec(validator("results"), {"output": bad})


if __name__ == "__main__":
    unittest.main()
