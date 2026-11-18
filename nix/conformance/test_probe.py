import unittest

from probe import cases, compare, digest, payload


class DifferentialContract(unittest.TestCase):
    def baseline(self):
        return [{"case": name, "expected": expected, "observed": expected}
                for side in ("lan", "wan", "pmtu") for name, _, expected in cases(side)]

    def test_identical_failure_is_not_a_pass(self):
        failed = self.baseline()
        failed[0] = {**failed[0], "observed": {"error": "timeout"}}
        result = compare(failed, failed)
        self.assertFalse(result[0]["oracle_valid"])
        self.assertFalse(result[0]["passed"])

    def test_known_mismatch_is_not_suppressed(self):
        oracle = self.baseline()
        subject = [{**oracle[0], "observed": {"error": "timeout"}}, *oracle[1:]]
        self.assertFalse(compare(oracle, subject)[0]["passed"])
        self.assertTrue(compare(oracle, oracle)[0]["passed"])

    def test_different_or_duplicate_inventory_is_refused(self):
        one = self.baseline()
        for other in ([], one + one, [{**one[0], "expected": {"different": True}}, *one[1:]]):
            with self.assertRaises(ValueError):
                compare(one, other)
        with self.assertRaises(ValueError):
            compare([], [])
        with self.assertRaises(ValueError):
            compare(one[1:], one[1:])

    def test_payload_and_case_inventory_are_deterministic(self):
        self.assertEqual(len(payload(4000)), 4000)
        self.assertEqual(digest(payload(4000)), digest(payload(4000)))
        names = [case[0] for side in ("lan", "wan", "pmtu") for case in cases(side)]
        self.assertEqual(len(names), 17)
        self.assertEqual(len(names), len(set(names)))

    def test_both_probes_cannot_redefine_loss_as_success(self):
        records = self.baseline()
        records[0] = {**records[0], "expected": {"error": "timeout"},
                      "observed": {"error": "timeout"}}
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            compare(records, records)

    def test_boolean_success_cannot_be_replaced_with_numeric_one(self):
        records = self.baseline()
        index = next(i for i, record in enumerate(records)
                     if record["case"] == "ipv4-icmp-echo-snat")
        records[index] = {**records[index], "observed": {"delivered": 1}}
        self.assertFalse(compare(records, records)[index]["oracle_valid"])
        self.assertFalse(compare(self.baseline(), records)[index]["passed"])
        records[index]["expected"] = {"delivered": 1}
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            compare(records, records)

    def test_malformed_records_fail_closed(self):
        for bad in (None, {}, [None], [{"case": []}],
                    [{**self.baseline()[0], "observed": None}],
                    [{**self.baseline()[0], "ignored": True}]):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "malformed"):
                    compare(bad, self.baseline())
                with self.assertRaisesRegex(ValueError, "malformed"):
                    compare(self.baseline(), bad)

    def test_unknown_side_never_silently_selects_pmtu(self):
        with self.assertRaisesRegex(ValueError, "unknown traffic side"):
            cases("typo")


if __name__ == "__main__":
    unittest.main()
