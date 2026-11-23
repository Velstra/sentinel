"""Unit tests for ha-failover-bound.py: the resume instant is the client's own reply time."""

import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location(
    "ha_failover_bound", pathlib.Path(__file__).with_name("ha-failover-bound.py")
)
bound = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bound)

ANCHOR = 1000.0


def stream(gap_from, gap_to, until=None, step=0.03):
    """Reply times every `step` s, with no reply between gap_from and gap_to (anchor-relative)."""
    times, t = [], ANCHOR - 1.0
    until = gap_to + 1.2 if until is None else until
    while t < ANCHOR + until:
        if not (ANCHOR + gap_from < t < ANCHOR + gap_to):
            times.append(round(t, 3))
        t += step
    return times


class Resume(unittest.TestCase):
    def test_the_resume_instant_is_the_reply_that_ends_the_outage(self):
        times = stream(0.3, 0.9)
        resumed = bound.ha_resume(times, ANCHOR, outage=True)
        self.assertAlmostEqual(resumed - ANCHOR, 0.92, delta=0.031)

    def test_a_resume_after_the_bound_is_a_miss_however_soon_it_is_polled(self):
        limit = 1.6
        late = stream(0.3, limit + 0.05)
        resumed = bound.ha_resume(late, ANCHOR, outage=True)
        self.assertFalse(bound.ha_resumed_within(resumed, ANCHOR, limit), resumed - ANCHOR)
        early = stream(0.3, limit - 0.08)
        resumed = bound.ha_resume(early, ANCHOR, outage=True)
        self.assertTrue(bound.ha_resumed_within(resumed, ANCHOR, limit), resumed - ANCHOR)

    def test_an_outage_still_running_or_without_progress_has_not_resumed(self):
        running = [t for t in stream(0.3, 5.0) if t < ANCHOR + 2.0]
        self.assertIsNone(bound.ha_resume(running, ANCHOR, outage=True))
        one_reply = [t for t in stream(0.3, 0.9) if t <= ANCHOR + 0.93]
        self.assertIsNone(bound.ha_resume(one_reply, ANCHOR, outage=True))

    def test_a_fault_that_has_not_bitten_yet_is_not_a_resume(self):
        flowing = [t for t in stream(0.3, 0.9) if t < ANCHOR + 0.25]
        self.assertIsNone(bound.ha_resume(flowing, ANCHOR, outage=True))

    def test_a_short_stall_before_the_outage_is_not_its_end(self):
        # A 0.15 s stall right after the anchor, then the real outage: the
        # resume is the end of the longest silence, once the stream is steady.
        times = [t for t in stream(1.0, 2.0, until=3.2) if not (ANCHOR + 0.10 < t < ANCHOR + 0.25)]
        early = [t for t in times if t < ANCHOR + 0.6]
        self.assertIsNone(bound.ha_resume(early, ANCHOR, outage=True))
        resumed = bound.ha_resume(times, ANCHOR, outage=True)
        self.assertAlmostEqual(resumed - ANCHOR, 2.02, delta=0.031)

    def test_without_an_expected_outage_a_flowing_stream_resumes_at_once(self):
        flowing = [t for t in stream(5.0, 6.0) if t < ANCHOR + 0.3]
        resumed = bound.ha_resume(flowing, ANCHOR, outage=False)
        self.assertLess(resumed - ANCHOR, 0.031)
        # A gap that began before the call (the handover already under way) ends it.
        spanning = stream(-0.2, 0.4)
        resumed = bound.ha_resume(spanning, ANCHOR, outage=False)
        self.assertAlmostEqual(resumed - ANCHOR, 0.41, delta=0.031)


class Takeover(unittest.TestCase):
    """The split check: the product's takeover against its design, then the
    client's resume against the retransmission that design allows."""

    SENDS = [0.30, 0.51, 0.93, 1.77]  # s, s+R, s+3R, s+7R with R = 0.21

    def test_a_takeover_over_its_design_fails_even_when_the_stream_resumes_fast(self):
        verdict = bound.ha_judge_takeover(0.30, self.SENDS, owner_frame=0.30 + 0.75, resumed=0.94, p_max=0.70)
        self.assertFalse(verdict["primary"], verdict)
        self.assertTrue(verdict["secondary"], verdict)

    def test_a_takeover_inside_its_design_that_misses_the_3r_retry_passes_at_7r(self):
        verdict = bound.ha_judge_takeover(0.30, self.SENDS, owner_frame=0.30 + 0.66, resumed=1.78, p_max=0.70)
        self.assertTrue(verdict["primary"], verdict)
        self.assertTrue(verdict["secondary"], verdict)

    def test_a_resume_after_the_retransmission_the_design_allows_fails(self):
        # A design below the 3R retry allows 3R: answered only at 7R is a miss.
        verdict = bound.ha_judge_takeover(0.30, self.SENDS, owner_frame=0.30 + 0.50, resumed=1.78, p_max=0.60)
        self.assertTrue(verdict["primary"], verdict)
        self.assertFalse(verdict["secondary"], verdict)

    def test_a_server_answer_held_like_the_measured_one_passes_a_slower_one_fails(self):
        # Measured: a SYN-proxied server ACKs the 3R retransmission at once and
        # sends its data answer up to 101 ms later.
        retry = self.SENDS[2]
        held = bound.ha_judge_takeover(0.30, self.SENDS, owner_frame=0.30 + 0.37, resumed=retry + 0.101, p_max=0.47)
        self.assertTrue(held["secondary"], held)
        slower = bound.ha_judge_takeover(0.30, self.SENDS, owner_frame=0.30 + 0.37, resumed=retry + 0.16, p_max=0.47)
        self.assertFalse(slower["secondary"], slower)
        self.assertAlmostEqual(bound.HA_SERVER_ANSWER_MAX, 0.15)

    def test_retransmissions_beyond_the_capture_follow_the_doubling(self):
        self.assertAlmostEqual(bound.ha_retry_at_or_after([0.30, 0.51], 1.0), 1.77, places=6)
        self.assertAlmostEqual(bound.ha_retry_at_or_after(self.SENDS, 0.60), 0.93, places=6)

    def test_every_fault_class_has_a_design_takeover_from_named_terms(self):
        for fault in ("agent crash", "vm pause", "wren crash", "link loss"):
            self.assertGreater(bound.HA_TAKEOVER_DESIGN[fault], 0, fault)
        # An agent crash waits for the dead agent's report to go stale first.
        self.assertAlmostEqual(
            bound.HA_TAKEOVER_DESIGN["agent crash"] - bound.HA_TAKEOVER_DESIGN["vm pause"],
            bound.HA_AGENT_FRESH + bound.HA_COORDINATOR_POLL + bound.HA_WITNESS_IO,
            places=6,
        )


class Capture(unittest.TestCase):
    LOST = "1.0 a > b, x: 10.2.0.10.5 > 10.1.0.10.8443: Flags [P.], seq 100:105, ack 1, length 5"
    ARP = "1.0 nm > ff, ARP, Request who-has 10.2.0.100 tell 10.2.0.100, length 28"
    ANSWER = "1.0 s > a, x: 10.1.0.10.8443 > 10.2.0.10.5: Flags [P.], seq 1:6, ack 105, length 5"

    def test_the_lost_segment_its_sends_the_owners_arp_and_the_answer(self):
        packets = [(0.10, "m", self.LOST), (0.31, "m", self.LOST), (0.50, "nm", self.ARP),
                   (0.73, "m", self.LOST), (0.76, "s", self.ANSWER)]
        found = bound._ha_lost_segment(packets, "nm", "10.2.0.100", "10.1.0.10", 8443)
        self.assertEqual(found, (0.10, [0.10, 0.31, 0.73], 0.76, 0.50))

    def test_an_answer_not_yet_in_the_capture_is_none_not_a_miss(self):
        packets = [(0.10, "m", self.LOST), (0.31, "m", self.LOST)]
        found = bound._ha_lost_segment(packets, "nm", "10.2.0.100", "10.1.0.10", 8443)
        self.assertIsNone(found[2])


if __name__ == "__main__":
    unittest.main()
