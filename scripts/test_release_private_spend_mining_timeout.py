#!/usr/bin/env python3
"""Pure harness timing regressions: no node, build, proof or wallet execution."""
import copy
import math
import types
import unittest
from unittest.mock import patch
import release_private_spend_lifecycle as lifecycle


def status(**changes):
    value = dict(is_mining=True, mining_sync_gate_open=True, syncing=False,
                 block_height=113, next_difficulty=489136962,
                 difficulty=0x207fffff, hash_rate=733223.0)
    value.update(changes)
    return value


class MiningTimeoutTests(unittest.TestCase):
    def test_actual_target_and_observed_rate_get_finite_upper_bound(self):
        target = 0x27a342 << 208
        expected = (2**256 / (target + 1)) / 733223
        self.assertAlmostEqual(expected, 147.77979244748832)
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(), 113, 0), 3600)

    def test_middle_rate_uses_32_intervals_and_rounds_up(self):
        target = 0x27a342 << 208
        expected = math.ceil(32 * (2**256 / (target + 1)) / 2000000)
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(hash_rate=2000000), 113, 0), expected)
        self.assertGreater(expected, 600)
        self.assertLess(expected, 3600)

    def test_fast_rate_preserves_600_second_floor(self):
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(hash_rate=10**18), 113, 0), 600)

    def test_next_candidate_target_is_used_instead_of_parent(self):
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(difficulty=0x01010000), 113, 0), 3600)
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(next_difficulty=0x207fffff), 113, 0), 600)
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(next_difficulty=None), 113, 0), 600)

    def test_invalid_rates_and_nonfinite_inputs_never_extend(self):
        for rate in (None, True, '733223', 0, -1, .5, 10**18+1, 10**500, float('inf'), float('nan')):
            with self.subTest(rate=str(rate)):
                self.assertEqual(lifecycle.mining_no_progress_seconds(status(hash_rate=rate), 113, 0), 600)

    def test_invalid_compact_encodings_never_extend(self):
        for bits in (None, True, '489136962', 0, -1, 2**32, 0x1d800001, 0x2100ffff,
                     0x01000001, 0x01010001, 0x02000100, 0x20000001):
            with self.subTest(bits=bits):
                self.assertEqual(lifecycle.mining_no_progress_seconds(status(next_difficulty=bits), 113, 0), 600)

    def test_smallest_positive_canonical_target_stays_bounded(self):
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(next_difficulty=0x01010000), 113, 0), 3600)

    def test_stale_future_or_malformed_sample_age_never_extends(self):
        for age in (-1, 5.001, True, None, '0', 10**500, float('inf'), float('nan')):
            with self.subTest(age=str(age)):
                self.assertEqual(lifecycle.mining_no_progress_seconds(status(), 113, age), 600)
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(), 113, 5), 3600)

    def test_inactive_syncing_gate_or_height_mismatch_never_extends(self):
        for changes in ({'is_mining':False}, {'syncing':True}, {'mining_sync_gate_open':False},
                        {'block_height':112}, {'block_height':True}, {'block_height':'113'}):
            self.assertEqual(lifecycle.mining_no_progress_seconds(status(**changes), 113, 0), 600)
        self.assertEqual(lifecycle.mining_no_progress_seconds(None, 113, 0), 600)
        self.assertEqual(lifecycle.mining_no_progress_seconds(status(), True, 0), 600)

    def run_wait(self, final_at=None, valid=True, canonical_hash='0x'+'ab'*32, intermediate_at=None):
        clock = types.SimpleNamespace(seconds=0)
        fake_time = types.SimpleNamespace(monotonic=lambda:clock.seconds,
                         sleep=lambda _:setattr(clock, 'seconds', clock.seconds+50))
        def height(_):
            if final_at is not None and clock.seconds>=final_at:return 115
            return 114 if intermediate_at is not None and clock.seconds>=intermediate_at else 113
        def rpc(_, method, params=None):
            if method=='chain_getBlockHash':return canonical_hash
            self.assertEqual(method, 'hegemon_miningStatus')
            return status(block_height=height(None), hash_rate=733223 if valid else 0)
        with patch.object(lifecycle,'time',fake_time), patch.object(lifecycle.h,'height',side_effect=height), patch.object(lifecycle.h,'rpc',side_effect=rpc):
            lifecycle.wait_mining_height('http://unused', 115)
        return clock.seconds

    def test_actual_canonical_block_after_600_seconds_is_allowed(self):
        self.assertEqual(self.run_wait(final_at=700), 700)

    def test_active_telemetry_never_resets_progress_or_exceeds_finite_bound(self):
        with self.assertRaisesRegex(RuntimeError, 'for3600s'):
            self.run_wait()

    def test_invalid_telemetry_preserves_original_timeout(self):
        with self.assertRaisesRegex(RuntimeError, 'for600s'):
            self.run_wait(valid=False)

    def test_only_canonical_progress_resets_timer(self):
        self.assertEqual(self.run_wait(final_at=4200, intermediate_at=700), 4200)
        with self.assertRaisesRegex(RuntimeError, 'no canonical hash'):
            self.run_wait(final_at=700, canonical_hash='not-a-canonical-hash')


if __name__ == '__main__':
    unittest.main()
