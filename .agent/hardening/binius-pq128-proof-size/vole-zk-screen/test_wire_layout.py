#!/usr/bin/env python3

import unittest

from wire_layout import (
    HEADER_BYTES,
    KNOWN_FLAGS,
    Header,
    ParseError,
    parse_header,
    section_slices,
)


class WireLayoutTests(unittest.TestCase):
    def fixture(self) -> tuple[Header, bytes]:
        lengths = (
            912,
            8,
            50,
            8,
            768,
            18_432,
            4_608,
            64,
            64,
            192,
            4,
        )
        total = HEADER_BYTES + sum(lengths)
        header = Header(
            flags=KNOWN_FLAGS,
            total_length=total,
            relation_digest=bytes(range(64)),
            public_words=114,
            private_words=671,
            lambda_bits=384,
            tau=32,
            degree=16,
            small_vole_k=12,
            leaf_commitment_blocks=3,
            consistency_padding_bits=16,
            section_lengths=lengths,
        )
        blob = header.encode() + bytes(sum(lengths))
        return header, blob

    def test_round_trip_and_exact_slices(self) -> None:
        header, blob = self.fixture()
        parsed = parse_header(blob)
        self.assertEqual(parsed, header)
        slices = section_slices(parsed)
        self.assertEqual(slices["public_instance"], slice(HEADER_BYTES, HEADER_BYTES + 912))
        self.assertEqual(slices["counter"].stop, len(blob))

    def test_rejects_trailing_truncated_and_reserved(self) -> None:
        _, blob = self.fixture()
        with self.assertRaises(ParseError):
            parse_header(blob + b"\x00")
        with self.assertRaises(ParseError):
            parse_header(blob[:-1])
        changed = bytearray(blob)
        changed[HEADER_BYTES - 1] = 1
        with self.assertRaises(ParseError):
            parse_header(bytes(changed))


if __name__ == "__main__":
    unittest.main()
