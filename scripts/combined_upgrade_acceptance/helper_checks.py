#!/usr/bin/env python3
"""Cheap offline codec/arithmetic/helper checks; no runtime acceptance authority."""
import hashlib
import json
from pathlib import Path
import importlib.util
import sys
_io_spec = importlib.util.spec_from_file_location("combined_io", Path(__file__).with_name("combined_io.py"))
io = importlib.util.module_from_spec(_io_spec)
sys.dont_write_bytecode = True
_io_spec.loader.exec_module(io)

SOURCE = Path(__file__).resolve().parents[2]


def encoded(value):
    if value < 64:
        return bytes([value << 2])
    if value < 16384:
        return (value << 2 | 1).to_bytes(2, "little")
    return (value << 2 | 2).to_bytes(4, "little")


def main():
    vectors = json.loads((SOURCE / "formal/asert/fixtures/asert-v1.json").read_text())
    accepted = 0
    for row in vectors["cases"]:
        if row["expected_result"] != "accepted":
            continue
        actual = io.asert_bits(row["anchor_height"], row["anchor_parent_timestamp_ms"],
            row["anchor_bits"], row["parent_height"], row["parent_timestamp_ms"],
            row["spacing_ms"], row["half_life_ms"])
        io.require(actual == row["expected_bits"], "Python bigint oracle disagrees with formal fixture: " + row["name"])
        accepted += 1
    io.require(accepted > 5, "insufficient oracle fixture cases")
    for value in (0, 63, 64, 16383, 16384, 177900):
        raw = encoded(value)
        io.require(io.compact(raw, 0) == (value, len(raw)), "SCALE compact roundtrip")
    for raw in (b"\x01\x00", b"\x02\x00\x00\x00", b"\x03\x00\x00\x00\x00"):
        try:
            io.compact(raw, 0)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("noncanonical SCALE accepted")

    # Constructed bytes qualify these framing functions only, never a proof.
    carrier = bytearray(io.FIXED_BYTES + 4)
    carrier[:8] = b"HGPSLC02"
    carrier[8:24] = io.IDENTITY
    carrier[200:208] = (1000).to_bytes(8, "little")
    carrier[io.FIXED_BYTES:] = b"SMZL"
    header = bytearray(104)
    header[48:56] = bytes.fromhex("0c00070001000f00")
    action = bytes(header) + b"\x00" * 4 + encoded(len(carrier)) + carrier + (1000).to_bytes(8, "little") + b"\x00"
    io.require(io.public_args(action) == carrier, "carrier extraction")
    body = encoded(1) + encoded(len(action)) + action
    io.require(io.decode_action_vec(body) == [action], "canonical action body extraction")
    try:
        io.decode_action_vec(body + b"\x00")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("trailing action body byte accepted")

    prefix, suffix = b"offline helper check", b"no chain authority"
    merkle = hashlib.sha256(hashlib.sha256(prefix + bytes(28) + suffix).digest()).digest()
    header80 = (0x20000000).to_bytes(4, "little") + bytes(32) + merkle + (1).to_bytes(4, "little") + (0x207fffff).to_bytes(4, "little") + bytes(4)
    job = {"algorithm": "sha256d-bitcoin80", "job_id": "00" * 16,
        "header80": header80.hex(), "coinbase_prefix": prefix.hex(),
        "coinbase_suffix": suffix.hex(), "ntime": "00000001", "nbits": "207fffff",
        "target": "0x" + io.target_from_bits(0x207fffff).to_bytes(32, "big").hex()}
    solution, measured = io.solve_job(job, 0x20000020, 1024, 2)
    solved = bytes.fromhex(measured["header80"])
    digest = hashlib.sha256(hashlib.sha256(solved).digest()).digest()[::-1]
    io.require(measured["work_hash"] == "0x" + digest.hex() and int(solution["nonce"], 16) + 1 == measured["attempts"], "exact80 helper hash/nonce")
    print(json.dumps({"schema": "hegemon.combined-acceptance.offline-helper-checks.v1",
        "accepted_formal_asert_fixture_cases": accepted, "codec_checks": "PASS",
        "single_thread_python_solver_helper": "PASS", "runtime_acceptance": False,
        "nodes_started": 0, "proofs_generated": 0}))


if __name__ == "__main__":
    main()
