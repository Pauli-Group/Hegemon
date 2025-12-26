#!/usr/bin/env python3
import hashlib
from typing import List, Tuple

FIELD_MODULUS = (1 << 64) - (1 << 32) + 1
POSEIDON_WIDTH = 3
POSEIDON_ROUNDS = 63

DOMAIN_ROUND = b"hegemon-poseidon-round-constants-v1"
DOMAIN_MDS = b"hegemon-poseidon-mds-v1"


def hash_to_field(domain: bytes, label: bytes) -> int:
    counter = 0
    while True:
        hasher = hashlib.sha256()
        hasher.update(domain)
        hasher.update(label)
        hasher.update(counter.to_bytes(4, "big"))
        digest = hasher.digest()
        candidate = int.from_bytes(digest[:8], "big")
        if candidate < FIELD_MODULUS:
            return candidate
        counter += 1


def gen_round_constants() -> List[List[int]]:
    constants: List[List[int]] = []
    for round_idx in range(POSEIDON_ROUNDS):
        row: List[int] = []
        for position in range(POSEIDON_WIDTH):
            label = round_idx.to_bytes(4, "big") + position.to_bytes(4, "big")
            row.append(hash_to_field(DOMAIN_ROUND, label))
        constants.append(row)
    return constants


def gen_mds_matrix() -> Tuple[List[int], List[int], List[List[int]]]:
    xs: List[int] = []
    ys: List[int] = []

    i = 0
    while len(xs) < POSEIDON_WIDTH:
        label = b"x" + i.to_bytes(4, "big")
        value = hash_to_field(DOMAIN_MDS, label)
        if value not in xs:
            xs.append(value)
        i += 1

    j = 0
    while len(ys) < POSEIDON_WIDTH:
        label = b"y" + j.to_bytes(4, "big")
        value = hash_to_field(DOMAIN_MDS, label)
        if value in xs or value in ys:
            j += 1
            continue
        ys.append(value)
        j += 1

    matrix: List[List[int]] = []
    for x in xs:
        row: List[int] = []
        for y in ys:
            denom = (x - y) % FIELD_MODULUS
            inv = pow(denom, FIELD_MODULUS - 2, FIELD_MODULUS)
            row.append(inv)
        matrix.append(row)

    return xs, ys, matrix


def format_rows(rows: List[List[int]], indent: str = "    ") -> str:
    lines = ["["]
    for row in rows:
        values = ", ".join(f"0x{value:016x}" for value in row)
        lines.append(f"{indent}[{values}],")
    lines.append("]")
    return "\n".join(lines)


def main() -> None:
    round_constants = gen_round_constants()
    xs, ys, mds = gen_mds_matrix()

    print("// Auto-generated Poseidon constants (NUMS).")
    print("//")
    print("// Generation scheme:")
    print(f"// - Field modulus: {FIELD_MODULUS} (Goldilocks)")
    print("// - Round constants: SHA-256(domain || round_be32 || pos_be32 || counter_be32)")
    print("// - MDS: Cauchy matrix with x/y from SHA-256(domain || label || counter_be32)")
    print("//")
    print("// Domains:")
    print(f"// - round constants: {DOMAIN_ROUND.decode('ascii')}")
    print(f"// - MDS seeds: {DOMAIN_MDS.decode('ascii')}")
    print("")
    print("use crate::constants::{POSEIDON_ROUNDS, POSEIDON_WIDTH};")
    print("")
    print(f"pub const NUMS_DOMAIN_ROUND_CONSTANTS: &[u8] = b\"{DOMAIN_ROUND.decode('ascii')}\";")
    print(f"pub const NUMS_DOMAIN_MDS: &[u8] = b\"{DOMAIN_MDS.decode('ascii')}\";")
    print("")
    print(f"pub const MDS_X_SEEDS: [u64; {POSEIDON_WIDTH}] = [")
    for value in xs:
        print(f"    0x{value:016x},")
    print("];\n")
    print(f"pub const MDS_Y_SEEDS: [u64; {POSEIDON_WIDTH}] = [")
    for value in ys:
        print(f"    0x{value:016x},")
    print("];\n")
    print("pub const MDS_MATRIX: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] = ")
    print(format_rows(mds))
    print(";\n")
    print("pub const ROUND_CONSTANTS: [[u64; POSEIDON_WIDTH]; POSEIDON_ROUNDS] = ")
    print(format_rows(round_constants))
    print(";")


if __name__ == "__main__":
    main()
