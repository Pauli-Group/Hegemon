#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_consensus_hash_profile as checker


def expect_rejected(callable_, expected: str) -> None:
    try:
        callable_()
    except SystemExit as error:
        if expected not in str(error):
            raise SystemExit(f"profile rejected for the wrong reason: {error}") from error
        return
    raise SystemExit("invalid consensus hash profile unexpectedly passed")


def main() -> None:
    checker.check_foundation(ROOT)

    # The mutation fixture intentionally contains only a tiny subset of the
    # repository. Its local exception tables are populated explicitly below;
    # production entries remain stale-fail-closed in the real checkout.
    checker.V3_NARROW_HASH_LINE_ALLOWLIST.clear()
    checker.V3_APPROVED_HASH_FUNCTION_ALLOWLIST.clear()
    checker.V3_APPROVED_FUNCTION_CALLERS.clear()
    checker.V3_UNREACHABLE_LEGACY_FUNCTION_ALLOWLIST.clear()

    with tempfile.TemporaryDirectory(prefix="consensus-hash-profile-") as raw:
        fixture = Path(raw)
        central = fixture / checker.CENTRAL
        central.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / checker.CENTRAL, central)
        _, domains = checker.check_foundation(fixture)

        canonical_central = central.read_text(encoding="utf-8")
        central.write_text(
            canonical_central + "\nfn fourth_direct() { let _ = Blake2b::<U48>::new(); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.check_foundation(fixture),
            "exactly three reviewed direct BLAKE2b-384 constructors",
        )
        central.write_text(canonical_central, encoding="utf-8")

        duplicate = fixture / "node/src/native/pow.rs"
        duplicate.parent.mkdir(parents=True)
        duplicate.write_text(
            "fn duplicate() { let _ = Blake2b::<U48>::new(); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.check_foundation(fixture),
            "direct BLAKE2b-384 implementation outside central crate",
        )

        duplicate.write_text(
            "#[cfg(test)]\n"
            "mod tests { fn reference() { let _ = Blake2b::<U48>::new(); } }\n",
            encoding="utf-8",
        )
        checker.check_foundation(fixture)

        duplicate.write_text(
            "#[cfg(test)]\n"
            "mod tests { fn reference() { let _ = Blake2b::<U48>::new(); } }\n"
            "fn production_after_tests() { let _ = Blake2b::<U48>::new(); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.check_foundation(fixture),
            "node/src/native/pow.rs:3",
        )

        duplicate.write_text(
            "use blake3::Hasher as AcceptedHash;\n"
            "fn active() { let _ = AcceptedHash::new(); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "active BLAKE3 token",
        )

        duplicate.write_text(
            "use blake2::Blake2b as WorkHash;\n"
            "fn active() { let _ = WorkHash::new(); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "active raw/direct BLAKE2b token",
        )

        duplicate.write_text(
            "use hegemon_hash384::{blake2b_384_domain_hash, Blake2b384DomainHasher};\n"
            "fn active() {\n"
            "  let _ = blake2b_384_domain_hash(b\"d\", [b\"x\".as_slice()]);\n"
            "  let _ = Blake2b384DomainHasher::new(b\"d\");\n"
            "}\n",
            encoding="utf-8",
        )
        checker.enforce_v3(fixture, domains)

        duplicate.write_text(
            "use crypto::hashes::sha256 as accepted_hash;\n"
            "fn active() { let _ = accepted_hash(b\"x\"); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "active SHA-256/SHA256d token",
        )

        duplicate.write_text(
            "fn blake3_384(input: &[u8]) -> [u8; 48] { unimplemented!() }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "active BLAKE3 token",
        )

        duplicate.write_text(
            "fn active_poseidon_wire(_: PoseidonDigest56) {}\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "active forbidden active PoseidonDigest56 wire token",
        )

        duplicate.write_text(
            "#[cfg(test)]\n"
            "mod tests { fn ignored() { let _ = blake3::hash(b\"x\"); } }\n"
            "fn production_after_tests() { let _ = blake3::hash(b\"x\"); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "node/src/native/pow.rs:3: active BLAKE3 token",
        )

        duplicate.write_text(
            'const BAD: &[u8] = b"hegemon.consensus.block-id.v3";\n',
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "duplicated central domain literal",
        )

        duplicate.write_text(
            '// b"hegemon.consensus.block-id.v3" and blake3::hash are comments\n'
            'const MESSAGE: &str = "blake3::hash and // are inert text";\n',
            encoding="utf-8",
        )
        checker.enforce_v3(fixture, domains)

        test_only = fixture / "node/src/native/tests.rs"
        test_only.write_text("fn ignored() { let _ = blake3::hash(b\"x\"); }\n", encoding="utf-8")
        checker.enforce_v3(fixture, domains)

        scoped = fixture / "crypto/src/hashes.rs"
        scoped.parent.mkdir(parents=True, exist_ok=True)
        scoped.write_text(
            "fn fixed_nums() { let _ = sha256(b\"fixed\"); }\n"
            "fn reviewed_caller() { fixed_nums(); }\n",
            encoding="utf-8",
        )
        fixed_key = ("crypto/src/hashes.rs", "fixed_nums", "SHA-256/SHA256d")
        checker.V3_APPROVED_HASH_FUNCTION_ALLOWLIST[fixed_key] = "mutation-test fixed input"
        checker.V3_APPROVED_FUNCTION_CALLERS[("crypto/src/hashes.rs", "fixed_nums")] = frozenset(
            {"reviewed_caller"}
        )
        checker.enforce_v3(fixture, domains)

        scoped.write_text(
            "fn fixed_nums() { let _ = sha256(b\"fixed\"); }\n"
            "fn reviewed_caller() { fixed_nums(); }\n"
            "fn active_acceptance() { fixed_nums(); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "caller drift; unexpected=['active_acceptance']",
        )
        checker.V3_APPROVED_HASH_FUNCTION_ALLOWLIST.clear()
        checker.V3_APPROVED_FUNCTION_CALLERS.clear()

        scoped.write_text(
            "fn legacy_digest() { let _ = blake3::hash(b\"legacy\"); }\n",
            encoding="utf-8",
        )
        legacy_key = ("crypto/src/hashes.rs", "legacy_digest", "BLAKE3")
        checker.V3_UNREACHABLE_LEGACY_FUNCTION_ALLOWLIST[legacy_key] = (
            "mutation-test private unreachable diagnostic"
        )
        checker.enforce_v3(fixture, domains)

        scoped.write_text(
            "fn legacy_digest() { let _ = blake3::hash(b\"legacy\"); }\n"
            "fn active_acceptance() { legacy_digest(); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "unreachable legacy function legacy_digest called by active_acceptance",
        )

        scoped.write_text(
            "pub fn legacy_digest() { let _ = blake3::hash(b\"legacy\"); }\n",
            encoding="utf-8",
        )
        expect_rejected(
            lambda: checker.enforce_v3(fixture, domains),
            "legacy function crypto/src/hashes.rs::legacy_digest must be private",
        )

    print("consensus hash profile checker tests: PASS")


if __name__ == "__main__":
    main()
