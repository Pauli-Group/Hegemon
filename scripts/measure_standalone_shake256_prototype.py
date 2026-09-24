#!/usr/bin/env python3
"""Measure and fail-close a standalone SHAKE256 proof prototype.

The backend must emit one JSON object on stdout.  This wrapper deliberately
keeps prototype measurements separate from release qualification: an upstream
proof can round-trip correctly while the Hegemon-specific zero-knowledge and
composed post-quantum arguments are still incomplete.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, NoReturn, Sequence


BACKEND_SCHEMA = "hegemon.standalone-shake256.backend-measurement.v1"
REPORT_SCHEMA = "hegemon.standalone-shake256.benchmark-report.v1"
PROFILE = "pay1x2"

BLOCK_BYTES = 64 * 1024 * 1024
BLOCK_FIXED_BYTES = 2_525
NON_PROOF_ACTION_BYTES = 4_967
PROOF_TARGET_BYTES = 512 * 1024
ARTIFACT_HARD_CAP_BYTES = 1 * 1024 * 1024
POST_QUANTUM_BITS_MIN = 128
FRI_CLASSICAL_BITS_MIN = 264

SEMANTIC_HASH = "SHAKE256-448"
PROOF_HASH = "SHAKE256-512"
CHALLENGE_FIELD = "GF(2^384)"

DEFAULT_MIN_FREE_BYTES = 8 * 1024 * 1024 * 1024
BACKEND_OUTPUT_CAP_BYTES = 8 * 1024 * 1024


class MeasurementError(ValueError):
    """The backend output or measurement environment is invalid."""


def _fail(message: str) -> NoReturn:
    raise MeasurementError(message)


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{name} must be a JSON object")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{name} must be a non-empty string")
    return value


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        _fail(f"{name} must be a boolean")
    return value


def _integer(value: Any, name: str, *, positive: bool = False) -> int:
    if type(value) is not int:
        _fail(f"{name} must be an integer")
    if value < 0 or (positive and value == 0):
        qualifier = "positive" if positive else "non-negative"
        _fail(f"{name} must be {qualifier}")
    return value


def _number(value: Any, name: str) -> float:
    if type(value) not in (int, float) or value < 0:
        _fail(f"{name} must be a finite non-negative number")
    try:
        result = float(value)
    except OverflowError:
        _fail(f"{name} must be a finite non-negative number")
    if not math.isfinite(result):
        _fail(f"{name} must be a finite non-negative number")
    return result


def _optional_integer(value: Any, name: str) -> int | None:
    if value is None:
        return None
    return _integer(value, name, positive=True)


def _optional_number(value: Any, name: str) -> float | None:
    if value is None:
        return None
    return _number(value, name)


def validate_backend_payload(payload: Any) -> dict[str, Any]:
    """Return a normalized backend measurement or reject it.

    Extra object keys are retained so a backend can publish provenance such as
    its pinned commit.  Every field used for an admission decision is parsed
    here with an exact type and explicit bound.
    """

    root = _object(payload, "backend result")
    if _string(root.get("schema"), "schema") != BACKEND_SCHEMA:
        _fail(f"schema must equal {BACKEND_SCHEMA!r}")
    if _string(root.get("profile"), "profile") != PROFILE:
        _fail(f"profile must equal {PROFILE!r}")

    canonical_proof_bytes = _integer(
        root.get("canonical_proof_bytes"), "canonical_proof_bytes", positive=True
    )
    envelope_bytes = _integer(root.get("envelope_bytes"), "envelope_bytes", positive=True)
    if envelope_bytes < canonical_proof_bytes:
        _fail("envelope_bytes cannot be smaller than canonical_proof_bytes")

    prove_ms = _number(root.get("prove_ms"), "prove_ms")
    verify_ms = _number(root.get("verify_ms"), "verify_ms")
    shake256_permutations = _integer(
        root.get("shake256_permutations"), "shake256_permutations", positive=True
    )
    peak_rss_bytes = _optional_integer(root.get("peak_rss_bytes"), "peak_rss_bytes")

    security = _object(root.get("security_profile"), "security_profile")
    security_status = _string(security.get("status"), "security_profile.status")
    if security_status not in {"supported", "prototype", "unsupported"}:
        _fail("security_profile.status must be supported, prototype, or unsupported")
    composed_pq_bits = _optional_number(
        security.get("composed_pq_bits"), "security_profile.composed_pq_bits"
    )
    zero_knowledge = _bool(security.get("zero_knowledge"), "security_profile.zero_knowledge")

    verification = _object(root.get("verification"), "verification")
    valid = _bool(verification.get("valid"), "verification.valid")
    mutation_rejected = _bool(
        verification.get("mutation_rejected"), "verification.mutation_rejected"
    )
    canonical_roundtrip = _bool(
        verification.get("canonical_roundtrip"), "verification.canonical_roundtrip"
    )

    normalized = dict(root)
    normalized.update(
        {
            "schema": BACKEND_SCHEMA,
            "profile": PROFILE,
            "canonical_proof_bytes": canonical_proof_bytes,
            "envelope_bytes": envelope_bytes,
            "prove_ms": prove_ms,
            "verify_ms": verify_ms,
            "shake256_permutations": shake256_permutations,
            "peak_rss_bytes": peak_rss_bytes,
            "security_profile": {
                **security,
                "status": security_status,
                "composed_pq_bits": composed_pq_bits,
                "zero_knowledge": zero_knowledge,
            },
            "verification": {
                **verification,
                "valid": valid,
                "mutation_rejected": mutation_rejected,
                "canonical_roundtrip": canonical_roundtrip,
            },
        }
    )
    return normalized


def _strict_security_failures(security: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if security["status"] != "supported":
        failures.append(f"security profile status is {security['status']!r}, not 'supported'")
    if security.get("release_qualified") is not True:
        failures.append("security profile is not Hegemon release-qualified")
    if security.get("semantic_hash") != SEMANTIC_HASH:
        failures.append(f"semantic hash is not {SEMANTIC_HASH}")
    if security.get("proof_hash") != PROOF_HASH:
        failures.append(f"proof hash is not {PROOF_HASH}")
    if security.get("challenge_field") != CHALLENGE_FIELD:
        failures.append(f"challenge field is not {CHALLENGE_FIELD}")
    fri_classical_bits = security.get("fri_classical_bits")
    if type(fri_classical_bits) is not int or fri_classical_bits < FRI_CLASSICAL_BITS_MIN:
        failures.append(f"FRI classical target is below {FRI_CLASSICAL_BITS_MIN} bits")
    if security.get("qrom_accounting_complete") is not True:
        failures.append("composed QROM accounting is incomplete")
    if security["composed_pq_bits"] is None or security["composed_pq_bits"] < POST_QUANTUM_BITS_MIN:
        failures.append(f"composed post-quantum security is below {POST_QUANTUM_BITS_MIN} bits")
    if security["zero_knowledge"] is not True:
        failures.append("zero knowledge is not established for the measured relation")
    return failures


def capacity_for_envelope(envelope_bytes: int) -> int:
    denominator = NON_PROOF_ACTION_BYTES + envelope_bytes
    return (BLOCK_BYTES - BLOCK_FIXED_BYTES) // denominator


def build_report(
    backend: dict[str, Any],
    *,
    allow_unsupported_prototype: bool,
    wrapper_wall_ms: float | None = None,
    wrapper_peak_rss_bytes: int | None = None,
    free_bytes_before: int | None = None,
    free_bytes_at_backend_exit: int | None = None,
    free_bytes_after_cleanup: int | None = None,
    minimum_reserve_bytes: int | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Create the canonical report and return policy failures separately."""

    failures: list[str] = []
    if backend["canonical_proof_bytes"] > ARTIFACT_HARD_CAP_BYTES:
        failures.append("canonical proof exceeds the 1 MiB hard cap")
    if backend["envelope_bytes"] > ARTIFACT_HARD_CAP_BYTES:
        failures.append("standalone proof envelope exceeds the 1 MiB hard cap")

    verification = backend["verification"]
    if not verification["valid"]:
        failures.append("backend did not verify its generated proof")
    if not verification["mutation_rejected"]:
        failures.append("backend accepted a deterministic proof mutation")
    if not verification["canonical_roundtrip"]:
        failures.append("backend did not reject non-canonical or trailing proof bytes")

    strict_security_failures = _strict_security_failures(backend["security_profile"])
    prototype_override_used = bool(strict_security_failures and allow_unsupported_prototype)
    if strict_security_failures and not allow_unsupported_prototype:
        failures.extend(strict_security_failures)

    backend_peak = backend["peak_rss_bytes"]
    observed_peaks = [
        value for value in (backend_peak, wrapper_peak_rss_bytes) if value is not None
    ]
    peak_rss_bytes = max(observed_peaks) if observed_peaks else None
    if backend_peak is not None and wrapper_peak_rss_bytes is not None:
        peak_rss_source = "max(backend,rusage_children)"
    elif backend_peak is not None:
        peak_rss_source = "backend"
    elif wrapper_peak_rss_bytes is not None:
        peak_rss_source = "rusage_children"
    else:
        peak_rss_source = None

    accepted = not failures
    if accepted and prototype_override_used:
        mode = "prototype_only"
    elif accepted:
        mode = "strict"
    else:
        mode = "rejected"

    report = {
        "schema": REPORT_SCHEMA,
        "backend_schema": backend["schema"],
        "profile": backend["profile"],
        "measurement": {
            "canonical_proof_bytes": backend["canonical_proof_bytes"],
            "envelope_bytes": backend["envelope_bytes"],
            "prove_ms": backend["prove_ms"],
            "verify_ms": backend["verify_ms"],
            "backend_command_wall_ms": wrapper_wall_ms,
            "peak_rss_bytes": peak_rss_bytes,
            "peak_rss_source": peak_rss_source,
            "shake256_permutations": backend["shake256_permutations"],
        },
        "security_profile": backend["security_profile"],
        "verification": backend["verification"],
        "limits": {
            "proof_target_bytes": PROOF_TARGET_BYTES,
            "artifact_hard_cap_bytes": ARTIFACT_HARD_CAP_BYTES,
            "post_quantum_bits_min": POST_QUANTUM_BITS_MIN,
            "target_met": backend["envelope_bytes"] <= PROOF_TARGET_BYTES,
        },
        "capacity": {
            "block_bytes": BLOCK_BYTES,
            "block_fixed_bytes": BLOCK_FIXED_BYTES,
            "non_proof_action_bytes": NON_PROOF_ACTION_BYTES,
            "actions_per_64mib_block": capacity_for_envelope(backend["envelope_bytes"]),
        },
        "disk": {
            "free_bytes_before": free_bytes_before,
            "free_bytes_at_backend_exit": free_bytes_at_backend_exit,
            "free_bytes_after_cleanup": free_bytes_after_cleanup,
            "minimum_reserve_bytes": minimum_reserve_bytes,
        },
        "policy": {
            "accepted": accepted,
            "mode": mode,
            "prototype_override_used": prototype_override_used,
            "strict_security_failures": strict_security_failures,
            "failures": failures,
        },
    }
    return report, failures


def _reject_json_constant(value: str) -> NoReturn:
    _fail(f"backend JSON contains non-finite constant {value!r}")


def parse_backend_json(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, MeasurementError) as error:
        _fail(f"backend stdout is not one strict JSON object: {error}")
    return validate_backend_payload(payload)


def _free_bytes(paths: Sequence[Path]) -> int:
    values = [shutil.disk_usage(path).free for path in paths]
    if not values:
        _fail("no filesystem path was supplied for disk monitoring")
    return min(values)


def _rusage_maxrss_bytes() -> int | None:
    value = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if value <= 0:
        return None
    # macOS reports bytes; Linux and the BSDs commonly report KiB.  The
    # prototype runs on macOS, while this branch keeps Linux CI usable.
    if sys.platform == "darwin":
        return int(value)
    return int(value) * 1024


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (AttributeError, ProcessLookupError):
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (AttributeError, ProcessLookupError):
            process.kill()
        process.wait()


def run_backend(
    command: Sequence[str],
    *,
    min_free_bytes: int,
    ephemeral_cargo_target: bool,
) -> tuple[dict[str, Any], float, int | None, int, int, int]:
    if not command:
        _fail("backend command is empty")

    cwd = Path.cwd()
    temporary_root = (
        Path("/private/tmp")
        if Path("/private/tmp").is_dir()
        else Path(tempfile.gettempdir())
    )
    with ExitStack() as stack:
        environment = os.environ.copy()
        environment.setdefault("CARGO_INCREMENTAL", "0")
        environment.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
        environment.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")

        monitored_paths = [cwd]
        executable_name = Path(command[0]).name
        if ephemeral_cargo_target and executable_name == "cargo":
            target_dir = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(
                        prefix="hegemon-standalone-shake256-target-", dir=temporary_root
                    )
                )
            )
            environment["CARGO_TARGET_DIR"] = str(target_dir)
            monitored_paths.append(target_dir)

        free_before = _free_bytes(monitored_paths)
        if free_before < min_free_bytes:
            _fail(
                f"refusing to start backend with only {free_before} free bytes; "
                f"minimum is {min_free_bytes}"
            )

        stdout_file = stack.enter_context(tempfile.TemporaryFile(dir=temporary_root))
        stderr_file = stack.enter_context(tempfile.TemporaryFile(dir=temporary_root))
        start = time.perf_counter()
        try:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except OSError as error:
            _fail(f"could not start backend command: {error}")

        abort_reason: str | None = None
        while process.poll() is None:
            if _free_bytes(monitored_paths) < min_free_bytes:
                abort_reason = "backend crossed the minimum free-space reserve"
                break
            if (
                os.fstat(stdout_file.fileno()).st_size > BACKEND_OUTPUT_CAP_BYTES
                or os.fstat(stderr_file.fileno()).st_size > BACKEND_OUTPUT_CAP_BYTES
            ):
                abort_reason = "backend output exceeded the 8 MiB per-stream cap"
                break
            time.sleep(0.1)

        if abort_reason is not None:
            _terminate_process_group(process)
            _fail(abort_reason)

        wall_ms = (time.perf_counter() - start) * 1_000.0
        free_at_backend_exit = _free_bytes(monitored_paths)
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if stdout_size > BACKEND_OUTPUT_CAP_BYTES or stderr_size > BACKEND_OUTPUT_CAP_BYTES:
            _fail("backend output exceeded the 8 MiB per-stream cap")

        stdout_file.seek(0)
        stderr_file.seek(0)
        try:
            stdout = stdout_file.read().decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            _fail(f"backend stdout is not UTF-8: {error}")
        stderr = stderr_file.read().decode("utf-8", errors="replace")
        if process.returncode != 0:
            excerpt = stderr[-4_096:].strip()
            suffix = f": {excerpt}" if excerpt else ""
            _fail(f"backend exited with status {process.returncode}{suffix}")

        backend = parse_backend_json(stdout)
        peak_rss_bytes = _rusage_maxrss_bytes()

    # The ExitStack has now deleted the default ephemeral Cargo target.  Keep
    # this measurement distinct from the low-water mark at backend exit.
    free_after_cleanup = _free_bytes([cwd, temporary_root])
    return (
        backend,
        wall_ms,
        peak_rss_bytes,
        free_before,
        free_at_backend_exit,
        free_after_cleanup,
    )


def _load_backend_file(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        _fail(f"cannot read backend JSON {path}: {error}")
    return parse_backend_json(raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure a standalone SHAKE256 Pay1x2 proof and enforce prototype gates"
    )
    parser.add_argument(
        "--backend-json",
        type=Path,
        help="read an existing backend measurement instead of executing a command",
    )
    parser.add_argument(
        "--allow-unsupported-prototype",
        action="store_true",
        help="permit an explicitly prototype-only security profile; never relaxes the 1 MiB cap",
    )
    parser.add_argument(
        "--min-free-gib",
        type=float,
        default=DEFAULT_MIN_FREE_BYTES / (1024**3),
        help="abort before or during execution if free space drops below this reserve (default: 8)",
    )
    parser.add_argument(
        "--reuse-cargo-target",
        action="store_true",
        help="do not isolate and clean CARGO_TARGET_DIR when the backend command starts with cargo",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="backend command after --; stdout must be one backend-measurement JSON object",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if (args.backend_json is None) == (not command):
        raise SystemExit("provide exactly one of --backend-json or a backend command after --")
    if not math.isfinite(args.min_free_gib) or args.min_free_gib < 0:
        raise SystemExit("--min-free-gib must be a finite non-negative number")
    min_free_bytes = math.ceil(args.min_free_gib * 1024**3)

    try:
        if args.backend_json is not None:
            backend = _load_backend_file(args.backend_json)
            wall_ms = None
            peak_rss_bytes = None
            free_before = shutil.disk_usage(args.backend_json.parent).free
            free_at_backend_exit = free_before
            free_after_cleanup = free_before
        else:
            (
                backend,
                wall_ms,
                peak_rss_bytes,
                free_before,
                free_at_backend_exit,
                free_after_cleanup,
            ) = run_backend(
                command,
                min_free_bytes=min_free_bytes,
                ephemeral_cargo_target=not args.reuse_cargo_target,
            )
        report, failures = build_report(
            backend,
            allow_unsupported_prototype=args.allow_unsupported_prototype,
            wrapper_wall_ms=wall_ms,
            wrapper_peak_rss_bytes=peak_rss_bytes,
            free_bytes_before=free_before,
            free_bytes_at_backend_exit=free_at_backend_exit,
            free_bytes_after_cleanup=free_after_cleanup,
            minimum_reserve_bytes=min_free_bytes,
        )
    except MeasurementError as error:
        print(f"standalone SHAKE256 measurement rejected: {error}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
