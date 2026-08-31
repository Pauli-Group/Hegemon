#!/usr/bin/env python3
"""Record read-only native-node progress and process-memory observations.

This sampler intentionally polls ``hegemon_miningStatus`` to exercise the
status path under test.  It records operating-system memory counters after
each poll and writes a machine-readable CSV plus JSON summary.  The caller
must provide explicit RSS bounds when using this as an acceptance gate.

The observations do not identify heap-object reachability and therefore do
not prove the absence of logical leaks or allocator retention/fragmentation.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Any
from urllib import error, request
from urllib.parse import urlparse


@dataclass(frozen=True)
class ProcessMemory:
    rss_kib: int
    rss_anon_kib: int | None
    vm_hwm_kib: int | None
    vm_data_kib: int | None
    source: str


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "sample one local hegemon-node process while issuing read-only "
            "latest-block and mining-status RPCs"
        )
    )
    parser.add_argument("--pid", required=True, type=positive_int)
    parser.add_argument(
        "--rpc-url", default="http://127.0.0.1:9944", help="loopback RPC URL"
    )
    parser.add_argument("--output", required=True, type=Path, help="CSV output path")
    parser.add_argument(
        "--summary-output",
        type=Path,
        help="JSON summary path (default: <output>.summary.json)",
    )
    parser.add_argument("--warmup-samples", type=nonnegative_int, default=12)
    parser.add_argument("--samples", type=positive_int, default=60)
    parser.add_argument("--interval-seconds", type=positive_float, default=5.0)
    parser.add_argument(
        "--status-polls-per-sample",
        type=nonnegative_int,
        default=1,
        help="read-only hegemon_miningStatus calls before each memory sample",
    )
    parser.add_argument("--rpc-timeout-seconds", type=positive_float, default=5.0)
    parser.add_argument("--min-height-gain", type=nonnegative_int, default=1)
    parser.add_argument("--max-rss-growth-kib", type=nonnegative_int)
    parser.add_argument("--max-rss-envelope-kib", type=nonnegative_int)
    parser.add_argument("--max-hwm-growth-kib", type=nonnegative_int)
    parser.add_argument("--require-mining", action="store_true")
    parser.add_argument("--require-gate-open", action="store_true")
    parser.add_argument("--require-not-syncing", action="store_true")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing output files instead of failing closed",
    )
    return parser.parse_args()


def parse_kib_status(path: Path) -> ProcessMemory:
    values: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, raw = line.partition(":")
        if not separator or key not in {"VmRSS", "RssAnon", "VmHWM", "VmData"}:
            continue
        fields = raw.split()
        if len(fields) != 2 or fields[1] != "kB":
            raise RuntimeError(f"unexpected {key} format in {path}: {raw!r}")
        values[key] = int(fields[0])
    if "VmRSS" not in values:
        raise RuntimeError(f"VmRSS missing from {path}")
    return ProcessMemory(
        rss_kib=values["VmRSS"],
        rss_anon_kib=values.get("RssAnon"),
        vm_hwm_kib=values.get("VmHWM"),
        vm_data_kib=values.get("VmData"),
        source="linux-proc-status",
    )


def read_process_memory(pid: int) -> ProcessMemory:
    proc_status = Path(f"/proc/{pid}/status")
    if proc_status.is_file():
        return parse_kib_status(proc_status)

    completed = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(pid)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        detail = completed.stderr.strip() or "process not found"
        raise RuntimeError(f"cannot read RSS for pid {pid}: {detail}")
    return ProcessMemory(
        rss_kib=int(completed.stdout.strip()),
        rss_anon_kib=None,
        vm_hwm_kib=None,
        vm_data_kib=None,
        source="ps-rss",
    )


def process_identity(pid: int) -> str:
    stat_path = Path(f"/proc/{pid}/stat")
    if stat_path.is_file():
        raw = stat_path.read_text(encoding="utf-8").strip()
        closing = raw.rfind(")")
        if closing < 0:
            raise RuntimeError(f"cannot parse {stat_path}")
        fields_from_three = raw[closing + 2 :].split()
        if len(fields_from_three) <= 19:
            raise RuntimeError(f"start-time field missing from {stat_path}")
        return f"linux-start-ticks:{fields_from_three[19]}"

    completed = subprocess.run(
        ["ps", "-o", "lstart=", "-p", str(pid)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        detail = completed.stderr.strip() or "process not found"
        raise RuntimeError(f"cannot identify pid {pid}: {detail}")
    return f"ps-start:{completed.stdout.strip()}"


def process_command(pid: int) -> str:
    proc_comm = Path(f"/proc/{pid}/comm")
    if proc_comm.is_file():
        return proc_comm.read_text(encoding="utf-8").strip()
    completed = subprocess.run(
        ["ps", "-o", "comm=", "-p", str(pid)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        detail = completed.stderr.strip() or "process not found"
        raise RuntimeError(f"cannot read command for pid {pid}: {detail}")
    return completed.stdout.strip()


def rpc_call(url: str, method: str, timeout: float) -> Any:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": []},
        separators=(",", ":"),
    ).encode("utf-8")
    rpc_request = request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(rpc_request, timeout=timeout) as response:
            decoded = json.load(response)
    except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{method} RPC failed: {exc}") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{method} returned a non-object JSON-RPC response")
    if decoded.get("error") is not None:
        raise RuntimeError(f"{method} returned JSON-RPC error: {decoded['error']}")
    if "result" not in decoded:
        raise RuntimeError(f"{method} response has no result")
    return decoded["result"]


def integer_field(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise RuntimeError(f"{field} must be an integer, got boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise RuntimeError(f"{field} must be an integer, got {type(value).__name__}")


def optional_integer_field(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return integer_field(value, field)


def open_output(path: Path, overwrite: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w" if overwrite else "x", encoding="utf-8", newline="")


def sample_row(
    *,
    args: argparse.Namespace,
    identity: str,
    phase: str,
    sample_index: int,
    started: float,
    cumulative_status_polls: int,
) -> tuple[dict[str, Any], int]:
    status: dict[str, Any] | None = None
    poll_count = 0 if phase == "baseline" else args.status_polls_per_sample
    for _ in range(poll_count):
        raw_status = rpc_call(args.rpc_url, "hegemon_miningStatus", args.rpc_timeout_seconds)
        if not isinstance(raw_status, dict):
            raise RuntimeError("hegemon_miningStatus result must be an object")
        status = raw_status
        cumulative_status_polls += 1

    latest = rpc_call(args.rpc_url, "hegemon_latestBlock", args.rpc_timeout_seconds)
    if not isinstance(latest, dict):
        raise RuntimeError("hegemon_latestBlock result must be an object")
    if process_identity(args.pid) != identity:
        raise RuntimeError(f"pid {args.pid} changed identity during sampling")
    memory = read_process_memory(args.pid)

    row: dict[str, Any] = {
        "utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "phase": phase,
        "sample": sample_index,
        "pid": args.pid,
        "process_identity": identity,
        **asdict(memory),
        "height": integer_field(latest.get("height"), "latest.height"),
        "best_hash": latest.get("hash"),
        "status_polls_cumulative": cumulative_status_polls,
        "status_block_height": None,
        "sync_target_height": None,
        "syncing": None,
        "mining_sync_gate_open": None,
        "is_mining": None,
        "hash_rate": None,
    }
    if status is not None:
        row.update(
            {
                "status_block_height": optional_integer_field(
                    status.get("block_height"), "status.block_height"
                ),
                "sync_target_height": optional_integer_field(
                    status.get("sync_target_height"), "status.sync_target_height"
                ),
                "syncing": status.get("syncing"),
                "mining_sync_gate_open": status.get("mining_sync_gate_open"),
                "is_mining": status.get("is_mining"),
                "hash_rate": status.get("hash_rate"),
            }
        )
    return row, cumulative_status_polls


def summarize(
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    identity: str,
    command: str,
) -> tuple[dict[str, Any], list[str]]:
    measured = [row for row in rows if row["phase"] == "measure"]
    rss_values = [int(row["rss_kib"]) for row in measured]
    heights = [int(row["height"]) for row in measured]
    hwm_values = [row["vm_hwm_kib"] for row in measured]
    numeric_hwm = [int(value) for value in hwm_values if value is not None]

    rss_growth = rss_values[-1] - rss_values[0]
    rss_envelope = max(rss_values) - min(rss_values)
    height_gain = heights[-1] - heights[0]
    hwm_growth = numeric_hwm[-1] - numeric_hwm[0] if numeric_hwm else None

    failures: list[str] = []
    if height_gain < args.min_height_gain:
        failures.append(
            f"height gain {height_gain} is below required {args.min_height_gain}"
        )
    if (
        args.max_rss_growth_kib is not None
        and rss_growth > args.max_rss_growth_kib
    ):
        failures.append(
            f"RSS growth {rss_growth} KiB exceeds {args.max_rss_growth_kib} KiB"
        )
    if (
        args.max_rss_envelope_kib is not None
        and rss_envelope > args.max_rss_envelope_kib
    ):
        failures.append(
            f"RSS envelope {rss_envelope} KiB exceeds "
            f"{args.max_rss_envelope_kib} KiB"
        )
    if (
        args.max_hwm_growth_kib is not None
        and hwm_growth is not None
        and hwm_growth > args.max_hwm_growth_kib
    ):
        failures.append(
            f"high-water growth {hwm_growth} KiB exceeds "
            f"{args.max_hwm_growth_kib} KiB"
        )
    if args.max_hwm_growth_kib is not None and hwm_growth is None:
        failures.append("high-water bound requested but this OS exposes no VmHWM")
    if args.require_gate_open and any(
        row["mining_sync_gate_open"] is not True for row in measured
    ):
        failures.append("mining sync gate was not open for every measured sample")
    if args.require_mining and any(row["is_mining"] is not True for row in measured):
        failures.append("node did not report active mining for every measured sample")
    if args.require_not_syncing and any(row["syncing"] is not False for row in measured):
        failures.append("node reported syncing during at least one measured sample")

    summary = {
        "schema": "hegemon-native-node-memory-progress-v1",
        "pid": args.pid,
        "process_identity": identity,
        "process_command": command,
        "platform": platform.platform(),
        "rpc_url": args.rpc_url,
        "warmup_samples": args.warmup_samples,
        "measured_samples": args.samples,
        "interval_seconds": args.interval_seconds,
        "status_polls_per_sample": args.status_polls_per_sample,
        "status_rpc_polled": args.status_polls_per_sample > 0,
        "height_start": heights[0],
        "height_end": heights[-1],
        "height_gain": height_gain,
        "rss_start_kib": rss_values[0],
        "rss_end_kib": rss_values[-1],
        "rss_min_kib": min(rss_values),
        "rss_max_kib": max(rss_values),
        "rss_growth_kib": rss_growth,
        "rss_envelope_kib": rss_envelope,
        "hwm_growth_kib": hwm_growth,
        "limits": {
            "min_height_gain": args.min_height_gain,
            "max_rss_growth_kib": args.max_rss_growth_kib,
            "max_rss_envelope_kib": args.max_rss_envelope_kib,
            "max_hwm_growth_kib": args.max_hwm_growth_kib,
            "require_mining": args.require_mining,
            "require_gate_open": args.require_gate_open,
            "require_not_syncing": args.require_not_syncing,
        },
        "passed": not failures,
        "failures": failures,
        "claim_boundary": {
            "measured": (
                "OS process RSS and, on Linux, RssAnon/VmHWM/VmData after the "
                "recorded read-only RPC workload"
            ),
            "not_proven": (
                "heap-object reachability, absence of every logical leak, or "
                "allocator retention/fragmentation behavior outside this run; "
                "the caller-supplied PID is not independently matched to the "
                "loopback RPC listener"
            ),
        },
    }
    return summary, failures


def main() -> int:
    args = parse_args()
    parsed_rpc_url = urlparse(args.rpc_url)
    if parsed_rpc_url.scheme not in {"http", "https"} or parsed_rpc_url.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise SystemExit("--rpc-url must identify a loopback HTTP(S) endpoint")

    summary_path = args.summary_output or Path(f"{args.output}.summary.json")
    if args.output.resolve() == summary_path.resolve():
        raise SystemExit("CSV and summary output paths must differ")
    if not args.overwrite:
        existing = [path for path in (args.output, summary_path) if path.exists()]
        if existing:
            rendered = ", ".join(str(path) for path in existing)
            raise SystemExit(f"refusing to overwrite existing output: {rendered}")
    identity = process_identity(args.pid)
    command = process_command(args.pid)
    if Path(command).name != "hegemon-node":
        raise SystemExit(
            f"--pid must identify hegemon-node; pid {args.pid} command is {command!r}"
        )
    started = time.monotonic()
    rows: list[dict[str, Any]] = []
    cumulative_status_polls = 0

    fieldnames = [
        "utc",
        "elapsed_seconds",
        "phase",
        "sample",
        "pid",
        "process_identity",
        "rss_kib",
        "rss_anon_kib",
        "vm_hwm_kib",
        "vm_data_kib",
        "source",
        "height",
        "best_hash",
        "status_polls_cumulative",
        "status_block_height",
        "sync_target_height",
        "syncing",
        "mining_sync_gate_open",
        "is_mining",
        "hash_rate",
    ]

    try:
        with open_output(args.output, args.overwrite) as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            baseline, cumulative_status_polls = sample_row(
                args=args,
                identity=identity,
                phase="baseline",
                sample_index=0,
                started=started,
                cumulative_status_polls=cumulative_status_polls,
            )
            rows.append(baseline)
            writer.writerow(baseline)
            csv_file.flush()

            phases = ["warmup"] * args.warmup_samples + ["measure"] * args.samples
            next_sample_at = time.monotonic()
            phase_indexes = {"warmup": 0, "measure": 0}
            for phase in phases:
                delay = next_sample_at - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                phase_indexes[phase] += 1
                row, cumulative_status_polls = sample_row(
                    args=args,
                    identity=identity,
                    phase=phase,
                    sample_index=phase_indexes[phase],
                    started=started,
                    cumulative_status_polls=cumulative_status_polls,
                )
                rows.append(row)
                writer.writerow(row)
                csv_file.flush()
                next_sample_at += args.interval_seconds
    except FileExistsError as exc:
        raise SystemExit(f"refusing to overwrite existing output: {exc.filename}") from exc

    summary, failures = summarize(args, rows, identity, command)
    try:
        with open_output(summary_path, args.overwrite) as summary_file:
            json.dump(summary, summary_file, indent=2, sort_keys=True)
            summary_file.write("\n")
    except FileExistsError as exc:
        raise SystemExit(f"refusing to overwrite existing output: {exc.filename}") from exc

    print(json.dumps(summary, indent=2, sort_keys=True))
    if failures:
        for failure in failures:
            print(f"measurement failure: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
