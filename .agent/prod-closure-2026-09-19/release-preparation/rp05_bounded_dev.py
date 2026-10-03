#!/usr/bin/env python3
"""Reviewed bounded-development supervisor for the current RP05 lifecycle lane.

This forward-only guard preserves the canonical R5 config/receipt shape while
raising the reviewed operational ceilings for this RP05 run. It is development
evidence only; it does not authenticate execution or confer release authority.
"""

from __future__ import annotations

import ast
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
REFERENCE_GUARD = WORKSPACE_ROOT / (
    ".agent/artifacts/smallwood-poseidon2-v8-smza/"
    "production-checklist-closure-2026-09-14/external-supervision/"
    "smz9-prod-resume.x2q0SU4G/bounded_dev.py"
)
REFERENCE_GUARD_SHA256 = "d136760ee4c8f701df347f11aa58d3ab037d514625d33af556cda90d3275f4ce"
PROCESS_GROUP_HELPER = WORKSPACE_ROOT / (
    ".agent/artifacts/smallwood-poseidon2-v8-smza/"
    "production-checklist-closure-2026-09-14/external-supervision/"
    "smz9-aeneas-stage1.IgNKumAA/run_stage4_instrumentation_r3.py"
)
PROCESS_GROUP_HELPER_SHA256 = "8dfa95252ded2640ace88b025cad1eb087499ca4e145866cddec338656edb305"
CONTROL = Path("/private/tmp/rp05-smza-bounded-dev-control")
HARD_STOP_MARGIN_SECONDS = 120
MAX_WALL_SECONDS = 3600
MAX_CHILD_STOP_SECONDS = 3500
MAX_PEAK_RSS_BYTES = 16 * 1024**3
MAX_SCRATCH_BYTES = 1024**3
MINIMUM_FREE_BYTES = 20 * 1024**3
MAX_SAMPLE_GAP_SECONDS = 5
ACTIVE_GROUPS: dict[int, Any] = {}
ENV: dict[str, str] = {}
ChildProcessGroup: Any


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"expected a regular, non-symlink file: {path}")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_pinned_process_group_helper() -> None:
    global ChildProcessGroup
    if sha256_file(REFERENCE_GUARD) != REFERENCE_GUARD_SHA256:
        raise RuntimeError("immutable reference guard source changed")
    if sha256_file(PROCESS_GROUP_HELPER) != PROCESS_GROUP_HELPER_SHA256:
        raise RuntimeError("immutable process-group helper source changed")
    tree = ast.parse(PROCESS_GROUP_HELPER.read_text(encoding="utf-8"))
    definitions = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ChildProcessGroup"
    ]
    if len(definitions) != 1:
        raise RuntimeError("pinned process-group source must define exactly one ChildProcessGroup")
    compiled = compile(ast.Module(body=definitions, type_ignores=[]), str(PROCESS_GROUP_HELPER), "exec")
    exec(compiled, globals())
    if not isinstance(ChildProcessGroup, type):
        raise RuntimeError("pinned process-group class was not loaded")


def census(root: Path, mutable: list[Path]) -> int:
    """Count allocated bytes, rejecting symlinks and non-regular files."""
    for attempt in range(3):
        try:
            total = 0
            for directory, dirs, files in os.walk(
                root, followlinks=False,
                onerror=lambda error: (_ for _ in ()).throw(error),
            ):
                for path in [Path(directory)] + [Path(directory) / name for name in files]:
                    info = path.lstat()
                    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                        raise RuntimeError(f"scratch census rejects non-file entry: {path}")
                    total += info.st_blocks * 512
                for name in dirs:
                    if (Path(directory) / name).is_symlink():
                        raise RuntimeError(f"scratch census rejects symlink directory: {name}")
            return total
        except FileNotFoundError as error:
            missing = Path(error.filename or "")
            if (
                error.errno != errno.ENOENT
                or not missing.is_absolute()
                or ".." in missing.parts
                or str(missing) != error.filename
                or not any(missing.is_relative_to(path) for path in mutable)
                or attempt == 2
            ):
                raise
    raise AssertionError("unreachable")


def _validate_limits(limits: dict[str, Any]) -> None:
    expected = (
        "wall_seconds", "child_stop_seconds", "peak_rss_bytes", "stop_group_rss_bytes",
        "scratch_bytes", "stop_scratch_bytes", "minimum_free_bytes", "max_sample_gap_seconds",
    )
    if any(key not in limits for key in expected):
        raise ValueError("bounded RP05 config omitted a required limit")
    integer_keys = expected[:-1]
    if any(type(limits[key]) is not int for key in integer_keys):
        raise ValueError("bounded RP05 integer limits must be integers")
    gap = limits["max_sample_gap_seconds"]
    if type(gap) not in (int, float) or isinstance(gap, bool):
        raise ValueError("maximum sample gap must be numeric")
    if not 0 < limits["wall_seconds"] <= MAX_WALL_SECONDS:
        raise ValueError("wall limit exceeds the reviewed RP05 guard ceiling")
    if not 0 < limits["child_stop_seconds"] <= MAX_CHILD_STOP_SECONDS:
        raise ValueError("child limit exceeds the reviewed RP05 guard ceiling")
    if limits["child_stop_seconds"] > limits["wall_seconds"]:
        raise ValueError("child stop limit exceeds whole-command wall limit")
    if limits["child_stop_seconds"] > limits["wall_seconds"] - HARD_STOP_MARGIN_SECONDS:
        raise ValueError("child stop limit must preserve the 120-second hard-stop margin")
    if not 0 < limits["peak_rss_bytes"] <= MAX_PEAK_RSS_BYTES:
        raise ValueError("RSS limit exceeds the reviewed RP05 guard ceiling")
    if not 0 < limits["stop_group_rss_bytes"] <= limits["peak_rss_bytes"] - 512 * 1024**2:
        raise ValueError("group RSS stop threshold must retain the 512-MiB safety margin")
    if not 0 < limits["scratch_bytes"] <= MAX_SCRATCH_BYTES:
        raise ValueError("scratch limit exceeds the reviewed 1-GiB cap")
    if not 0 < limits["stop_scratch_bytes"] < limits["scratch_bytes"]:
        raise ValueError("scratch stop threshold must be below its limit")
    if limits["minimum_free_bytes"] < MINIMUM_FREE_BYTES:
        raise ValueError("minimum free-disk headroom is below 20 GiB")
    if not 0 < gap <= MAX_SAMPLE_GAP_SECONDS:
        raise ValueError("sample gap exceeds the reviewed five-second ceiling")


def _read_config(config_path: Path, name: str) -> tuple[dict[str, Any], dict[str, Any], Path, Path]:
    if config_path.is_symlink() or not config_path.is_file():
        raise ValueError("config must be a regular non-symlink file")
    config_path = config_path.resolve(strict=True)
    spec = json.loads(config_path.read_text(encoding="utf-8"))
    root = Path(spec["root"])
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("guard scratch root must be canonical and absolute")
    if not root.is_relative_to(Path("/private/tmp")) or root == Path("/private/tmp"):
        raise ValueError("guard scratch root must be a dedicated descendant of /private/tmp")
    if spec.get("cwd") != str(WORKSPACE_ROOT):
        raise ValueError("guard working directory must be the pinned Hegemon workspace")
    inputs = spec["inputs"]
    if not isinstance(inputs, dict) or not inputs:
        raise ValueError("guard inputs must be a nonempty path-to-SHA256 map")
    for path_text, expected in inputs.items():
        if not isinstance(path_text, str) or not Path(path_text).is_absolute():
            raise ValueError("guard input paths must be absolute")
        if not isinstance(expected, str) or len(expected) != 64 or expected.lower() != expected:
            raise ValueError("guard input SHA256 must be lowercase hex")
        try:
            bytes.fromhex(expected)
        except ValueError as error:
            raise ValueError("guard input SHA256 is not hexadecimal") from error
    if inputs.get(str(REFERENCE_GUARD)) != REFERENCE_GUARD_SHA256:
        raise ValueError("config omitted the immutable reviewed reference-guard pin")
    if inputs.get(str(PROCESS_GROUP_HELPER)) != PROCESS_GROUP_HELPER_SHA256:
        raise ValueError("config omitted the immutable process-group helper pin")
    commands = spec["commands"]
    if not isinstance(commands, list) or sum(item.get("name") == name for item in commands) != 1:
        raise ValueError("exactly one uniquely named lifecycle command is required")
    command = next(item for item in commands if item.get("name") == name)
    argv = command.get("argv")
    if not isinstance(argv, list) or argv[:2] != ["/usr/bin/sandbox-exec", "-f"]:
        raise ValueError("lifecycle command must start under the pinned macOS sandbox wrapper")
    if len(argv) < 4 or argv[2] not in inputs:
        raise ValueError("sandbox profile must be pinned as a config input")
    if any(not isinstance(part, str) for part in argv):
        raise ValueError("command argv must be an array of strings")
    limits = spec["limits"]
    if not isinstance(limits, dict):
        raise ValueError("guard resource limits must be an object")
    _validate_limits(limits)
    environment = spec["environment"]
    if not isinstance(environment, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise ValueError("guard environment must be a string map")
    permitted_hegemon = {
        "HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH",
        "HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_SHA512",
        "HEGEMON_TEST_RETAINED_CARRIER_PROFILE",
    }
    if any(key.startswith("HEGEMON_") and key not in permitted_hegemon for key in environment):
        raise ValueError("guard config includes an unapproved Hegemon environment variable")
    if {"PQ_IDENTITY_SEED", "PQ_IDENTITY_SEED_PATH"} & set(environment):
        raise ValueError("guard config must not carry identity seed environment variables")
    if environment.get("TMPDIR") != str(root / "tmp"):
        raise ValueError("test TMPDIR must remain under the guarded scratch root")
    return spec, command, root, config_path


def run_config(config_path: Path | str, name: str) -> dict[str, Any]:
    """Run one canonical config under the pinned process-group supervisor."""
    global ENV
    _load_pinned_process_group_helper()
    config_path = Path(config_path)
    spec, command, root, resolved_config = _read_config(config_path, name)
    limits = spec["limits"]
    hard_stop = time.time() + limits["wall_seconds"] + HARD_STOP_MARGIN_SECONDS
    if time.time() + limits["wall_seconds"] >= hard_stop:
        raise RuntimeError("bounded RP05 hard-stop window is shorter than its command limit")
    if any(path.is_symlink() for path in (root, root / "out")):
        raise RuntimeError("guard scratch/output path contains a symlink")
    root.mkdir(parents=True, exist_ok=True)
    (root / "out").mkdir(exist_ok=True)
    output = root / "out" / ("dev-" + name)
    output.mkdir(parents=True, exist_ok=False)

    lock_parent = CONTROL
    if lock_parent.is_symlink():
        raise RuntimeError("guard control directory cannot be a symlink")
    lock_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = lock_parent / "lane.lock"
    if lock_path.is_symlink():
        raise RuntimeError("guard control lock cannot be a symlink")
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another reviewed RP05 lifecycle guard owns the control lock") from error

        ENV = dict(spec["environment"])
        report: dict[str, Any] = {
            "purpose": "development-only",
            "production_authorized": False,
            "production_eligible": False,
            "execution_receipts_authenticated": False,
            "reference_guard_sha256": REFERENCE_GUARD_SHA256,
            "process_group_helper_sha256": PROCESS_GROUP_HELPER_SHA256,
            "config_sha256": sha256_file(resolved_config),
            "command": command,
            "samples": [],
        }
        report_path = output / "receipt.json"
        log_path = output / "command.log"

        def persist() -> None:
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

        def inputs() -> dict[str, str]:
            result = {path: sha256_file(Path(path)) for path in spec["inputs"]}
            if result != spec["inputs"]:
                raise RuntimeError("development source input changed")
            return result

        start = time.monotonic()
        last_sample = [start]
        stop_watchdog = threading.Event()
        group = None
        watcher = None

        def watch() -> None:
            while not stop_watchdog.wait(0.1):
                now = time.monotonic()
                if (
                    now - start >= limits["child_stop_seconds"]
                    or now - last_sample[0] > limits["max_sample_gap_seconds"]
                    or time.time() >= hard_stop - 20
                ):
                    report["watchdog_stop"] = {
                        "elapsed": now - start,
                        "sample_gap": now - last_sample[0],
                    }
                    group._kill_watchdog()
                    return

        def sample(active: Any = None) -> None:
            before = time.monotonic()
            row: dict[str, Any] = {
                "elapsed": before - start,
                "scratch_allocated_bytes": census(
                    root, [root / part for part in spec.get("child_writable", ["build", "cache", "tmp", "out"])]
                ),
                "free_bytes": shutil.disk_usage(root).free,
                "waited_children_peak_rss_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            }
            if active is not None:
                result = subprocess.run(
                    ["/bin/ps", "-p", str(active.proc.pid), "-g", str(active.pgid),
                     "-o", "pid=,pgid=,rss="],
                    env=ENV, text=True, capture_output=True, check=True, timeout=0.2,
                )
                rows = [[int(value) for value in line.split()] for line in result.stdout.splitlines()]
                if not any(values[0] == active.proc.pid for values in rows):
                    raise RuntimeError("reserved process-group leader missing from resource sample")
                if not all(values[1] == active.pgid for values in rows):
                    raise RuntimeError("process escaped the supervised process group")
                row["owned_group_rss_bytes"] = sum(values[2] * 1024 for values in rows)
            completed = time.monotonic()
            row["completed_sample_gap_seconds"] = completed - last_sample[0]
            report["samples"].append(row)
            persist()
            if row["free_bytes"] < limits["minimum_free_bytes"]:
                raise RuntimeError("minimum free-disk headroom reached")
            if row["scratch_allocated_bytes"] >= limits["stop_scratch_bytes"]:
                raise RuntimeError("scratch stop threshold reached")
            if row["waited_children_peak_rss_bytes"] >= limits["peak_rss_bytes"]:
                raise RuntimeError("waited-child RSS limit reached")
            if row.get("owned_group_rss_bytes", 0) >= limits["stop_group_rss_bytes"]:
                raise RuntimeError("supervised process-group RSS stop threshold reached")
            if row["completed_sample_gap_seconds"] > limits["max_sample_gap_seconds"]:
                raise RuntimeError("resource sample gap exceeded configured maximum")
            if completed - start >= limits["wall_seconds"]:
                raise RuntimeError("whole-command wall limit reached")
            if active is not None and completed - start >= limits["child_stop_seconds"]:
                raise RuntimeError("child stop limit reached")
            last_sample[0] = completed

        try:
            report["preflight_inputs"] = inputs()
            sample()
            execution = report["execution"] = {}
            group = ChildProcessGroup(execution)
            process = None
            with log_path.open("xb") as log:
                try:
                    process = subprocess.Popen(
                        command["argv"], cwd=spec["cwd"], env=ENV,
                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                    )
                    group.attach(process)
                    watcher = threading.Thread(target=watch, daemon=True)
                    watcher.start()
                    group.initialize_metadata()
                    while not group.leader_exited():
                        sample(group)
                        time.sleep(0.1)
                    stop_watchdog.set()
                    watcher.join(timeout=1)
                    if watcher.is_alive():
                        raise RuntimeError("process-group watchdog did not stop after leader exit")
                    group.finish()
                except BaseException:
                    stop_watchdog.set()
                    try:
                        if watcher is not None and watcher.ident is not None:
                            watcher.join(timeout=1)
                    finally:
                        if process is not None:
                            if group.proc is None:
                                group.attach(process)
                            if not group.retired:
                                group.finish(terminate=True)
                    raise
            report["exit_code"] = process.returncode
            if process.returncode != 0:
                raise RuntimeError(f"guarded command returned {process.returncode}")
            if group.kill_event.is_set() or execution.get("watchdog_errors"):
                raise RuntimeError("guard watchdog or cleanup reported a failure")
            report["postflight_inputs"] = inputs()
            sample()
            report["status"] = "PASS_DEVELOPMENT_ONLY"
        except BaseException as error:
            report["status"] = "FAILED"
            report["error"] = repr(error)
        finally:
            report["elapsed_seconds"] = time.monotonic() - start
            report["active_reservations"] = list(ACTIVE_GROUPS)
            if log_path.exists():
                report["log_sha256"] = sha256_file(log_path)
            persist()

        report["receipt_path"] = str(report_path)
        report["command_log_path"] = str(log_path)
        return report


_load_pinned_process_group_helper()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        raise SystemExit("usage: rp05_bounded_dev.py CONFIG.json COMMAND_NAME")
    try:
        report = run_config(args[0], args[1])
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"RP05 bounded development guard stopped: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": report["status"],
        "receipt": report["receipt_path"],
        "sha256": sha256_file(Path(report["receipt_path"])),
        "production_authorized": False,
    }, sort_keys=True), flush=True)
    return 0 if report.get("status") == "PASS_DEVELOPMENT_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
