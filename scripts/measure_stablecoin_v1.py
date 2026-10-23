#!/usr/bin/env python3
"""Measure one candidate executable without Cargo or /usr/bin/time sysctl.

Usage: measure_stablecoin_v1.py NEW_RECEIPT.json NEW_LOG EXECUTABLE [ARGS...]
The executable should retain its public artifacts separately. This records the
whole child process peak RSS, not a prover-only allocation bound.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    receipt, log, executable = map(Path, sys.argv[1:4])
    if receipt.exists() or log.exists():
        raise SystemExit("Receipt/log already exists; choose fresh output paths")
    executable = executable.resolve(strict=True)
    command = [str(executable), *sys.argv[4:]]
    started = time.monotonic()
    with log.open("xb") as output:
        run = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=False)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    # Darwin reports bytes, Linux reports KiB. No polling/sysctl is required.
    peak_rss_bytes = usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    result = {
        "schema": "hegemon.stablecoin.process-measurement.v1",
        "command": command,
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "exit_code": run.returncode,
        "wall_seconds": time.monotonic() - started,
        "user_seconds": usage.ru_utime,
        "system_seconds": usage.ru_stime,
        "whole_process_peak_rss_bytes": peak_rss_bytes,
        "rss_scope": "entire child including compile, encryption, proving and verification",
        "platform": sys.platform,
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "rayon_num_threads": os.environ.get("RAYON_NUM_THREADS"),
        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
    }
    with receipt.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps(result))
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
