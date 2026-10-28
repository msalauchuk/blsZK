#!/usr/bin/env python3
"""Measure one child command in a fresh process; macOS/Linux, standard library only."""

import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("supply a command after --")
    if sys.platform not in ("darwin", "linux"):
        parser.error("peak RSS units are implemented for macOS and Linux only")
    args.metrics.parent.mkdir(parents=True, exist_ok=True)
    # Do not leave a successful result from an earlier invocation on failure.
    args.metrics.unlink(missing_ok=True)
    start = time.perf_counter()
    try:
        result = subprocess.run(command, timeout=args.timeout, check=False)
        code = result.returncode
    except subprocess.TimeoutExpired:
        code = 124
    elapsed_ms = (time.perf_counter() - start) * 1000
    # This runner starts exactly one child and waits for it; RUSAGE_CHILDREN
    # therefore measures that command, not a prior prover run or the parent Node.
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    metrics = {
        "command": command,
        "exitCode": code,
        "wallTimeMs": elapsed_ms,
        "cpuUserSeconds": usage.ru_utime,
        "cpuSystemSeconds": usage.ru_stime,
        "peakRssBytes": int(usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)),
        "majorPageFaults": usage.ru_majflt,
        "measurement": "getrusage(RUSAGE_CHILDREN); one fresh runner per command",
        "platform": sys.platform,
    }
    with tempfile.NamedTemporaryFile(mode="w", dir=args.metrics.parent, delete=False) as temporary:
        json.dump(metrics, temporary, indent=2)
        temporary.write("\n")
        temp_name = temporary.name
    os.replace(temp_name, args.metrics)
    print(f"Measured command: {elapsed_ms / 1000:.1f}s wall, {metrics['peakRssBytes'] / 2**30:.2f} GiB peak RSS, exit {code}", flush=True)
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
