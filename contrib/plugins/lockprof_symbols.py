#!/usr/bin/env python3
"""Annotate a local lockprof report with symbols from its matching vmlinux."""

import argparse
import bisect
import re
import subprocess
from pathlib import Path


def symbols(vmlinux: Path):
    result = subprocess.run(
        ["nm", "-n", str(vmlinux)], check=True, capture_output=True, text=True
    )
    addresses = []
    names = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t"):
            addresses.append(int(parts[0], 16))
            names.append(parts[2])
    return addresses, names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vmlinux", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    addresses, names = symbols(args.vmlinux)

    pattern = re.compile(
        r"(?:^|\s)(pc|first_pc|caller|outer_caller|site)=([0-9a-f]{16})"
    )
    for line in args.report.read_text().splitlines():
        annotations = []
        for match in pattern.finditer(line):
            pc = int(match.group(2), 16)
            index = bisect.bisect_right(addresses, pc) - 1
            if index >= 0:
                label = (
                    "symbol"
                    if match.group(1) in ("pc", "first_pc")
                    else f"{match.group(1)}_symbol"
                )
                annotations.append(
                    f"{label}={names[index]}+0x{pc - addresses[index]:x}"
                )
        print(f"{line} {' '.join(annotations)}" if annotations else line)


if __name__ == "__main__":
    main()
