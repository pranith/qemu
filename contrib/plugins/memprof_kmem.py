#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Summarize Linux kmem tracepoint churn for the local memprof experiment."""

import argparse
from collections import defaultdict
from dataclasses import dataclass
import re


EVENT = re.compile(
    r"(?P<time>\d+\.\d+):\s+(?:kmem:)?"
    r"(?P<name>kmalloc(?:_node)?|kmem_cache_alloc(?:_node)?|"
    r"kfree|kmem_cache_free|mm_page_alloc|mm_page_free):\s*"
    r"(?P<fields>.*)$"
)
FIELD = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)=([^\s]+)")
ALLOC = {"kmalloc", "kmalloc_node", "kmem_cache_alloc",
         "kmem_cache_alloc_node", "mm_page_alloc"}
FREE = {"kfree", "kmem_cache_free", "mm_page_free"}


@dataclass
class LiveAllocation:
    time: float
    key: tuple[str, str]
    size: int


@dataclass
class SiteStats:
    allocations: int = 0
    frees: int = 0
    requested_bytes: int = 0
    allocated_bytes: int = 0
    total_lifetime: float = 0.0


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value, 0)
    except (ValueError, TypeError):
        return default


def parse_event(line: str):
    match = EVENT.search(line)
    if not match:
        return None
    return (float(match["time"]), match["name"],
            dict(FIELD.findall(match["fields"])))


def allocation_key(name: str, fields: dict[str, str]):
    if name.startswith("mm_page_"):
        ptr = fields.get("pfn")
        return ("page", ptr) if ptr is not None else None
    ptr = fields.get("ptr")
    if not ptr or ptr in {"(____ptrval____)", "(null)", "0x0"}:
        return None
    return ("object", ptr)


def analyze(lines, page_size: int):
    live = {}
    sites = defaultdict(SiteStats)
    unmatched_frees = 0
    reused_before_free = 0
    parsed = 0

    for line in lines:
        event = parse_event(line)
        if event is None:
            continue
        parsed += 1
        when, name, fields = event
        key = allocation_key(name, fields)
        if key is None:
            continue
        if name in ALLOC:
            site = fields.get("call_site", "unknown")
            group = (name, site)
            if name == "mm_page_alloc":
                allocated = page_size << min(parse_int(fields.get("order")), 30)
                requested = allocated
            else:
                requested = parse_int(fields.get("bytes_req"))
                allocated = parse_int(fields.get("bytes_alloc"), requested)
            stats = sites[group]
            stats.allocations += 1
            stats.requested_bytes += requested
            stats.allocated_bytes += allocated
            if key in live:
                reused_before_free += 1
            live[key] = LiveAllocation(when, group, allocated)
        elif name in FREE:
            active = live.pop(key, None)
            if active is None:
                unmatched_frees += 1
                continue
            stats = sites[active.key]
            stats.frees += 1
            stats.total_lifetime += max(0.0, when - active.time)

    return sites, live, parsed, unmatched_frees, reused_before_free


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", help="guest ftrace text or trace-cmd report")
    parser.add_argument("--page-size", type=int, default=4096)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    with open(args.trace, encoding="utf-8", errors="replace") as stream:
        sites, live, parsed, unmatched, reused = analyze(stream, args.page_size)

    print(f"kmem events={parsed} sites={len(sites)} live={len(live)} "
          f"unmatched_frees={unmatched} reused_before_free={reused}")
    print("type site allocations frees live requested_bytes allocated_bytes "
          "mean_lifetime_s")
    for (kind, site), stats in sorted(
        sites.items(), key=lambda item: item[1].allocated_bytes, reverse=True
    )[:args.limit]:
        mean_lifetime = (stats.total_lifetime / stats.frees
                         if stats.frees else 0.0)
        print(f"{kind} {site} {stats.allocations} {stats.frees} "
              f"{stats.allocations - stats.frees} "
              f"{stats.requested_bytes} {stats.allocated_bytes} "
              f"{mean_lifetime:.6f}")


if __name__ == "__main__":
    main()
