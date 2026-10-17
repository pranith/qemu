.. SPDX-License-Identifier: GPL-2.0-or-later

Linux-user memory attribution experiment
========================================

``userprof`` attributes TCG memory accesses to the guest process, thread,
executable mapping, instruction address and (when QEMU finds one) symbol. It
also counts mapping, thread, fork, exec-attempt and process-exit events. The
plugin is a local experiment built on plugin API version 10.

Build QEMU with plugins enabled, then run, for example::

  qemu-aarch64 -L /usr/aarch64-linux-gnu \
    -d plugin -D userprof.log \
    -plugin contrib/plugins/libuserprof.so,top=20 \
    ./guest-program

Options:

``top=N``
  Show the N instruction sites with the most memory accesses (default 20).

``image=TEXT``
  Instrument only instructions in mappings whose file path contains TEXT.

``events=on``
  Log every task and mapping event. This can produce a large log.

``atomic_addrs=on``
  Report atomic addresses touched by two or more guest threads, ranked by
  atomic access count. A per-thread cap of 100,000 distinct addresses limits
  memory use; the report shows how many observations were dropped. Shared
  access is a contention candidate, not a measured cache miss or stall.

The ``offset`` column is a file offset, obtained from the executable mapping.
For anonymous executable memory it is zero. Use the mapping path and offset
with the matching binary for offline symbolization; ELF tools may require a
conversion from file offset to ELF virtual address. The ``threads`` column
counts distinct guest threads that accessed the site, up to 64 per process.
Memory counters are private to each thread during execution and are merged
when QEMU exits, so a contended guest instruction does not contend on the
profiler's own counters.
Each atomic read and write access is counted separately. ``failed`` counts
failed compare-and-swap stores when the target reports that outcome.

``exec_attempt`` occurs before the host exec call. If exec succeeds, the QEMU
process is replaced, so the plugin does not produce a final summary for that
process. Fork creates independent copies of profiler state; the child starts
new counters and inherits its mapping metadata. The report describes accesses
observed by TCG, not target cache misses or hardware cycles.

The mapping callback runs under linux-user's mapping lock. Plugins using this
API must not access or change guest mappings from that callback. The mapping
path is best effort, and pointers passed to callbacks expire when they return.
