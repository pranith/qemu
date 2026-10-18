# Triage plugin (local experiment)

This plugin uses the extended QEMU plugin API to collect architectural
instruction, memory, and branch observations under TCG. It helps locate
code worth measuring more carefully. The output is **not** a hardware
performance counter report and is not intended for upstream submission.

Build it with `ninja -C BUILD contrib/plugins/libtriage.so`. Enable plugin
logging with `-d plugin -D report.log`.

For a quick x86 Linux-user integration check, run
`contrib/plugins/triage-smoke.sh BUILD/qemu-x86_64
BUILD/contrib/plugins/libtriage.so`.

Linux-user example:

```sh
BUILD/qemu-x86_64 -d plugin -D report.log \
  -plugin BUILD/contrib/plugins/libtriage.so,top=20 \
  ./guest-program
```

ARM64 kernel example (paths adapted to this local rootfs checkout):

```sh
BUILD/qemu-system-aarch64 -machine virt -cpu max -smp 4 -m 1024 \
  -kernel /home/pranith/work/code/rootfs/kernel/build/7.3-rc7/arm64/arch/arm64/boot/Image \
  -initrd /home/pranith/work/code/rootfs/initrd/initrd.cpio.arm64 \
  -append 'console=ttyAMA0 nokaslr memprof.atomic_probe=1' \
  -nographic -no-reboot -d plugin -D report.log \
  -plugin BUILD/contrib/plugins/libtriage.so,top=20,sites=300000,lines=65536,symbols=/home/pranith/work/code/rootfs/kernel/build/7.3-rc7/arm64/System.map
```

`BUILD` must contain a QEMU binary built from this API version. Kernel
`System.map` addresses require `nokaslr`. The optional `pc_start` and
`pc_end` hexadecimal arguments restrict instrumentation to a guest PC range.
`top`, `sites`, and `lines` bound report length and resident state. A filled
site or line table evicts old entries. The report shows both counts. For a
focused workload, use a PC filter or enough table
capacity to keep the relevant sites and lines.

The report ranks:

* Executed instruction PCs and memory access PCs.
* Atomic memory events and failed atomic events, with decoded mnemonics.
* Conditional branches with both outcomes, ranked by the less common outcome.
* Lines with atomic writes from multiple vCPUs, suggesting contention.
* Lines whose vCPU writers touched disjoint bytes, suggesting false sharing.

One atomic read-modify-write instruction can generate a read and a write
event. A failed atomic event is not necessarily a failed lock acquisition.
Memory traces are buffered per vCPU, so their flush order cannot establish
cross-vCPU cache-line transfer order. The sharing sections compare writer
footprints; they do not count cache misses, line transfers, cycles, lock
wait time, or branch mispredictions. RAM offsets are used when available,
then physical addresses. Linux-user virtual addresses are grouped by PID;
without a PID, virtual addresses are kept separate per vCPU. The summary
reports virtual records whose PID was unavailable. The `space` field names
the address kind and, for virtual addresses, the PID or vCPU scope.

Linux-user rows include the process ID and image path when available.
System-emulation rows have PID zero because the API cannot identify guest
kernel tasks from a vCPU callback. Kernel symbols come from the optional
`System.map` file.
