#!/bin/sh
# Local integration check for libtriage.so; not for upstream submission.
# Usage: triage-smoke.sh BUILD/qemu-x86_64 BUILD/contrib/plugins/libtriage.so
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 QEMU_X86_64 LIBTRIAGE_SO" >&2
    exit 2
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

cat > "$workdir/guest.c" <<'EOF'
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

static _Alignas(64) volatile uint64_t slots[8];
static _Alignas(64) atomic_uint counter;
static pthread_barrier_t gate;

static void *worker(void *arg)
{
    uintptr_t id = (uintptr_t)arg;

    pthread_barrier_wait(&gate);
    for (unsigned int i = 0; i < 20000; i++) {
        slots[id] = i;
        atomic_fetch_add_explicit(&counter, 1, memory_order_relaxed);
    }
    return NULL;
}

int main(void)
{
    pthread_t thread[3];

    if (pthread_barrier_init(&gate, NULL, 4)) {
        return 1;
    }
    for (uintptr_t i = 1; i < 4; i++) {
        if (pthread_create(&thread[i - 1], NULL, worker, (void *)i)) {
            return 2;
        }
    }
    worker(NULL);
    for (int i = 0; i < 3; i++) {
        pthread_join(thread[i], NULL);
    }
    return atomic_load(&counter) == 80000 ? 0 : 3;
}
EOF

${CC:-cc} -O1 -g -static -no-pie -pthread \
    -o "$workdir/guest" "$workdir/guest.c"
"$1" -d plugin -D "$workdir/report.log" \
    -plugin "$2,top=10" "$workdir/guest"

rg -q 'thread_starts=4' "$workdir/report.log"
rg -q 'atomic=160000.*worker' "$workdir/report.log"
rg -q 'atomic=160000.*atomic_vcpus=4' "$workdir/report.log"
rg -q 'pairs=6 .*writes=80000.*writers=4' "$workdir/report.log"
echo 'triage smoke test passed'
