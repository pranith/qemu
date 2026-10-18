/* Local AI-assisted plugin API experiment; not for upstream submission. */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <pthread.h>
#include <stdint.h>

static pthread_barrier_t barrier;
/* Preserve each worker's guest stores for the instrumentation test. */
static volatile uint64_t result[4];

static void *work(void *arg)
{
    unsigned int index = (uintptr_t)arg;
    uint64_t value = index;
    int barrier_result = pthread_barrier_wait(&barrier);

    if (barrier_result != 0 &&
        barrier_result != PTHREAD_BARRIER_SERIAL_THREAD) {
        return (void *)1;
    }
    for (unsigned int i = 0; i < 10000; i++) {
        value += (i & 1) ? i : i * 3;
    }
    result[index] = value;
    return NULL;
}

int main(void)
{
    pthread_t threads[3];

    if (pthread_barrier_init(&barrier, NULL, 4)) {
        return 1;
    }
    for (uintptr_t i = 1; i < 4; i++) {
        if (pthread_create(&threads[i - 1], NULL, work, (void *)i)) {
            return 2;
        }
    }
    if (work(NULL)) {
        return 3;
    }
    for (unsigned int i = 0; i < 3; i++) {
        if (pthread_join(threads[i], NULL)) {
            return 4;
        }
    }
    pthread_barrier_destroy(&barrier);
    return result[0] == result[1] ? 5 : 0;
}
