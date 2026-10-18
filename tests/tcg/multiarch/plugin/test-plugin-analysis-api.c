/* Local AI-assisted plugin API experiment; not for upstream submission. */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>

/* Keep each loop iteration and noinline call visible to the profiler. */
static volatile unsigned long result;
static sigjmp_buf fault_jump;
static volatile sig_atomic_t fault_seen;

static void fault_handler(int signo)
{
    fault_seen = signo;
    siglongjmp(fault_jump, 1);
}

__attribute__((noinline)) unsigned long analysis_target(unsigned long value)
{
    return value * 3 + 1;
}

__attribute__((noinline))
unsigned long analysis_replacement(unsigned long value)
{
    return value * 5 + 7;
}

__attribute__((noinline)) unsigned long analysis_original(unsigned long value)
{
    return value + 1;
}

int main(void)
{
    char path[] = "/tmp/qemu-analysis-image-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0 || ftruncate(fd, 4096) != 0) {
        return 1;
    }
    void *mapped = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED ||
        mprotect(mapped, 4096, PROT_READ | PROT_EXEC) != 0) {
        return 2;
    }
    mapped = mremap(mapped, 4096, 8192, MREMAP_MAYMOVE);
    if (mapped == MAP_FAILED || munmap(mapped, 8192) != 0) {
        return 2;
    }
    close(fd);
    unlink(path);

    struct sigaction action = {.sa_handler = fault_handler};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) != 0) {
        return 5;
    }
    /* Force an actual load from PROT_NONE to exercise the signal event. */
    volatile int *guard = mmap(NULL, 4096, PROT_NONE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED) {
        return 6;
    }
    if (sigsetjmp(fault_jump, 1) == 0) {
        result += *guard;
        return 7;
    }
    if (fault_seen != SIGSEGV || munmap((void *)guard, 4096) != 0) {
        return 8;
    }

    for (unsigned long i = 0; i < 16; i++) {
        result += analysis_target(i);
    }

    /* Keep both calls visible to the translator across optimization levels. */
    volatile unsigned long replacement_arg = 1;
    /* Keep the original call visible for redirect instrumentation. */
    volatile unsigned long original_arg = 2;
    if (analysis_replacement(replacement_arg) != 12 ||
        analysis_original(original_arg) != 17) {
        return 9;
    }

    for (unsigned long i = 0; i < 1000; i++) {
        if (i & 1) {
            result += i;
        } else {
            result ^= i;
        }
    }
    pid_t child = fork();
    if (child < 0) {
        return 3;
    }
    if (child == 0) {
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 4;
    }
    printf("%lu\n", result);
    return 0;
}
