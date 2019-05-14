#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "plugins.h"

static char *DEFAULT_PATH = "trace-s0.txt";
static uint64_t MAX_TRACE_LENGTH = 1000000000ull;
static uint64_t trace_length = 0ull;
static uint64_t inst_count = 0ull;
static FILE *trace = NULL;
static uint8_t start_seen = 0;
static uint64_t startpc = 0;

bool plugin_init(const char *args)
{
    char *trace_path = NULL;
    char *trace_length_str = NULL;
    char *startpc_str = NULL;

    trace_path = getenv("TRACEPATH");
    if (trace_path == NULL) {
        trace_path = DEFAULT_PATH;
    }

    trace_length_str = getenv("TRACELENGTH");
    if (trace_length_str == NULL) {
        trace_length = MAX_TRACE_LENGTH;
    }
    else {
        trace_length = atoll(trace_length_str);
    }

    startpc_str = getenv("STARTPC");
    if (startpc_str == NULL) {
	start_seen = 1;
    }
    else {
	startpc = strtol(startpc_str, NULL, 16);
        if (startpc == 0) {
	    start_seen = 1;
        }
    }

    if (trace_length) {
        trace = fopen(trace_path, "w");
        if (trace == NULL) {
            printf("error opening file %s for writing trace\n", trace_path);
	    return false;
        }
    }

    return true;
}

extern bool enable_instrumentation;

bool plugin_needs_before_insn(uint64_t pc, void *cpu)
{
    if (enable_instrumentation) {
        return true;
    }

    return false;
}

void plugin_before_insn(uint64_t pc, void *cpu)
{
    uint8_t inst_buffer[4];

    qemulib_read_memory(cpu, pc, inst_buffer, sizeof(uint32_t));
    inst_cb(qemulib_get_cpuid(cpu), pc, qemulib_translate_memory(cpu, pc),
            sizeof(uint32_t), inst_buffer);
}

void plugin_after_mem(void *cpu, uint64_t v, int size, int type)
{
    mem_cb(qemulib_get_cpuid(cpu), v,
           qemulib_translate_memory(cpu, v), size, type);
}

void inst_cb(int c, uint64_t v, uint64_t p, uint8_t l,
             const uint8_t *b)
{
    if (!start_seen && (v == startpc)) start_seen = 1;
    if (!start_seen) return;

    //fprintf(stderr, "executing instruction at pc: %lx\n", v);
    if (inst_count < trace_length && trace) {
        fprintf(trace, "user=%d\n", (v >= 0xffff000000000000));
        fprintf(trace, "0x%016lx:  --  0x%02x%02x%02x%02x    N/A\n", v, b[3], b[2], b[1], b[0]);
    }
    else if (trace) {
        fclose(trace);
        trace = NULL;
    }
    ++inst_count;
    return;
}

void mem_cb(int c, uint64_t v, uint64_t p, int size, int w)
{
    if (!start_seen) return;

    //fprintf(stderr, "core: %d, vaddr: %lx, paddr: %lx, \
    //                 size: %d, write: %d\n", c, v, p, size, w);

    if (inst_count <= trace_length && trace) {
        fprintf(trace, "va=%016lx\npa=%016lx\n", v, p);
    }
    return;
}
