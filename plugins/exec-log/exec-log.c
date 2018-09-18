#include <stdint.h>
#include <stdio.h>
#include "plugins.h"

bool plugin_init(const char *args)
{
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
    fprintf(stderr, "executing instruction at pc: %lx\n", v);
    return;
}

void mem_cb(int c, uint64_t v, uint64_t p, int size, int w)
{
    fprintf(stderr, "core: %d, vaddr: %lx, paddr: %lx, \
                     size: %d, write: %d\n", c, v, p, size, w);

    return;
}
