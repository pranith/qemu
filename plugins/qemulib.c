#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "qemu/error-report.h"
#include "qemu/plugins.h"
#include "qemu/log.h"
#include "include/plugins.h"

void qemulib_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    qemu_log_vprintf(fmt, args);
    va_end(args);
}

uint64_t qemulib_translate_memory(void *cpu, uint64_t addr)
{
    return cpu_memory_phys_addr(cpu, addr);
}

int qemulib_read_memory(void *cpu, uint64_t addr, uint8_t *buf, int len)
{
    return cpu_memory_rw_debug(cpu, addr, buf, len, false);
}

int qemulib_read_register(void *cpu, uint8_t *mem_buf, int reg)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    if (reg < cc->gdb_num_core_regs) {
        return cc->gdb_read_register(cpu, mem_buf, reg);
    }

    return 0;
}

int qemulib_get_cpuid(void *cpu)
{
    CPUState *cs = CPU(cpu);

    return cs ? cs->cpu_index : -1;
}

// NOTE: ARM specific function; cannot be generalized
uint32_t qemulib_get_current_el(void *cpu)
{

//#if TARGET_BASE_ARCH != arm
//    assert(0 && "Building illegal target base");
//#endif

    CPUState *cs = CPU(cpu);
    ARMCPU *arm_cpu = ARM_CPU(cs);

    assert( arm_cpu );
    return arm_cpu ? arm_current_el(&(arm_cpu->env)) : -1;
}

// NOTE: ARM specific function; cannot be generalized
uint32_t qemulib_get_tid(void *cpu, uint32_t el)
{

//#if TARGET_BASE_ARCH != arm
//    assert(0 && "Building illegal target base");
//#endif

    CPUState *cs = CPU(cpu);
    ARMCPU *arm_cpu = ARM_CPU(cs);

    assert( arm_cpu );
    assert( el != -1 );
    return arm_cpu ? arm_cpu->env.cp15.contextidr_el[el] : -1;
}
