/*
 *  x86 memory access helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"

/* broken thread support */

static bool atomic_flag = false;
static int atomic_locked;
static uint64_t atomic_addr;
static int nonatomic_locked = 0;

extern uint64_t qsim_icount;
uint64_t qsim_eip, qsim_locked_addr;
extern inst_cb_t    qsim_inst_cb;
extern atomic_cb_t  qsim_atomic_cb;
extern int_cb_t     qsim_int_cb;
extern reg_cb_t     qsim_reg_cb;

extern int qsim_id;

extern qsim_lockstruct *qsim_ram_l;

CPUState *qsim_cpu;

void helper_lock(void)
{
    atomic_flag = 1;
    atomic_locked = 0;
    // Suspend execution immediately if the atomic callback returns nonzero
    if (qsim_atomic_cb && qsim_atomic_cb(qsim_id))
        swapcontext(&qemu_context, &main_context);
}

void helper_unlock(void)
{
    atomic_flag = 0;
    if (atomic_locked) qsim_aunlock_addr(qsim_ram_l, atomic_addr);
}

void helper_cmpxchg8b(CPUX86State *env, target_ulong a0)
{
    uint64_t d;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);
    d = cpu_ldq_data(env, a0);
    if (d == (((uint64_t)env->regs[R_EDX] << 32) | (uint32_t)env->regs[R_EAX])) {
        cpu_stq_data(env, a0, ((uint64_t)env->regs[R_ECX] << 32) | (uint32_t)env->regs[R_EBX]);
        eflags |= CC_Z;
    } else {
        /* always do the store */
        cpu_stq_data(env, a0, d);
        env->regs[R_EDX] = (uint32_t)(d >> 32);
        env->regs[R_EAX] = (uint32_t)d;
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

#ifdef TARGET_X86_64
void helper_cmpxchg16b(CPUX86State *env, target_ulong a0)
{
    uint64_t d0, d1;
    int eflags;

    if ((a0 & 0xf) != 0) {
        raise_exception(env, EXCP0D_GPF);
    }
    eflags = cpu_cc_compute_all(env, CC_OP);
    d0 = cpu_ldq_data(env, a0);
    d1 = cpu_ldq_data(env, a0 + 8);
    if (d0 == env->regs[R_EAX] && d1 == env->regs[R_EDX]) {
        cpu_stq_data(env, a0, env->regs[R_EBX]);
        cpu_stq_data(env, a0 + 8, env->regs[R_ECX]);
        eflags |= CC_Z;
    } else {
        /* always do the store */
        cpu_stq_data(env, a0, d0);
        cpu_stq_data(env, a0 + 8, d1);
        env->regs[R_EDX] = d1;
        env->regs[R_EAX] = d0;
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}
#endif

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_data(env, a0);
    high = cpu_ldsw_data(env, a0 + 2);
    v = (int16_t)v;
    if (v < low || v > high) {
        raise_exception(env, EXCP05_BOUND);
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_data(env, a0);
    high = cpu_ldl_data(env, a0 + 4);
    if (v < low || v > high) {
        raise_exception(env, EXCP05_BOUND);
    }
}

#if !defined(CONFIG_USER_ONLY)
/* try to fill the TLB and return an exception if error. If retaddr is
 * NULL, it means that the function was called in C code (i.e. not
 * from generated code or from helper.c)
 */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUState *cs, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr)
{
    int ret;

    ret = x86_cpu_handle_mmu_fault(cs, addr, is_write, mmu_idx);
    if (ret) {
        X86CPU *cpu = X86_CPU(cs);
        CPUX86State *env = &cpu->env;

        if (retaddr) {
            /* now we have a real cpu fault */
            cpu_restore_state(cs, retaddr);
        }
        raise_exception_err(env, cs->exception_index, env->error_code);
    }
}
#endif

#include "qsim-vm.h"
#include "qsim-func.h"

#include "qsim-context.h"
#include "qsim-x86-regs.h"

void helper_atomic_callback(void)
{
    atomic_flag = !atomic_flag;
    /* if atomic callback returns non-zero, suspend execution */
    if (qsim_atomic_cb && qsim_atomic_cb(qsim_id))
        swapcontext(&qemu_context, &main_context);

    return;
}

uint8_t mem_rd(CPUX86State *env, uint64_t paddr);
void mem_wr(CPUX86State *env, uint64_t paddr, uint8_t value);
uint8_t mem_rd_virt(CPUX86State *env, uint64_t vaddr);
void mem_wr_virt(CPUX86State *env, uint64_t vaddr, uint8_t val);
uint64_t get_reg(CPUX86State *env, enum regs r);
void set_reg(enum regs r, uint64_t val);

target_ulong helper_reg_read_callback(target_ulong reg, target_ulong size)
{
	if (qsim_reg_cb) qsim_reg_cb(qsim_id, reg, size, 0);
	return 0;
}

target_ulong helper_reg_write_callback(target_ulong reg, target_ulong size)
{
  if (qsim_reg_cb) qsim_reg_cb(qsim_id, reg, size, 1);
  return 0;
}

uint64_t get_reg(CPUX86State *env, enum regs r) {
    CPUX86State *cpu = (CPUX86State *)first_cpu;
    switch (r) {
        case QSIM_RAX:    return cpu->regs[R_EAX];
        case QSIM_RCX:    return cpu->regs[R_ECX];
        case QSIM_RDX:    return cpu->regs[R_EDX];
        case QSIM_RBX:    return cpu->regs[R_EBX];
        case QSIM_RSP:    return cpu->regs[R_ESP];
        case QSIM_RBP:    return cpu->regs[R_EBP];
        case QSIM_RSI:    return cpu->regs[R_ESI];
        case QSIM_RDI:    return cpu->regs[R_EDI];
        case QSIM_FP0:    return cpu->fpregs[0].mmx.q;
        case QSIM_FP1:    return cpu->fpregs[1].mmx.q;
        case QSIM_FP2:    return cpu->fpregs[2].mmx.q;
        case QSIM_FP3:    return cpu->fpregs[3].mmx.q;
        case QSIM_FP4:    return cpu->fpregs[4].mmx.q;
        case QSIM_FP5:    return cpu->fpregs[5].mmx.q;
        case QSIM_FP6:    return cpu->fpregs[6].mmx.q;
        case QSIM_FP7:    return cpu->fpregs[7].mmx.q;
        case QSIM_FPSP:   return cpu->fpstt;
        case QSIM_ES :    return cpu->segs[R_ES ].selector;
        case QSIM_ESB:    return cpu->segs[R_ES ].base;
        case QSIM_ESL:    return cpu->segs[R_ES ].limit;
        case QSIM_ESF:    return cpu->segs[R_ES ].flags;
        case QSIM_CS :    return cpu->segs[R_CS ].selector;
        case QSIM_CSB:    return cpu->segs[R_CS ].base;
        case QSIM_CSL:    return cpu->segs[R_CS ].limit;
        case QSIM_CSF:    return cpu->segs[R_CS ].flags;
        case QSIM_SS :    return cpu->segs[R_SS ].selector;
        case QSIM_SSB:    return cpu->segs[R_SS ].base;
        case QSIM_SSL:    return cpu->segs[R_SS ].limit;
        case QSIM_SSF:    return cpu->segs[R_SS ].flags;
        case QSIM_DS :    return cpu->segs[R_DS ].selector;
        case QSIM_DSB:    return cpu->segs[R_DS ].base;
        case QSIM_DSL:    return cpu->segs[R_DS ].limit;
        case QSIM_DSF:    return cpu->segs[R_DS ].flags;
        case QSIM_FS :    return cpu->segs[R_FS ].selector;
        case QSIM_FSB:    return cpu->segs[R_FS ].base;
        case QSIM_FSL:    return cpu->segs[R_FS ].limit;
        case QSIM_FSF:    return cpu->segs[R_FS ].flags;
        case QSIM_GS :    return cpu->segs[R_GS ].selector;
        case QSIM_GSB:    return cpu->segs[R_GS ].base;
        case QSIM_GSL:    return cpu->segs[R_GS ].limit;
        case QSIM_GSF:    return cpu->segs[R_GS ].flags;
        case QSIM_RIP:    return qsim_eip;
        case QSIM_CR0:    return cpu->cr  [0    ];
        case QSIM_CR2:    return cpu->cr  [2    ];
        case QSIM_CR3:    return cpu->cr  [3    ];
        case QSIM_CR4:    return cpu->cr  [4    ];
        case QSIM_RFLAGS: return cpu_compute_eflags(cpu);
        case QSIM_GDTB:   return cpu->gdt.base;
        case QSIM_IDTB:   return cpu->idt.base;
        case QSIM_GDTL:   return cpu->gdt.limit;
        case QSIM_IDTL:   return cpu->idt.limit;
        case QSIM_TR:     return cpu->tr.selector;
        case QSIM_TRB:    return cpu->tr.base;
        case QSIM_TRL:    return cpu->tr.limit;
        case QSIM_TRF:    return cpu->tr.flags;
        case QSIM_LDT:    return cpu->ldt.selector;
        case QSIM_LDTB:   return cpu->ldt.base;
        case QSIM_LDTL:   return cpu->ldt.limit;
        case QSIM_LDTF:   return cpu->ldt.flags;
        case QSIM_DR6:    return cpu->dr[6];
        case QSIM_DR7:    return cpu->dr[7];
        case QSIM_HFLAGS: return cpu->hflags;
        case QSIM_HFLAGS2:return cpu->hflags2;
        case QSIM_SE_CS:  return cpu->sysenter_cs;
        case QSIM_SE_SP:  return cpu->sysenter_esp;
        case QSIM_SE_IP:  return cpu->sysenter_eip;
        default       :   return 0xbadbadbadbadbadbULL;
    }
} 

static inline void qsim_update_seg(int seg) {
    CPUX86State *cpu = (CPUX86State *)first_cpu;
    cpu_x86_load_seg_cache(cpu, seg, 
            cpu->segs[seg].selector,
            cpu->segs[seg].base,
            cpu->segs[seg].limit,
            cpu->segs[seg].flags);
}

void set_reg(enum regs r, uint64_t val) {
    CPUX86State *cpu = (CPUX86State *)first_cpu;

    switch (r) {
        case QSIM_RAX:    cpu->regs[R_EAX]          = val;      break;
        case QSIM_RCX:    cpu->regs[R_ECX]          = val;      break;
        case QSIM_RDX:    cpu->regs[R_EDX]          = val;      break;
        case QSIM_RBX:    cpu->regs[R_EBX]          = val;      break;
        case QSIM_RSP:    cpu->regs[R_ESP]          = val;      break;
        case QSIM_RBP:    cpu->regs[R_EBP]          = val;      break;
        case QSIM_RSI:    cpu->regs[R_ESI]          = val;      break;
        case QSIM_RDI:    cpu->regs[R_EDI]          = val;      break;
        case QSIM_FP0:    cpu->fpregs[0].mmx.q      = val;      break;
        case QSIM_FP1:    cpu->fpregs[1].mmx.q      = val;      break;
        case QSIM_FP2:    cpu->fpregs[2].mmx.q      = val;      break;
        case QSIM_FP3:    cpu->fpregs[3].mmx.q      = val;      break;
        case QSIM_FP4:    cpu->fpregs[4].mmx.q      = val;      break;
        case QSIM_FP5:    cpu->fpregs[5].mmx.q      = val;      break;
        case QSIM_FP6:    cpu->fpregs[6].mmx.q      = val;      break;
        case QSIM_FP7:    cpu->fpregs[7].mmx.q      = val;      break;
        case QSIM_FPSP:   cpu->fpstt                = val;      break;
        case QSIM_ES :    cpu->segs[R_ES ].selector = val;      break;
        case QSIM_ESB:    cpu->segs[R_ES ].base     = val;      break;
        case QSIM_ESL:    cpu->segs[R_ES ].limit    = val;      break;
        case QSIM_ESF:    cpu->segs[R_ES ].flags    = val;
                          qsim_update_seg(R_ES);                      break;
        case QSIM_CS :    cpu->segs[R_CS ].selector = val;
                          cpu->segs[R_CS ].base     = val << 4; break;
        case QSIM_CSB:    cpu->segs[R_CS ].base     = val;      break;
        case QSIM_CSL:    cpu->segs[R_CS ].limit    = val;      break;
        case QSIM_CSF:    cpu->segs[R_CS ].flags    = val;
                          qsim_update_seg(R_CS);                      break;
        case QSIM_SS :    cpu->segs[R_SS ].selector = val;
                          cpu->segs[R_SS ].base     = val << 4; break;
        case QSIM_SSB:    cpu->segs[R_SS ].base     = val;      break;
        case QSIM_SSL:    cpu->segs[R_SS ].limit    = val;      break;
        case QSIM_SSF:    cpu->segs[R_SS ].flags    = val;
                          qsim_update_seg(R_SS);                      break;
        case QSIM_DS :    cpu->segs[R_DS ].selector = val;
                          cpu->segs[R_DS ].base     = val << 4; break;
        case QSIM_DSB:    cpu->segs[R_DS ].base     = val;      break;
        case QSIM_DSL:    cpu->segs[R_DS ].limit    = val;      break;
        case QSIM_DSF:    cpu->segs[R_DS ].flags    = val;
                          qsim_update_seg(R_DS);                      break;
        case QSIM_FS :    cpu->segs[R_FS ].selector = val;
                          cpu->segs[R_FS ].base     = val << 4; break;
        case QSIM_FSB:    cpu->segs[R_FS ].base     = val;      break;
        case QSIM_FSL:    cpu->segs[R_FS ].limit    = val;      break;
        case QSIM_FSF:    cpu->segs[R_FS ].flags    = val;
                          qsim_update_seg(R_FS);                      break;
        case QSIM_GS :    cpu->segs[R_GS ].selector = val;
                          cpu->segs[R_GS ].base     = val << 4; break;
        case QSIM_GSB:    cpu->segs[R_GS ].base     = val;      break;
        case QSIM_GSL:    cpu->segs[R_GS ].limit    = val;      break;
        case QSIM_GSF:    cpu->segs[R_GS ].flags    = val;
                          qsim_update_seg(R_GS);                      break;
        case QSIM_RIP:    cpu->eip                  = val;      break;
        case QSIM_CR0:    helper_write_crN(cpu, 0, val);                   break;
        case QSIM_CR2:
                          helper_write_crN(cpu, 2, val);                   break;
        case QSIM_CR3:
                          helper_write_crN(cpu, 3, val);                   break;
        case QSIM_CR4:
                          helper_write_crN(cpu, 4, val);                   break;
        case QSIM_GDTB:   cpu->gdt.base             = val;      break;
        case QSIM_GDTL:   cpu->gdt.limit            = val;      break;
        case QSIM_IDTB:   cpu->idt.base             = val;      break;
        case QSIM_IDTL:   cpu->idt.limit            = val;      break;
        case QSIM_RFLAGS: cpu_load_eflags(cpu, val, ~(CC_O | CC_S | CC_Z | CC_A |
                                                      CC_P | CC_C | DF_MASK));
                          break;
        case QSIM_TR:     cpu->tr.selector          = val;      break;
        case QSIM_TRB:    cpu->tr.base              = val;      break;
        case QSIM_TRL:    cpu->tr.limit             = val;      break;
        case QSIM_TRF:    cpu->tr.flags             = val;      break;
        case QSIM_LDT:    cpu->ldt.selector         = val;      break;
        case QSIM_LDTB:   cpu->ldt.base             = val;      break;
        case QSIM_LDTL:   cpu->ldt.limit            = val;      break;
        case QSIM_LDTF:   cpu->ldt.flags            = val;      break;
        case QSIM_DR6:    cpu->dr[6]                = val;      break;
        case QSIM_DR7:    cpu->dr[7]                = val;      break;
        case QSIM_HFLAGS: cpu->hflags               = val;      break;
        case QSIM_HFLAGS2:cpu->hflags2              = val;      break;
        case QSIM_SE_CS:  cpu->sysenter_cs          = val;      break;
        case QSIM_SE_SP:  cpu->sysenter_esp         = val;      break;
        case QSIM_SE_IP:  cpu->sysenter_eip         = val;      break;
        default:          break;
    }
}

target_ulong helper_inst_callback(CPUX86State *env, target_ulong vaddr,
        target_ulong length, target_ulong type)
{
    if (atomic_flag || nonatomic_locked) {
        printf("!!!! %p: Inst helper while holding lock. !!!!\n", (void*)qsim_eip);
    }

    if (atomic_flag && atomic_locked) {
        qsim_aunlock_addr(qsim_ram_l, qsim_phys_addr);
        atomic_flag = 0;
        atomic_locked = 0;
    }

    if (nonatomic_locked) {
        qsim_unlock_addr(qsim_ram_l, qsim_locked_addr);
        nonatomic_locked = 0;
    }

    while (qsim_icount == 0) {
        swapcontext(&qemu_context, &main_context);
    }

    qsim_eip = vaddr;

    qsim_icount--;

    if (qsim_inst_cb != NULL) {
        qsim_memop_flag = 1;
        cpu_ldub_code(env, vaddr);
        qsim_memop_flag = 0;
        // Using our own now because qemu_ram_addr_from_host had some weird
        // results.
        qsim_phys_addr = qsim_ram_addr_from_host((void *)qsim_host_addr);
        qsim_inst_cb(qsim_id, vaddr, qsim_phys_addr, length,
                (uint8_t*)qsim_host_addr, type);
    }
    return 0;
}

static void memop_callback(CPUX86State *env, target_ulong adr,
        target_ulong size, int type)
{
    if (qsim_mem_cb) {
        // Handle unaligned page-crossing accessess as a series of aligned accesses.
        if ((size-1)&adr && (adr&0xfff)+size >= 0x1000) {
            memop_callback(env, adr,          size/2, type);
            memop_callback(env, adr + size/2, size/2, type);
        } else {
            helper_ldb_mmu(env, adr, 0);
            qsim_phys_addr = qsim_ram_addr_from_host((void *)qsim_host_addr);
            if (qsim_mem_cb(qsim_id, adr, qsim_phys_addr, size, type))
                swapcontext(&qemu_context, &main_context);
        }
    }
}

target_ulong helper_store_callback_pre(CPUX86State *env, target_ulong vaddr,
        target_ulong size, target_ulong data)
{
    qsim_memop_flag = 1;

    helper_ldb_mmu(env, vaddr, 0);
    qsim_phys_addr = qsim_ram_addr_from_host((void *)qsim_host_addr);

    if (atomic_flag && !atomic_locked) {
        atomic_locked = 1;
        atomic_addr = qsim_phys_addr;
        qsim_alock_addr(qsim_ram_l, qsim_phys_addr);
    } else if (!atomic_flag) {
        qsim_lock_addr(qsim_ram_l, qsim_phys_addr);
        qsim_locked_addr = qsim_phys_addr;
        nonatomic_locked = 1;
    }

    return 0;
}

target_ulong helper_load_callback_pre(CPUX86State *env, target_ulong vaddr, target_ulong size) 
{
    qsim_memop_flag = 1;

    helper_ldb_mmu(env, vaddr, 0);
    qsim_phys_addr = qsim_ram_addr_from_host((void *)qsim_host_addr);

    if (atomic_flag && !atomic_locked) {
        atomic_locked = 1;
        atomic_addr = qsim_phys_addr;
        qsim_alock_addr(qsim_ram_l, qsim_phys_addr);
    } else if (!atomic_flag) {
        qsim_lock_addr(qsim_ram_l, qsim_phys_addr);
        qsim_locked_addr = qsim_phys_addr;
        nonatomic_locked = 1;
    }

    memop_callback(env, vaddr, size, 0);

    return 0;
}

target_ulong helper_store_callback_post(CPUX86State *env,  target_ulong vaddr,
        target_ulong size, target_ulong data)
{
    memop_callback(env, vaddr, size, 1);

    if (nonatomic_locked) {
        qsim_unlock_addr(qsim_ram_l, qsim_locked_addr);
        nonatomic_locked = 0;
    }

    qsim_memop_flag = 0;

    return 0;
}

target_ulong helper_load_callback_post(CPUX86State *env, target_ulong vaddr, target_ulong size)
{
    if (nonatomic_locked) {
        qsim_unlock_addr(qsim_ram_l, qsim_locked_addr);
        nonatomic_locked = 0;
    }

    qsim_memop_flag = 0;

    return 0;
}


uint8_t mem_rd(CPUX86State *env, uint64_t paddr) {
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    uint8_t b = ldub_phys(cs->as, paddr); // ldub_kernel(vaddr)*/0;
    qsim_memop_flag = bak;
    return b;
}

void mem_wr(CPUX86State *env, uint64_t paddr, uint8_t value) {
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    stb_phys(cs->as, paddr, value);
    qsim_memop_flag = bak;
}

uint8_t mem_rd_virt(CPUX86State *env, uint64_t vaddr) {
    // This is known to fail on guest operating systems that support the NX bit.
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    char b = cpu_ldub_code(env, vaddr);
    qsim_memop_flag = bak;
    return b;
}

void mem_wr_virt(CPUX86State *env, uint64_t vaddr, uint8_t value) {
    // This is known to fail on guest operating systems that support the NX bit.
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    cpu_ldub_code(env, vaddr); // discard result but get the host address
    (*(uint8_t *)qsim_host_addr) = value;
    qsim_memop_flag = bak;
}
