/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_PLUGIN_H
#define QEMU_PLUGIN_H

#include "qemu/config-file.h"
#include "plugins/qemu-plugin.h"
#include "qemu/error-report.h"
#include "qemu/queue.h"
#include "qemu/option.h"
#include "qemu/plugin-event.h"
#include "qemu/bitmap.h"
#include "exec/memopidx.h"
#include "hw/core/cpu.h"

/*
 * Option parsing/processing.
 * Note that we can load an arbitrary number of plugins.
 */
struct qemu_plugin_desc;
typedef QTAILQ_HEAD(, qemu_plugin_desc) QemuPluginList;

/*
 * Construct a qemu_plugin_meminfo_t.
 */
static inline qemu_plugin_meminfo_t
make_plugin_meminfo(MemOpIdx oi, enum qemu_plugin_mem_rw rw)
{
    return oi | (rw << 16);
}

#define QEMU_PLUGIN_MEMINFO_ATOMIC (1U << 18)
#define QEMU_PLUGIN_MEMINFO_ATOMIC_FAILED (1U << 19)

static inline qemu_plugin_meminfo_t
make_plugin_atomic_meminfo(MemOpIdx oi, enum qemu_plugin_mem_rw rw)
{
    return make_plugin_meminfo(oi, rw) | QEMU_PLUGIN_MEMINFO_ATOMIC;
}

/*
 * Extract the memory operation direction from a qemu_plugin_meminfo_t.
 * Other portions may be extracted via get_memop and get_mmuidx.
 */
static inline enum qemu_plugin_mem_rw
get_plugin_meminfo_rw(qemu_plugin_meminfo_t i)
{
    return (i >> 16) & QEMU_PLUGIN_MEM_RW;
}

#ifdef CONFIG_PLUGIN
extern QemuOptsList qemu_plugin_opts;

static inline void qemu_plugin_add_opts(void)
{
    qemu_add_opts(&qemu_plugin_opts);
}

void qemu_plugin_opt_parse(const char *optstr, QemuPluginList *head);
int qemu_plugin_load_list(QemuPluginList *head, Error **errp);

union qemu_plugin_cb_sig {
    qemu_plugin_udata_cb_t               udata;
    qemu_plugin_vcpu_udata_cb_t          vcpu_udata;
    qemu_plugin_vcpu_discon_cb_t         vcpu_discon;
    qemu_plugin_vcpu_tb_trans_cb_t       vcpu_tb_trans;
    qemu_plugin_vcpu_mem_cb_t            vcpu_mem;
    qemu_plugin_vcpu_syscall_cb_t        vcpu_syscall;
    qemu_plugin_vcpu_syscall_ret_cb_t    vcpu_syscall_ret;
    qemu_plugin_vcpu_syscall_filter_cb_t vcpu_syscall_filter;
    qemu_plugin_user_task_cb_t           user_task;
    qemu_plugin_user_mapping_cb_t        user_mapping;
    qemu_plugin_user_image_cb_t          user_image;
    qemu_plugin_vcpu_tb_edge_cb_t        tb_edge;
    qemu_plugin_branch_cb_t              branch;
    qemu_plugin_routine_cb_t             routine;
    qemu_plugin_user_signal_cb_t         user_signal;
    qemu_plugin_exception_cb_t           exception;
    void *generic;
};

enum plugin_dyn_cb_type {
    PLUGIN_CB_REGULAR,
    PLUGIN_CB_COND,
    PLUGIN_CB_MEM_REGULAR,
    PLUGIN_CB_MEM_COND,
    PLUGIN_CB_TRACE_INSN,
    PLUGIN_CB_MEM_TRACE,
    PLUGIN_CB_INLINE_ADD_U64,
    PLUGIN_CB_INLINE_STORE_U64,
    PLUGIN_CB_REDIRECT,
};

struct qemu_plugin_regular_cb {
    union qemu_plugin_cb_sig f;
    TCGHelperInfo *info;
    void *userp;
    enum qemu_plugin_mem_rw rw;
    enum qemu_plugin_cond cond;
    qemu_plugin_u64 entry;
    uint64_t imm;
};

struct qemu_plugin_inline_cb {
    qemu_plugin_u64 entry;
    uint64_t imm;
    enum qemu_plugin_mem_rw rw;
};

struct qemu_plugin_trace_cb {
    struct qemu_plugin_trace_buffer *buffer;
    uint64_t pc;
    enum qemu_plugin_trace_kind kind;
    enum qemu_plugin_mem_rw rw;
};

struct qemu_plugin_conditional_cb {
    union qemu_plugin_cb_sig f;
    TCGHelperInfo *info;
    void *userp;
    qemu_plugin_u64 entry;
    enum qemu_plugin_cond cond;
    uint64_t imm;
};

/*
 * A dynamic callback has an insertion point that is determined at run-time.
 * Usually the insertion point is somewhere in the code cache; think for
 * instance of a callback to be called upon the execution of a particular TB.
 */
struct qemu_plugin_dyn_cb {
    enum plugin_dyn_cb_type type;
    union {
        struct qemu_plugin_regular_cb regular;
        struct qemu_plugin_conditional_cb cond;
        struct qemu_plugin_inline_cb inline_insn;
        struct qemu_plugin_trace_cb trace;
        uint64_t redirect_pc;
    };
};

/* Internal context for instrumenting an instruction */
struct qemu_plugin_insn {
    uint64_t vaddr;
    GArray *insn_cbs;
    GArray *after_cbs;
    GArray *mem_cbs;
    uint8_t len;
    uint32_t properties;
    bool has_direct_target;
    uint64_t direct_target;
    bool calls_helpers;

    /* if set, the instruction calls helpers that might access guest memory */
    bool mem_helper;
};

/* A scoreboard is an array of values, indexed by vcpu_index */
struct qemu_plugin_scoreboard {
    GArray *data;
    QLIST_ENTRY(qemu_plugin_scoreboard) entry;
};

/* Private layout shared by the trace-buffer API and TCG's direct writer. */
struct trace_buffer_vcpu {
    uint8_t *records;
    uint32_t used;
    bool in_callback;
};

struct qemu_plugin_trace_buffer {
    struct qemu_plugin_scoreboard *score;
    size_t record_size;
    size_t capacity;
    qemu_plugin_trace_buffer_cb_t cb;
    void *userdata;
};

/* Internal context for this TranslationBlock */
struct qemu_plugin_tb {
    GPtrArray *insns;
    size_t n;

    /* if set, the TB calls helpers that might access guest memory */
    bool mem_helper;

    GArray *cbs;
};

/**
 * struct CPUPluginState - per-CPU state for plugins
 * @event_mask: plugin event bitmap. Modified only via async work.
 */
struct CPUPluginState {
    DECLARE_BITMAP(event_mask, QEMU_PLUGIN_EV_MAX);
    bool edge_pending;
    struct qemu_plugin_tb_edge edge;
    qemu_plugin_exclusive_cb_t exclusive_cb;
    qemu_plugin_id_t exclusive_id;
    void *exclusive_userdata;
};

/**
 * qemu_plugin_create_vcpu_state: allocate plugin state
 *
 * The returned data must be released with g_free()
 * when no longer required.
 */
CPUPluginState *qemu_plugin_create_vcpu_state(void);

void qemu_plugin_vcpu_init_hook(CPUState *cpu);
void qemu_plugin_vcpu_exit_hook(CPUState *cpu);
void qemu_plugin_tb_trans_cb(CPUState *cpu, struct qemu_plugin_tb *tb);
void qemu_plugin_vcpu_idle_cb(CPUState *cpu);
void qemu_plugin_vcpu_resume_cb(CPUState *cpu);
void qemu_plugin_vcpu_interrupt_cb(CPUState *cpu, uint64_t from);
void qemu_plugin_vcpu_exception_cb(CPUState *cpu, uint64_t from);
void qemu_plugin_vcpu_hostcall_cb(CPUState *cpu, uint64_t from);
void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1,
                         uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8);
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret);
bool
qemu_plugin_vcpu_syscall_filter(CPUState *cpu, int64_t num, uint64_t a1,
                                uint64_t a2, uint64_t a3, uint64_t a4,
                                uint64_t a5, uint64_t a6, uint64_t a7,
                                uint64_t a8, int64_t *sysret);

void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                             uint64_t value_low,
                             uint64_t value_high,
                             MemOpIdx oi, enum qemu_plugin_mem_rw rw,
                             bool atomic, bool atomic_success);

void qemu_plugin_vcpu_mem_cond_wrapper(unsigned int vcpu_index,
                                       qemu_plugin_meminfo_t info,
                                       uint64_t vaddr, void *userdata);

void qemu_plugin_trace_insn_record(unsigned int vcpu_index,
                                   struct qemu_plugin_trace_buffer *buffer,
                                   uint64_t pc, uint32_t kind);
void qemu_plugin_trace_mem_record(unsigned int vcpu_index,
                                  qemu_plugin_meminfo_t info,
                                  uint64_t vaddr,
                                  struct qemu_plugin_trace_buffer *buffer,
                                  uint64_t pc);
G_NORETURN void qemu_plugin_redirect_pc(uint64_t target_pc);

void qemu_plugin_vcpu_tb_edge_exit(unsigned int vcpu_index, uint64_t from_pc,
                                   uint64_t sequential_pc,
                                   uint32_t from_properties,
                                   bool has_direct_target,
                                   uint64_t direct_target);
void qemu_plugin_vcpu_tb_edge_entry(unsigned int vcpu_index, uint64_t to_pc);
void qemu_plugin_process_exclusive(CPUState *cpu);

void qemu_plugin_flush_cb(void);

void qemu_plugin_atexit_cb(void);

void qemu_plugin_add_dyn_cb_arr(GArray *arr);

static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
{
    cpu->neg.plugin_mem_cbs = NULL;
}

/**
 * qemu_plugin_user_exit(): clean-up callbacks before calling exit callbacks
 *
 * This is a user-mode only helper that ensure we have fully cleared
 * callbacks from all threads before calling the exit callbacks. This
 * is so the plugins themselves don't have to jump through hoops to
 * guard against race conditions.
 */
void qemu_plugin_user_exit(void);

/**
 * qemu_plugin_user_prefork_lock(): take plugin lock before forking
 *
 * This is a user-mode only helper to take the internal plugin lock
 * before a fork event. This is ensure a consistent lock state
 */
void qemu_plugin_user_prefork_lock(void);

/**
 * qemu_plugin_user_postfork(): reset the plugin lock
 * @is_child: is this thread the child
 *
 * This user-mode only helper resets the lock state after a fork so we
 * can continue using the plugin interface.
 */
void qemu_plugin_user_postfork(bool is_child);

void qemu_plugin_user_task_notify(enum qemu_plugin_user_task_event_type type,
                                  uint64_t related_pid, const char *path);
void qemu_plugin_user_signal_notify(int signo, int code, bool has_fault_addr,
                                    uint64_t fault_addr);
void qemu_plugin_user_mapping_notify(
    enum qemu_plugin_user_mapping_event_type type,
    uint64_t addr, uint64_t len, uint64_t old_addr, uint64_t old_len,
    uint32_t prot, uint32_t flags, int fd, uint64_t offset);

enum qemu_plugin_cb_flags tcg_call_to_qemu_plugin_cb_flags(int flags);

static inline void qemu_plugin_set_cb_flags(CPUState *cpu,
                                            enum qemu_plugin_cb_flags flags)
{
    assert(cpu);
    cpu->neg.plugin_cb_flags = flags;
}

static inline enum qemu_plugin_cb_flags qemu_plugin_get_cb_flags(void)
{
    assert(current_cpu);
    return current_cpu->neg.plugin_cb_flags;
}

#else /* !CONFIG_PLUGIN */

static inline void qemu_plugin_add_opts(void)
{ }

static inline void qemu_plugin_opt_parse(const char *optstr,
                                         QemuPluginList *head)
{
    error_report("plugin interface not enabled in this build");
    exit(1);
}

static inline int qemu_plugin_load_list(QemuPluginList *head, Error **errp)
{
    return 0;
}

static inline void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_tb_trans_cb(CPUState *cpu,
                                           struct qemu_plugin_tb *tb)
{ }

static inline void qemu_plugin_vcpu_idle_cb(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_resume_cb(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_interrupt_cb(CPUState *cpu, uint64_t from)
{ }

static inline void qemu_plugin_vcpu_exception_cb(CPUState *cpu, uint64_t from)
{ }

static inline void qemu_plugin_vcpu_hostcall_cb(CPUState *cpu, uint64_t from)
{ }

static inline void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                         uint64_t a7, uint64_t a8)
{ }

static inline
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret)
{ }

static inline bool
qemu_plugin_vcpu_syscall_filter(CPUState *cpu, int64_t num, uint64_t a1,
                                uint64_t a2, uint64_t a3, uint64_t a4,
                                uint64_t a5, uint64_t a6, uint64_t a7,
                                uint64_t a8, int64_t *sysret)
{
    return false;
}

static inline void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                                           uint64_t value_low,
                                           uint64_t value_high,
                                           MemOpIdx oi,
                                           enum qemu_plugin_mem_rw rw,
                                           bool atomic, bool atomic_success)
{ }

static inline void qemu_plugin_flush_cb(void)
{ }

static inline void qemu_plugin_atexit_cb(void)
{ }

static inline
void qemu_plugin_add_dyn_cb_arr(GArray *arr)
{ }

static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
{ }

static inline void qemu_plugin_user_exit(void)
{ }

static inline void qemu_plugin_user_prefork_lock(void)
{ }

static inline void qemu_plugin_user_postfork(bool is_child)
{ }

static inline void qemu_plugin_user_task_notify(
    enum qemu_plugin_user_task_event_type type,
    uint64_t related_pid, const char *path)
{ }

static inline void qemu_plugin_user_mapping_notify(
    enum qemu_plugin_user_mapping_event_type type,
    uint64_t addr, uint64_t len, uint64_t old_addr, uint64_t old_len,
    uint32_t prot, uint32_t flags, int fd, uint64_t offset)
{ }

#endif /* !CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_H */
