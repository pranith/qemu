/*
 * QEMU Plugin Core code
 *
 * This is the core code that deals with injecting instrumentation into the code
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "qemu/option.h"
#include "qemu/plugin.h"
#include "plugins/qemu-plugin.h"
#include "qemu/queue.h"
#include "qemu/rcu_queue.h"
#include "qemu/rcu.h"
#include "exec/tb-flush.h"
#include "disas/disas.h"
#include "tcg/tcg-op-common.h"
#include "plugin.h"

struct qemu_plugin_cb {
    struct qemu_plugin_ctx *ctx;
    union qemu_plugin_cb_sig f;
    void *udata;
    QLIST_ENTRY(qemu_plugin_cb) entry;
};

struct qemu_plugin_state plugin;

struct qemu_plugin_ctx *plugin_id_to_ctx_locked(qemu_plugin_id_t id)
{
    struct qemu_plugin_ctx *ctx;
    qemu_plugin_id_t *id_p;

    id_p = g_hash_table_lookup(plugin.id_ht, &id);
    ctx = container_of(id_p, struct qemu_plugin_ctx, id);
    if (ctx == NULL) {
        error_report("plugin: invalid plugin id %" PRIu64, id);
        abort();
    }
    return ctx;
}

static void plugin_cpu_update__async(CPUState *cpu, run_on_cpu_data data)
{
    bitmap_copy(cpu->plugin_state->event_mask,
                &data.host_ulong, QEMU_PLUGIN_EV_MAX);
    if (!test_bit(QEMU_PLUGIN_EV_VCPU_TB_EDGE,
                  cpu->plugin_state->event_mask) &&
        !test_bit(QEMU_PLUGIN_EV_VCPU_ROUTINE,
                  cpu->plugin_state->event_mask)) {
        cpu->plugin_state->edge_pending = false;
    }
    tcg_flush_jmp_cache(cpu);
}

static void plugin_cpu_update__locked(gpointer k, gpointer v, gpointer udata)
{
    CPUState *cpu = container_of(k, CPUState, cpu_index);
    run_on_cpu_data mask = RUN_ON_CPU_HOST_ULONG(*plugin.mask);

    async_run_on_cpu(cpu, plugin_cpu_update__async, mask);
}

void plugin_unregister_cb__locked(struct qemu_plugin_ctx *ctx,
                                  enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb = ctx->callbacks[ev];

    if (cb == NULL) {
        return;
    }
    QLIST_REMOVE_RCU(cb, entry);
    g_free(cb);
    ctx->callbacks[ev] = NULL;
    if (QLIST_EMPTY_RCU(&plugin.cb_lists[ev])) {
        clear_bit(ev, plugin.mask);
        g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update__locked, NULL);
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
static void plugin_vcpu_cb__udata(CPUState *cpu, enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_VCPU_INIT:
    case QEMU_PLUGIN_EV_VCPU_IDLE:
    case QEMU_PLUGIN_EV_VCPU_RESUME:
    case QEMU_PLUGIN_EV_VCPU_EXIT:
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_vcpu_udata_cb_t func = cb->f.vcpu_udata;
            func(cpu->cpu_index, cb->udata);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
static void plugin_vcpu_cb__discon(CPUState *cpu,
                                   enum qemu_plugin_event ev,
                                   enum qemu_plugin_discon_type type,
                                   uint64_t from)
{
    struct qemu_plugin_cb *cb, *next;
    uint64_t to = cpu->cc->get_pc(cpu);

    cpu->plugin_state->edge_pending = false;

    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS_PC);
    if (cpu->cpu_index < plugin.num_vcpus) {
        /* iterate safely; plugins might uninstall themselves at any time */
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_vcpu_discon_cb_t func = cb->f.vcpu_discon;
            func(cpu->cpu_index, type, from, to, cb->udata);
        }
    }
    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
}

void qemu_plugin_vcpu_tb_edge_exit(unsigned int vcpu_index, uint64_t from_pc,
                                   uint64_t sequential_pc,
                                   uint32_t from_properties)
{
    CPUPluginState *state = current_cpu->plugin_state;

    g_assert(current_cpu->cpu_index == vcpu_index);
    state->edge.from_pc = from_pc;
    state->edge.sequential_pc = sequential_pc;
    state->edge.from_properties = from_properties;
    state->edge_pending = true;
}

QEMU_DISABLE_CFI
void qemu_plugin_vcpu_tb_edge_entry(unsigned int vcpu_index, uint64_t to_pc)
{
    CPUPluginState *state = current_cpu->plugin_state;
    struct qemu_plugin_cb *cb, *next;

    g_assert(current_cpu->cpu_index == vcpu_index);
    if (!state->edge_pending) {
        return;
    }
    state->edge_pending = false;
    state->edge.to_pc = to_pc;
    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_VCPU_TB_EDGE],
                           entry, next) {
        cb->f.tb_edge(vcpu_index, &state->edge, cb->udata);
    }

    if (test_bit(QEMU_PLUGIN_EV_VCPU_ROUTINE, state->event_mask)) {
        enum qemu_plugin_routine_event_type type;
        const char *name;

        if (state->edge.from_properties & QEMU_PLUGIN_INSN_CALL) {
            type = QEMU_PLUGIN_ROUTINE_ENTRY;
            name = lookup_symbol(to_pc);
        } else if (state->edge.from_properties & QEMU_PLUGIN_INSN_RETURN) {
            type = QEMU_PLUGIN_ROUTINE_RETURN;
            name = lookup_symbol(state->edge.from_pc);
        } else {
            return;
        }
        if (!name || !name[0]) {
            return;
        }
        struct qemu_plugin_routine_event event = {
            .struct_size = sizeof(event),
            .type = type,
            .from_pc = state->edge.from_pc,
            .to_pc = to_pc,
            .name = name,
        };
        qemu_plugin_get_exec_context(&event.context, sizeof(event.context));
        QLIST_FOREACH_SAFE_RCU(cb,
                               &plugin.cb_lists[QEMU_PLUGIN_EV_VCPU_ROUTINE],
                               entry, next) {
            cb->f.routine(&event, cb->udata);
        }
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
static void plugin_cb__udata(enum qemu_plugin_event ev)
{
    struct qemu_plugin_cb *cb, *next;

    switch (ev) {
    case QEMU_PLUGIN_EV_ATEXIT:
    case QEMU_PLUGIN_EV_FLUSH:
        QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
            qemu_plugin_udata_cb_t func = cb->f.udata;

            func(cb->udata);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static void
do_plugin_register_cb(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                      void *func, void *udata)
{
    struct qemu_plugin_ctx *ctx;

    QEMU_LOCK_GUARD(&plugin.lock);
    ctx = plugin_id_to_ctx_locked(id);
    /* if the plugin is on its way out, ignore this request */
    if (unlikely(ctx->uninstalling)) {
        return;
    }
    if (func) {
        struct qemu_plugin_cb *cb = ctx->callbacks[ev];

        if (cb) {
            cb->f.generic = func;
            cb->udata = udata;
        } else {
            cb = g_new(struct qemu_plugin_cb, 1);
            cb->ctx = ctx;
            cb->f.generic = func;
            cb->udata = udata;
            ctx->callbacks[ev] = cb;
            QLIST_INSERT_HEAD_RCU(&plugin.cb_lists[ev], cb, entry);
            if (!test_bit(ev, plugin.mask)) {
                set_bit(ev, plugin.mask);
                g_hash_table_foreach(plugin.cpu_ht, plugin_cpu_update__locked,
                                     NULL);
            }
        }
    } else {
        plugin_unregister_cb__locked(ctx, ev);
    }
}

void plugin_register_cb(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                        void *func)
{
    do_plugin_register_cb(id, ev, func, NULL);
}

void
plugin_register_cb_udata(qemu_plugin_id_t id, enum qemu_plugin_event ev,
                         void *func, void *udata)
{
    do_plugin_register_cb(id, ev, func, udata);
}

CPUPluginState *qemu_plugin_create_vcpu_state(void)
{
    return g_new0(CPUPluginState, 1);
}

static void plugin_grow_scoreboards__locked(CPUState *cpu)
{
    size_t scoreboard_size = plugin.scoreboard_alloc_size;
    bool need_realloc = false;

    if (cpu->cpu_index < scoreboard_size) {
        return;
    }

    while (cpu->cpu_index >= scoreboard_size) {
        scoreboard_size *= 2;
        need_realloc = true;
    }

    if (!need_realloc) {
        return;
    }

    if (QLIST_EMPTY(&plugin.scoreboards)) {
        /* just update size for future scoreboards */
        plugin.scoreboard_alloc_size = scoreboard_size;
        return;
    }

    /*
     * A scoreboard creation/deletion might be in progress. If a new vcpu is
     * initialized at the same time, we are safe, as the new
     * plugin.scoreboard_alloc_size was not yet written.
     */
    qemu_rec_mutex_unlock(&plugin.lock);

    /* cpus must be stopped, as tb might still use an existing scoreboard. */
    start_exclusive();
    /* re-acquire lock */
    qemu_rec_mutex_lock(&plugin.lock);
    /* in case another vcpu is created between unlock and exclusive section. */
    if (scoreboard_size > plugin.scoreboard_alloc_size) {
        struct qemu_plugin_scoreboard *score;
        QLIST_FOREACH(score, &plugin.scoreboards, entry) {
            g_array_set_size(score->data, scoreboard_size);
        }
        plugin.scoreboard_alloc_size = scoreboard_size;
        /* force all tb to be flushed, as scoreboard pointers were changed. */
        tb_flush__exclusive_or_serial();
    }
    end_exclusive();
}

static void qemu_plugin_vcpu_init__async(CPUState *cpu, run_on_cpu_data unused)
{
    bool success;

    assert(cpu->cpu_index != UNASSIGNED_CPU_INDEX);
    qemu_rec_mutex_lock(&plugin.lock);
    plugin.num_vcpus = MAX(plugin.num_vcpus, cpu->cpu_index + 1);
    plugin_cpu_update__locked(&cpu->cpu_index, NULL, NULL);
    success = g_hash_table_insert(plugin.cpu_ht, &cpu->cpu_index,
                                  &cpu->cpu_index);
    g_assert(success);
    plugin_grow_scoreboards__locked(cpu);
    qemu_rec_mutex_unlock(&plugin.lock);

    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS);
    plugin_vcpu_cb__udata(cpu, QEMU_PLUGIN_EV_VCPU_INIT);
    qemu_plugin_user_task_notify(QEMU_PLUGIN_USER_THREAD_START, 0, NULL);
    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
}

void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{
    /* Plugin initialization must wait until the cpu start executing code */
    async_run_on_cpu(cpu, qemu_plugin_vcpu_init__async, RUN_ON_CPU_NULL);
}

void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{
    bool success;

    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS);
    qemu_plugin_user_task_notify(QEMU_PLUGIN_USER_THREAD_EXIT, 0, NULL);
    plugin_vcpu_cb__udata(cpu, QEMU_PLUGIN_EV_VCPU_EXIT);
    plugin_vcpu_storage_exit(cpu->cpu_index);
    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);

    assert(cpu->cpu_index != UNASSIGNED_CPU_INDEX);
    qemu_rec_mutex_lock(&plugin.lock);
    success = g_hash_table_remove(plugin.cpu_ht, &cpu->cpu_index);
    g_assert(success);
    qemu_rec_mutex_unlock(&plugin.lock);
}

struct plugin_for_each_args {
    struct qemu_plugin_ctx *ctx;
    qemu_plugin_vcpu_udata_cb_t cb;
    void *userdata;
};

static void plugin_vcpu_for_each(gpointer k, gpointer v, gpointer udata)
{
    struct plugin_for_each_args *args = udata;
    int cpu_index = *(int *)k;
    args->cb(cpu_index, args->userdata);
}

void qemu_plugin_vcpu_for_each(qemu_plugin_id_t id,
                               qemu_plugin_vcpu_udata_cb_t cb,
                               void *userdata)
{
    struct plugin_for_each_args args;

    if (cb == NULL) {
        return;
    }
    qemu_rec_mutex_lock(&plugin.lock);
    args.ctx = plugin_id_to_ctx_locked(id);
    args.cb = cb;
    args.userdata = userdata;
    g_hash_table_foreach(plugin.cpu_ht, plugin_vcpu_for_each, &args);
    qemu_rec_mutex_unlock(&plugin.lock);
}

/* Allocate and return a callback record */
static struct qemu_plugin_dyn_cb *plugin_get_dyn_cb(GArray **arr)
{
    GArray *cbs = *arr;

    if (!cbs) {
        cbs = g_array_sized_new(false, true,
                                sizeof(struct qemu_plugin_dyn_cb), 1);
        *arr = cbs;
    }

    g_array_set_size(cbs, cbs->len + 1);
    return &g_array_index(cbs, struct qemu_plugin_dyn_cb, cbs->len - 1);
}

static enum plugin_dyn_cb_type op_to_cb_type(enum qemu_plugin_op op)
{
    switch (op) {
    case QEMU_PLUGIN_INLINE_ADD_U64:
        return PLUGIN_CB_INLINE_ADD_U64;
    case QEMU_PLUGIN_INLINE_STORE_U64:
        return PLUGIN_CB_INLINE_STORE_U64;
    default:
        g_assert_not_reached();
    }
}

void plugin_register_inline_op_on_entry(GArray **arr,
                                        enum qemu_plugin_mem_rw rw,
                                        enum qemu_plugin_op op,
                                        qemu_plugin_u64 entry,
                                        uint64_t imm)
{
    struct qemu_plugin_dyn_cb *dyn_cb;

    struct qemu_plugin_inline_cb inline_cb = { .rw = rw,
                                               .entry = entry,
                                               .imm = imm };
    dyn_cb = plugin_get_dyn_cb(arr);
    dyn_cb->type = op_to_cb_type(op);
    dyn_cb->inline_insn = inline_cb;
}

void plugin_register_dyn_cb__udata(GArray **arr,
                                   qemu_plugin_vcpu_udata_cb_t cb,
                                   enum qemu_plugin_cb_flags flags,
                                   void *udata)
{
    static TCGHelperInfo info[4] = {
        [QEMU_PLUGIN_CB_NO_REGS].flags = TCG_CALL_NO_RWG,
        [QEMU_PLUGIN_CB_R_REGS].flags = TCG_CALL_NO_WG,
        [QEMU_PLUGIN_CB_RW_REGS].flags = 0,
        [QEMU_PLUGIN_CB_RW_REGS_PC].flags = 0,
        /*
         * Match qemu_plugin_vcpu_udata_cb_t:
         *   void (*)(uint32_t, void *)
         */
        [0 ... 3].typemask = (dh_typemask(void, 0) |
                              dh_typemask(i32, 1) |
                              dh_typemask(ptr, 2))
    };
    assert((unsigned)flags < ARRAY_SIZE(info));

    struct qemu_plugin_dyn_cb *dyn_cb = plugin_get_dyn_cb(arr);
    struct qemu_plugin_regular_cb regular_cb = { .f.vcpu_udata = cb,
                                                 .userp = udata,
                                                 .info = &info[flags] };
    dyn_cb->type = PLUGIN_CB_REGULAR;
    dyn_cb->regular = regular_cb;
}

void plugin_register_dyn_cond_cb__udata(GArray **arr,
                                        qemu_plugin_vcpu_udata_cb_t cb,
                                        enum qemu_plugin_cb_flags flags,
                                        enum qemu_plugin_cond cond,
                                        qemu_plugin_u64 entry,
                                        uint64_t imm,
                                        void *udata)
{
    static TCGHelperInfo info[4] = {
        [QEMU_PLUGIN_CB_NO_REGS].flags = TCG_CALL_NO_RWG,
        [QEMU_PLUGIN_CB_R_REGS].flags = TCG_CALL_NO_WG,
        [QEMU_PLUGIN_CB_RW_REGS].flags = 0,
        [QEMU_PLUGIN_CB_RW_REGS_PC].flags = 0,
        /*
         * Match qemu_plugin_vcpu_udata_cb_t:
         *   void (*)(uint32_t, void *)
         */
        [0 ... 3].typemask = (dh_typemask(void, 0) |
                              dh_typemask(i32, 1) |
                              dh_typemask(ptr, 2))
    };
    assert((unsigned)flags < ARRAY_SIZE(info));

    struct qemu_plugin_dyn_cb *dyn_cb = plugin_get_dyn_cb(arr);
    struct qemu_plugin_conditional_cb cond_cb = { .userp = udata,
                                                  .f.vcpu_udata = cb,
                                                  .cond = cond,
                                                  .entry = entry,
                                                  .imm = imm,
                                                  .info = &info[flags] };
    dyn_cb->type = PLUGIN_CB_COND;
    dyn_cb->cond = cond_cb;
}

void plugin_register_vcpu_mem_cb(GArray **arr,
                                 void *cb,
                                 enum qemu_plugin_cb_flags flags,
                                 enum qemu_plugin_mem_rw rw,
                                 void *udata)
{
    /*
     * Expect that the underlying type for enum qemu_plugin_meminfo_t
     * is either int32_t or uint32_t, aka int or unsigned int.
     */
    QEMU_BUILD_BUG_ON(
        !__builtin_types_compatible_p(qemu_plugin_meminfo_t, uint32_t) &&
        !__builtin_types_compatible_p(qemu_plugin_meminfo_t, int32_t));

    static TCGHelperInfo info[4] = {
        [QEMU_PLUGIN_CB_NO_REGS].flags = TCG_CALL_NO_RWG,
        [QEMU_PLUGIN_CB_R_REGS].flags = TCG_CALL_NO_WG,
        [QEMU_PLUGIN_CB_RW_REGS].flags = 0,
        [QEMU_PLUGIN_CB_RW_REGS_PC].flags = 0,
        /*
         * Match qemu_plugin_vcpu_mem_cb_t:
         *   void (*)(uint32_t, qemu_plugin_meminfo_t, uint64_t, void *)
         */
        [0 ... 3].typemask =
            (dh_typemask(void, 0) |
             dh_typemask(i32, 1) |
             (__builtin_types_compatible_p(qemu_plugin_meminfo_t, uint32_t)
              ? dh_typemask(i32, 2) : dh_typemask(s32, 2)) |
             dh_typemask(i64, 3) |
             dh_typemask(ptr, 4))
    };
    assert((unsigned)flags < ARRAY_SIZE(info));

    struct qemu_plugin_dyn_cb *dyn_cb = plugin_get_dyn_cb(arr);
    struct qemu_plugin_regular_cb regular_cb = { .userp = udata,
                                                 .rw = rw,
                                                 .f.vcpu_mem = cb,
                                                 .info = &info[flags] };
    dyn_cb->type = PLUGIN_CB_MEM_REGULAR;
    dyn_cb->regular = regular_cb;
}

void plugin_register_vcpu_mem_cond_cb(GArray **arr, void *cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      enum qemu_plugin_cond cond,
                                      qemu_plugin_u64 entry, uint64_t imm,
                                      void *udata)
{
    plugin_register_vcpu_mem_cb(arr, cb, flags, rw, udata);
    struct qemu_plugin_dyn_cb *dyn_cb =
        &g_array_index(*arr, struct qemu_plugin_dyn_cb, (*arr)->len - 1);

    dyn_cb->type = PLUGIN_CB_MEM_COND;
    dyn_cb->regular.cond = cond;
    dyn_cb->regular.entry = entry;
    dyn_cb->regular.imm = imm;
}

void plugin_register_trace_cb(GArray **arr,
                              struct qemu_plugin_trace_buffer *buffer,
                              uint64_t pc, enum qemu_plugin_trace_kind kind,
                              enum qemu_plugin_mem_rw rw)
{
    struct qemu_plugin_dyn_cb *dyn_cb = plugin_get_dyn_cb(arr);

    dyn_cb->type = kind == QEMU_PLUGIN_TRACE_MEMORY ?
                   PLUGIN_CB_MEM_TRACE : PLUGIN_CB_TRACE_INSN;
    dyn_cb->trace.buffer = buffer;
    dyn_cb->trace.pc = pc;
    dyn_cb->trace.kind = kind;
    dyn_cb->trace.rw = rw;
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
void qemu_plugin_tb_trans_cb(CPUState *cpu, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_TB_TRANS;

    /* no plugin_state->event_mask check here; caller should have checked */

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_tb_trans_cb_t func = cb->f.vcpu_tb_trans;

        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS);
        func(tb, cb->udata);
        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
    }
}

static void clamp_syscall_arguments(uint64_t *a1, uint64_t *a2, uint64_t *a3,
                                    uint64_t *a4, uint64_t *a5, uint64_t *a6,
                                    uint64_t *a7, uint64_t *a8)
{
    if (target_long_bits() == 32) {
        const uint64_t mask = UINT32_MAX;
        *a1 &= mask;
        *a2 &= mask;
        *a3 &= mask;
        *a4 &= mask;
        *a5 &= mask;
        *a6 &= mask;
        *a7 &= mask;
        *a8 &= mask;
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_SYSCALL;

    if (!test_bit(ev, cpu->plugin_state->event_mask)) {
        return;
    }

    clamp_syscall_arguments(&a1, &a2, &a3, &a4, &a5, &a6, &a7, &a8);

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_syscall_cb_t func = cb->f.vcpu_syscall;

        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS_PC);
        func(cpu->cpu_index, num, a1, a2, a3, a4, a5, a6, a7, a8, cb->udata);
        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_SYSCALL_RET;

    if (!test_bit(ev, cpu->plugin_state->event_mask)) {
        return;
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_syscall_ret_cb_t func = cb->f.vcpu_syscall_ret;

        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS_PC);
        func(cpu->cpu_index, num, ret, cb->udata);
        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
    }
}

/*
 * Disable CFI checks.
 * The callback function has been loaded from an external library so we do not
 * have type information
 */
QEMU_DISABLE_CFI
bool
qemu_plugin_vcpu_syscall_filter(CPUState *cpu, int64_t num, uint64_t a1,
                                uint64_t a2, uint64_t a3, uint64_t a4,
                                uint64_t a5, uint64_t a6, uint64_t a7,
                                uint64_t a8, int64_t *sysret)
{
    struct qemu_plugin_cb *cb, *next;
    enum qemu_plugin_event ev = QEMU_PLUGIN_EV_VCPU_SYSCALL_FILTER;
    bool filtered = false;

    if (!test_bit(ev, cpu->plugin_state->event_mask)) {
        return false;
    }

    clamp_syscall_arguments(&a1, &a2, &a3, &a4, &a5, &a6, &a7, &a8);

    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS_PC);

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
        qemu_plugin_vcpu_syscall_filter_cb_t func = cb->f.vcpu_syscall_filter;

        if (func(cpu->cpu_index, num, a1, a2, a3, a4,
                 a5, a6, a7, a8, sysret, cb->udata)) {
            filtered = true;
            break;
        }
    }

    qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);

    return filtered;
}

void qemu_plugin_vcpu_idle_cb(CPUState *cpu)
{
    /* idle and resume cb may be called before init, ignore in this case */
    if (cpu->cpu_index < plugin.num_vcpus) {
        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS_PC);
        plugin_vcpu_cb__udata(cpu, QEMU_PLUGIN_EV_VCPU_IDLE);
        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
    }
}

void qemu_plugin_vcpu_resume_cb(CPUState *cpu)
{
    if (cpu->cpu_index < plugin.num_vcpus) {
        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_RW_REGS_PC);
        plugin_vcpu_cb__udata(cpu, QEMU_PLUGIN_EV_VCPU_RESUME);
        qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
    }
}

void qemu_plugin_vcpu_interrupt_cb(CPUState *cpu, uint64_t from)
{
    plugin_vcpu_cb__discon(cpu, QEMU_PLUGIN_EV_VCPU_INTERRUPT,
                           QEMU_PLUGIN_DISCON_INTERRUPT, from);
}

void qemu_plugin_vcpu_exception_cb(CPUState *cpu, uint64_t from)
{
    plugin_vcpu_cb__discon(cpu, QEMU_PLUGIN_EV_VCPU_EXCEPTION,
                           QEMU_PLUGIN_DISCON_EXCEPTION, from);

    if (test_bit(QEMU_PLUGIN_EV_VCPU_EXCEPTION_DETAIL,
                 cpu->plugin_state->event_mask)) {
        struct qemu_plugin_exception_event event = {
            .struct_size = sizeof(event),
            .exception_index = cpu->exception_index,
            .from_pc = from,
            .to_pc = cpu->cc->get_pc(cpu),
        };
        struct qemu_plugin_cb *cb, *next;

        qemu_plugin_get_exec_context(&event.context, sizeof(event.context));
        QLIST_FOREACH_SAFE_RCU(cb,
                               &plugin.cb_lists[
                                   QEMU_PLUGIN_EV_VCPU_EXCEPTION_DETAIL],
                               entry, next) {
            cb->f.exception(&event, cb->udata);
        }
    }
}

void qemu_plugin_vcpu_hostcall_cb(CPUState *cpu, uint64_t from)
{
    plugin_vcpu_cb__discon(cpu, QEMU_PLUGIN_EV_VCPU_HOSTCALL,
                           QEMU_PLUGIN_DISCON_HOSTCALL, from);
}

void qemu_plugin_register_vcpu_idle_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_udata_cb_t cb,
                                       void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_VCPU_IDLE, cb, userdata);
}

void qemu_plugin_register_vcpu_resume_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_udata_cb_t cb,
                                         void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_VCPU_RESUME, cb, userdata);
}

void qemu_plugin_register_vcpu_discon_cb(qemu_plugin_id_t id,
                                         enum qemu_plugin_discon_type type,
                                         qemu_plugin_vcpu_discon_cb_t cb,
                                         void *userdata)
{
    if (type & QEMU_PLUGIN_DISCON_INTERRUPT) {
        plugin_register_cb_udata(id, QEMU_PLUGIN_EV_VCPU_INTERRUPT, cb, userdata);
    }
    if (type & QEMU_PLUGIN_DISCON_EXCEPTION) {
        plugin_register_cb_udata(id, QEMU_PLUGIN_EV_VCPU_EXCEPTION, cb, userdata);
    }
    if (type & QEMU_PLUGIN_DISCON_HOSTCALL) {
        plugin_register_cb_udata(id, QEMU_PLUGIN_EV_VCPU_HOSTCALL, cb, userdata);
    }
}

void qemu_plugin_register_exception_cb(qemu_plugin_id_t id,
                                       qemu_plugin_exception_cb_t cb,
                                       void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_VCPU_EXCEPTION_DETAIL,
                             cb, userdata);
}

void qemu_plugin_register_flush_cb(qemu_plugin_id_t id,
                                   qemu_plugin_udata_cb_t cb,
                                   void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_FLUSH, cb, userdata);
}

static bool free_dyn_cb_arr(void *p, uint32_t h, void *userp)
{
    g_array_free((GArray *) p, true);
    return true;
}

void qemu_plugin_flush_cb(void)
{
    qht_iter_remove(&plugin.dyn_cb_arr_ht, free_dyn_cb_arr, NULL);
    qht_reset(&plugin.dyn_cb_arr_ht);

    plugin_cb__udata(QEMU_PLUGIN_EV_FLUSH);
}

void exec_inline_op(enum plugin_dyn_cb_type type,
                    struct qemu_plugin_inline_cb *cb,
                    int cpu_index)
{
    char *ptr = cb->entry.score->data->data;
    size_t elem_size = g_array_get_element_size(
        cb->entry.score->data);
    size_t offset = cb->entry.offset;
    uint64_t *val = (uint64_t *)(ptr + offset + cpu_index * elem_size);

    switch (type) {
    case PLUGIN_CB_INLINE_ADD_U64:
        *val += cb->imm;
        break;
    case PLUGIN_CB_INLINE_STORE_U64:
        *val = cb->imm;
        break;
    default:
        g_assert_not_reached();
    }
}

static bool plugin_mem_cond_matches(const struct qemu_plugin_regular_cb *cb,
                                    unsigned int vcpu_index)
{
    uint64_t value = qemu_plugin_u64_get(cb->entry, vcpu_index);

    switch (cb->cond) {
    case QEMU_PLUGIN_COND_EQ:
        return value == cb->imm;
    case QEMU_PLUGIN_COND_NE:
        return value != cb->imm;
    case QEMU_PLUGIN_COND_LT:
        return value < cb->imm;
    case QEMU_PLUGIN_COND_LE:
        return value <= cb->imm;
    case QEMU_PLUGIN_COND_GT:
        return value > cb->imm;
    case QEMU_PLUGIN_COND_GE:
        return value >= cb->imm;
    default:
        g_assert_not_reached();
    }
}

QEMU_DISABLE_CFI
void qemu_plugin_vcpu_mem_cond_wrapper(unsigned int vcpu_index,
                                       qemu_plugin_meminfo_t info,
                                       uint64_t vaddr, void *userdata)
{
    struct qemu_plugin_regular_cb *cb = userdata;

    if (plugin_mem_cond_matches(cb, vcpu_index)) {
        cb->f.vcpu_mem(vcpu_index, info, vaddr, cb->userp);
    }
}

void qemu_plugin_trace_insn_record(unsigned int vcpu_index,
                                   struct qemu_plugin_trace_buffer *buffer,
                                   uint64_t pc, uint32_t kind)
{
    struct qemu_plugin_trace_record record = {
        .pc = pc,
        .kind = kind,
    };

    qemu_plugin_trace_buffer_append(buffer, vcpu_index, &record);
}

void qemu_plugin_trace_mem_record(unsigned int vcpu_index,
                                  qemu_plugin_meminfo_t info,
                                  uint64_t vaddr,
                                  struct qemu_plugin_trace_buffer *buffer,
                                  uint64_t pc)
{
    struct qemu_plugin_mem_access_info access;
    struct qemu_plugin_trace_record record = {
        .pc = pc,
        .vaddr = vaddr,
        .kind = QEMU_PLUGIN_TRACE_MEMORY,
    };

    qemu_plugin_mem_get_access_info(info, vaddr, &access);
    record.size = access.size;
    record.is_store = access.is_store;
    record.is_atomic = access.is_atomic;
    record.atomic_success = access.atomic_success;
    record.has_phys_addr = access.has_phys_addr;
    record.has_ram_addr = access.has_ram_addr;
    record.is_io = access.is_io;
    record.phys_addr = access.phys_addr;
    record.ram_addr = access.ram_addr;
    qemu_plugin_trace_buffer_append(buffer, vcpu_index, &record);
}

QEMU_DISABLE_CFI
void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                             uint64_t value_low,
                             uint64_t value_high,
                             MemOpIdx oi, enum qemu_plugin_mem_rw rw,
                             bool atomic, bool atomic_success)
{
    GArray *arr = cpu->neg.plugin_mem_cbs;
    size_t i;

    if (arr == NULL) {
        return;
    }

    cpu->neg.plugin_mem_value_low = value_low;
    cpu->neg.plugin_mem_value_high = value_high;

    for (i = 0; i < arr->len; i++) {
        struct qemu_plugin_dyn_cb *cb =
            &g_array_index(arr, struct qemu_plugin_dyn_cb, i);

        switch (cb->type) {
        case PLUGIN_CB_MEM_TRACE:
            if (rw & cb->trace.rw) {
                qemu_plugin_meminfo_t info = atomic ?
                    make_plugin_atomic_meminfo(oi, rw) :
                    make_plugin_meminfo(oi, rw);
                if (atomic && !atomic_success) {
                    info |= QEMU_PLUGIN_MEMINFO_ATOMIC_FAILED;
                }
                qemu_plugin_trace_mem_record(cpu->cpu_index, info, vaddr,
                                             cb->trace.buffer, cb->trace.pc);
            }
            break;
        case PLUGIN_CB_MEM_REGULAR:
        case PLUGIN_CB_MEM_COND:
            if ((rw & cb->regular.rw) &&
                (cb->type != PLUGIN_CB_MEM_COND ||
                 plugin_mem_cond_matches(&cb->regular, cpu->cpu_index))) {
                qemu_plugin_set_cb_flags(cpu,
                    tcg_call_to_qemu_plugin_cb_flags(cb->regular.info->flags));

                qemu_plugin_meminfo_t info = atomic ?
                    make_plugin_atomic_meminfo(oi, rw) :
                    make_plugin_meminfo(oi, rw);
                if (atomic && !atomic_success) {
                    info |= QEMU_PLUGIN_MEMINFO_ATOMIC_FAILED;
                }

                cb->regular.f.vcpu_mem(cpu->cpu_index, info,
                                       vaddr, cb->regular.userp);
                qemu_plugin_set_cb_flags(cpu, QEMU_PLUGIN_CB_NO_REGS);
            }
            break;
        case PLUGIN_CB_INLINE_ADD_U64:
        case PLUGIN_CB_INLINE_STORE_U64:
            if (rw & cb->inline_insn.rw) {
                exec_inline_op(cb->type, &cb->inline_insn, cpu->cpu_index);
            }
            break;
        default:
            g_assert_not_reached();
        }
    }
}

void qemu_plugin_atexit_cb(void)
{
    plugin_cb__udata(QEMU_PLUGIN_EV_ATEXIT);
}

void qemu_plugin_register_atexit_cb(qemu_plugin_id_t id,
                                    qemu_plugin_udata_cb_t cb,
                                    void *udata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_ATEXIT, cb, udata);
}

/*
 * Handle exit from linux-user. Unlike the normal atexit() mechanism
 * we need to handle the clean-up manually as it's possible threads
 * are still running. We need to remove all callbacks from code
 * generation, flush the current translations and then we can safely
 * trigger the exit callbacks.
 */

void qemu_plugin_user_exit(void)
{
    enum qemu_plugin_event ev;
    CPUState *cpu;

    /*
     * Locking order: we must acquire locks in an order that is consistent
     * with the one in fork_start(). That is:
     * - start_exclusive(), which acquires qemu_cpu_list_lock,
     *   must be called before acquiring plugin.lock.
     */
    start_exclusive();

    qemu_rec_mutex_lock(&plugin.lock);
    /* un-register all callbacks except the final AT_EXIT one */
    for (ev = 0; ev < QEMU_PLUGIN_EV_MAX; ev++) {
        if (ev != QEMU_PLUGIN_EV_ATEXIT) {
            struct qemu_plugin_cb *cb, *next;

            QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[ev], entry, next) {
                plugin_unregister_cb__locked(cb->ctx, ev);
            }
        }
    }
    CPU_FOREACH(cpu) {
        qemu_plugin_disable_mem_helpers(cpu);
    }
    qemu_rec_mutex_unlock(&plugin.lock);

    tb_flush__exclusive_or_serial();
    end_exclusive();

    /* now it's safe to handle the exit case */
    qemu_plugin_atexit_cb();
}

/*
 * Helpers for *-user to ensure locks are sane across fork() events.
 */

void qemu_plugin_user_prefork_lock(void)
{
    qemu_rec_mutex_lock(&plugin.lock);
}

void qemu_plugin_user_postfork(bool is_child)
{
    if (is_child) {
        /* should we just reset via plugin_init? */
        qemu_rec_mutex_init(&plugin.lock);
    } else {
        qemu_rec_mutex_unlock(&plugin.lock);
    }
}

void qemu_plugin_register_user_task_cb(qemu_plugin_id_t id,
                                       qemu_plugin_user_task_cb_t cb,
                                       void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_USER_TASK, cb, userdata);
}

void qemu_plugin_register_user_signal_cb(qemu_plugin_id_t id,
                                         qemu_plugin_user_signal_cb_t cb,
                                         void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_USER_SIGNAL, cb, userdata);
}

QEMU_DISABLE_CFI
void qemu_plugin_user_signal_notify(int signo, int code, bool has_fault_addr,
                                    uint64_t fault_addr)
{
    struct qemu_plugin_user_signal_event event = {
        .struct_size = sizeof(event),
        .signo = signo,
        .code = code,
        .has_fault_addr = has_fault_addr,
        .fault_addr = fault_addr,
    };
    struct qemu_plugin_cb *cb, *next;

    if (!test_bit(QEMU_PLUGIN_EV_USER_SIGNAL, plugin.mask) ||
        !qemu_plugin_get_exec_context(&event.context,
                                      sizeof(event.context)) ||
        event.context.system_emulation) {
        return;
    }
    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_USER_SIGNAL],
                           entry, next) {
        cb->f.user_signal(&event, cb->udata);
    }
}

void qemu_plugin_register_user_mapping_cb(qemu_plugin_id_t id,
                                           qemu_plugin_user_mapping_cb_t cb,
                                           void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_USER_MAPPING, cb, userdata);
}

void qemu_plugin_register_user_image_cb(qemu_plugin_id_t id,
                                        qemu_plugin_user_image_cb_t cb,
                                        void *userdata)
{
    plugin_register_cb_udata(id, QEMU_PLUGIN_EV_USER_IMAGE, cb, userdata);
}

/* Linux PROT_EXEC is 4 on every Linux target supported by linux-user. */
#define PLUGIN_LINUX_PROT_EXEC 4U
#define PLUGIN_LINUX_MREMAP_DONTUNMAP 4U

typedef struct {
    uint64_t id, pid, dev, ino, last_exec_addr;
    size_t exec_segments, mappings;
    bool was_active;
    char *path;
} PluginImage;

typedef struct {
    uint64_t pid, start, len, offset;
    uint32_t prot;
    PluginImage *image;
} PluginImageSegment;

static GPtrArray *plugin_images;
static GPtrArray *plugin_image_segments;
static uint64_t plugin_next_image_id = 1;

static void plugin_image_free(gpointer data)
{
    PluginImage *image = data;
    g_free(image->path);
    g_free(image);
}

static void plugin_images_init(void)
{
    if (!plugin_images) {
        plugin_images = g_ptr_array_new_with_free_func(plugin_image_free);
        plugin_image_segments = g_ptr_array_new_with_free_func(g_free);
    }
}

static uint64_t plugin_range_end(uint64_t start, uint64_t len)
{
    return len > UINT64_MAX - start ? UINT64_MAX : start + len;
}

static PluginImageSegment *plugin_image_segment_copy(PluginImageSegment *src)
{
    return g_memdup2(src, sizeof(*src));
}

static void plugin_image_remove_range(uint64_t pid, uint64_t start,
                                      uint64_t len)
{
    uint64_t end = plugin_range_end(start, len);

    for (guint i = 0; i < plugin_image_segments->len;) {
        PluginImageSegment *seg = g_ptr_array_index(plugin_image_segments, i);
        uint64_t seg_end = plugin_range_end(seg->start, seg->len);

        if (seg->pid != pid || seg_end <= start || end <= seg->start) {
            i++;
            continue;
        }
        if (seg->start < start && end < seg_end) {
            PluginImageSegment *right = plugin_image_segment_copy(seg);
            right->start = end;
            right->offset += end - seg->start;
            right->len = seg_end - end;
            seg->len = start - seg->start;
            g_ptr_array_add(plugin_image_segments, right);
            i++;
        } else if (seg->start < start) {
            seg->len = start - seg->start;
            i++;
        } else if (end < seg_end) {
            seg->offset += end - seg->start;
            seg->start = end;
            seg->len = seg_end - end;
            i++;
        } else {
            g_ptr_array_remove_index_fast(plugin_image_segments, i);
        }
    }
}

static void plugin_image_protect_range(uint64_t pid, uint64_t start,
                                       uint64_t len, uint32_t prot)
{
    uint64_t end = plugin_range_end(start, len);
    guint original_count = plugin_image_segments->len;

    for (guint i = 0; i < original_count; i++) {
        PluginImageSegment *seg = g_ptr_array_index(plugin_image_segments, i);
        uint64_t seg_end = plugin_range_end(seg->start, seg->len);
        uint64_t lo = MAX(start, seg->start);
        uint64_t hi = MIN(end, seg_end);
        uint64_t old_start = seg->start;

        if (seg->pid != pid || lo >= hi) {
            continue;
        }
        if (old_start < lo) {
            PluginImageSegment *left = plugin_image_segment_copy(seg);
            left->len = lo - old_start;
            g_ptr_array_add(plugin_image_segments, left);
        }
        if (hi < seg_end) {
            PluginImageSegment *right = plugin_image_segment_copy(seg);
            right->start = hi;
            right->offset += hi - old_start;
            right->len = seg_end - hi;
            g_ptr_array_add(plugin_image_segments, right);
        }
        seg->offset += lo - old_start;
        seg->start = lo;
        seg->len = hi - lo;
        seg->prot = prot;
    }
}

static PluginImage *plugin_image_find_or_create(
    const struct qemu_plugin_user_mapping_event *event)
{
    uint64_t pid = event->context.pid;

    for (guint i = 0; i < plugin_image_segments->len; i++) {
        PluginImageSegment *seg = g_ptr_array_index(plugin_image_segments, i);
        PluginImage *image = seg->image;

        if (seg->pid == pid && image->dev == event->file_dev &&
            image->ino == event->file_ino) {
            return image;
        }
    }
    PluginImage *image = g_new0(PluginImage, 1);
    image->id = plugin_next_image_id++;
    image->pid = pid;
    image->dev = event->file_dev;
    image->ino = event->file_ino;
    image->path = g_strdup(event->path);
    g_ptr_array_add(plugin_images, image);
    return image;
}

QEMU_DISABLE_CFI
static void plugin_image_emit(PluginImage *image,
                              const struct qemu_plugin_exec_context *context,
                              enum qemu_plugin_user_image_event_type type)
{
    struct qemu_plugin_user_image_event event = {
        .struct_size = sizeof(event),
        .type = type,
        .context = *context,
        .image_id = image->id,
        .file_dev = image->dev,
        .file_ino = image->ino,
        .executable_addr = image->last_exec_addr,
        .path = image->path,
    };
    struct qemu_plugin_cb *cb, *next;

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_USER_IMAGE],
                           entry, next) {
        cb->f.user_image(&event, cb->udata);
    }
}

static void plugin_image_update(
    const struct qemu_plugin_user_mapping_event *event)
{
    uint64_t pid = event->context.pid;
    GPtrArray *moved = NULL;

    QEMU_LOCK_GUARD(&plugin.lock);
    plugin_images_init();
    for (guint i = 0; i < plugin_images->len; i++) {
        PluginImage *image = g_ptr_array_index(plugin_images, i);
        image->was_active = image->exec_segments != 0;
        image->exec_segments = 0;
        image->mappings = 0;
    }

    switch (event->type) {
    case QEMU_PLUGIN_USER_MAP:
        plugin_image_remove_range(pid, event->addr, event->len);
        if (event->file_ino && event->path) {
            PluginImageSegment *seg = g_new0(PluginImageSegment, 1);
            seg->image = plugin_image_find_or_create(event);
            seg->pid = pid;
            seg->start = event->addr;
            seg->len = event->len;
            seg->offset = event->offset;
            seg->prot = event->prot;
            g_ptr_array_add(plugin_image_segments, seg);
        }
        break;
    case QEMU_PLUGIN_USER_UNMAP:
        plugin_image_remove_range(pid, event->addr, event->len);
        break;
    case QEMU_PLUGIN_USER_PROTECT:
        plugin_image_protect_range(pid, event->addr, event->len, event->prot);
        break;
    case QEMU_PLUGIN_USER_REMAP:
        moved = g_ptr_array_new_with_free_func(g_free);
        for (guint i = 0; i < plugin_image_segments->len; i++) {
            PluginImageSegment *seg =
                g_ptr_array_index(plugin_image_segments, i);
            uint64_t lo = MAX(seg->start, event->old_addr);
            uint64_t hi = MIN(plugin_range_end(seg->start, seg->len),
                              plugin_range_end(event->old_addr,
                                               event->old_len));
            if (seg->pid == pid && lo < hi) {
                uint64_t displacement = lo - event->old_addr;
                if (displacement >= event->len) {
                    continue;
                }
                PluginImageSegment *copy = plugin_image_segment_copy(seg);
                copy->offset += lo - seg->start;
                copy->start = event->addr + displacement;
                copy->len = MIN(hi - lo, event->len - displacement);
                g_ptr_array_add(moved, copy);
            }
        }
        if (!(event->flags & PLUGIN_LINUX_MREMAP_DONTUNMAP)) {
            plugin_image_remove_range(pid, event->old_addr, event->old_len);
        }
        plugin_image_remove_range(pid, event->addr, event->len);
        for (guint i = 0; i < moved->len; i++) {
            g_ptr_array_add(plugin_image_segments,
                            g_ptr_array_index(moved, i));
        }
        g_ptr_array_set_free_func(moved, NULL);
        g_ptr_array_free(moved, true);
        break;
    }

    for (guint i = 0; i < plugin_image_segments->len; i++) {
        PluginImageSegment *seg = g_ptr_array_index(plugin_image_segments, i);
        PluginImage *image = seg->image;
        image->mappings++;
        if (seg->prot & PLUGIN_LINUX_PROT_EXEC) {
            image->exec_segments++;
            image->last_exec_addr = seg->start;
        }
    }
    for (guint i = 0; i < plugin_images->len;) {
        PluginImage *image = g_ptr_array_index(plugin_images, i);
        bool is_active = image->exec_segments != 0;

        if (image->was_active != is_active) {
            plugin_image_emit(image, &event->context,
                              is_active ? QEMU_PLUGIN_USER_IMAGE_LOAD :
                                          QEMU_PLUGIN_USER_IMAGE_UNLOAD);
        }
        if (!image->mappings) {
            g_ptr_array_remove_index_fast(plugin_images, i);
        } else {
            i++;
        }
    }
}

static void plugin_image_task_update(
    const struct qemu_plugin_user_task_event *event)
{
    uint64_t pid = event->context.pid;

    QEMU_LOCK_GUARD(&plugin.lock);
    if (!plugin_images) {
        return;
    }
    if (event->type == QEMU_PLUGIN_USER_FORK_CHILD) {
        for (guint i = 0; i < plugin_image_segments->len; i++) {
            PluginImageSegment *seg =
                g_ptr_array_index(plugin_image_segments, i);
            if (seg->pid == event->related_pid) {
                seg->pid = pid;
            }
        }
        for (guint i = 0; i < plugin_images->len; i++) {
            PluginImage *image = g_ptr_array_index(plugin_images, i);
            if (image->pid == event->related_pid) {
                image->pid = pid;
                if (image->exec_segments) {
                    plugin_image_emit(image, &event->context,
                                      QEMU_PLUGIN_USER_IMAGE_LOAD);
                }
            }
        }
    } else if (event->type == QEMU_PLUGIN_USER_PROCESS_EXIT) {
        for (guint i = 0; i < plugin_images->len; i++) {
            PluginImage *image = g_ptr_array_index(plugin_images, i);
            if (image->pid == pid && image->exec_segments) {
                plugin_image_emit(image, &event->context,
                                  QEMU_PLUGIN_USER_IMAGE_UNLOAD);
            }
        }
        for (guint i = 0; i < plugin_image_segments->len;) {
            PluginImageSegment *seg =
                g_ptr_array_index(plugin_image_segments, i);
            if (seg->pid == pid) {
                g_ptr_array_remove_index_fast(plugin_image_segments, i);
            } else {
                i++;
            }
        }
        for (guint i = 0; i < plugin_images->len;) {
            PluginImage *image = g_ptr_array_index(plugin_images, i);
            if (image->pid == pid) {
                g_ptr_array_remove_index_fast(plugin_images, i);
            } else {
                i++;
            }
        }
    }
}

bool qemu_plugin_user_image_lookup(uint64_t vaddr, uint64_t *image_id,
                                   uint64_t *file_offset, char **path)
{
    struct qemu_plugin_exec_context context;

    if (!qemu_plugin_get_exec_context(&context, sizeof(context)) ||
        context.system_emulation) {
        return false;
    }
    QEMU_LOCK_GUARD(&plugin.lock);
    if (!plugin_image_segments) {
        return false;
    }
    for (guint i = 0; i < plugin_image_segments->len; i++) {
        PluginImageSegment *seg = g_ptr_array_index(plugin_image_segments, i);
        if (seg->pid == context.pid && vaddr >= seg->start &&
            vaddr - seg->start < seg->len) {
            if (image_id) {
                *image_id = seg->image->id;
            }
            if (file_offset) {
                *file_offset = seg->offset + vaddr - seg->start;
            }
            if (path) {
                *path = g_strdup(seg->image->path);
            }
            return true;
        }
    }
    return false;
}

/* Both notifications are synchronous; event-owned strings expire on return. */
QEMU_DISABLE_CFI
void qemu_plugin_user_task_notify(enum qemu_plugin_user_task_event_type type,
                                  uint64_t related_pid, const char *path)
{
    struct qemu_plugin_user_task_event event = {
        .struct_size = sizeof(event),
        .type = type,
        .related_pid = related_pid,
        .path = path,
    };
    struct qemu_plugin_cb *cb, *next;

    if ((!test_bit(QEMU_PLUGIN_EV_USER_TASK, plugin.mask) &&
         !test_bit(QEMU_PLUGIN_EV_USER_IMAGE, plugin.mask)) ||
        !qemu_plugin_get_exec_context(&event.context,
                                      sizeof(event.context)) ||
        event.context.system_emulation) {
        return;
    }

    if (test_bit(QEMU_PLUGIN_EV_USER_IMAGE, plugin.mask)) {
        plugin_image_task_update(&event);
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_USER_TASK],
                           entry, next) {
        cb->f.user_task(&event, cb->udata);
    }
}

QEMU_DISABLE_CFI
void qemu_plugin_user_mapping_notify(
    enum qemu_plugin_user_mapping_event_type type,
    uint64_t addr, uint64_t len, uint64_t old_addr, uint64_t old_len,
    uint32_t prot, uint32_t flags, int fd, uint64_t offset)
{
    struct qemu_plugin_user_mapping_event event = {
        .struct_size = sizeof(event),
        .type = type,
        .addr = addr,
        .len = len,
        .old_addr = old_addr,
        .old_len = old_len,
        .prot = prot,
        .flags = flags,
        .offset = offset,
    };
    struct qemu_plugin_cb *cb, *next;
    g_autofree char *path = NULL;
    bool want_mapping = test_bit(QEMU_PLUGIN_EV_USER_MAPPING, plugin.mask);
    bool want_image = test_bit(QEMU_PLUGIN_EV_USER_IMAGE, plugin.mask);

    if (!want_mapping && !want_image) {
        return;
    }
    if (!qemu_plugin_get_exec_context(&event.context,
                                      sizeof(event.context)) ||
        event.context.system_emulation) {
        return;
    }

    if (fd >= 0) {
        struct stat st;
        g_autofree char *link = g_strdup_printf("/proc/self/fd/%d", fd);

        if (fstat(fd, &st) == 0) {
            event.file_dev = st.st_dev;
            event.file_ino = st.st_ino;
        }
        path = g_file_read_link(link, NULL);
        event.path = path;
    }

    if (want_image) {
        plugin_image_update(&event);
    }

    QLIST_FOREACH_SAFE_RCU(cb, &plugin.cb_lists[QEMU_PLUGIN_EV_USER_MAPPING],
                           entry, next) {
        cb->f.user_mapping(&event, cb->udata);
    }
}

static bool plugin_dyn_cb_arr_cmp(const void *ap, const void *bp)
{
    return ap == bp;
}

static void __attribute__((__constructor__)) plugin_init(void)
{
    int i;

    for (i = 0; i < QEMU_PLUGIN_EV_MAX; i++) {
        QLIST_INIT(&plugin.cb_lists[i]);
    }
    qemu_rec_mutex_init(&plugin.lock);
    plugin.id_ht = g_hash_table_new(g_int64_hash, g_int64_equal);
    plugin.cpu_ht = g_hash_table_new(g_int_hash, g_int_equal);
    QLIST_INIT(&plugin.scoreboards);
    plugin.scoreboard_alloc_size = 16; /* avoid frequent reallocation */
    QTAILQ_INIT(&plugin.ctxs);
    qht_init(&plugin.dyn_cb_arr_ht, plugin_dyn_cb_arr_cmp, 16,
             QHT_MODE_AUTO_RESIZE);
    atexit(qemu_plugin_atexit_cb);
}

int plugin_num_vcpus(void)
{
    return plugin.num_vcpus;
}

struct qemu_plugin_scoreboard *plugin_scoreboard_new(size_t element_size)
{
    struct qemu_plugin_scoreboard *score =
        g_malloc0(sizeof(struct qemu_plugin_scoreboard));
    score->data = g_array_new(FALSE, TRUE, element_size);
    g_array_set_size(score->data, plugin.scoreboard_alloc_size);

    qemu_rec_mutex_lock(&plugin.lock);
    QLIST_INSERT_HEAD(&plugin.scoreboards, score, entry);
    qemu_rec_mutex_unlock(&plugin.lock);

    return score;
}

void plugin_scoreboard_free(struct qemu_plugin_scoreboard *score)
{
    qemu_rec_mutex_lock(&plugin.lock);
    QLIST_REMOVE(score, entry);
    qemu_rec_mutex_unlock(&plugin.lock);

    g_array_free(score->data, TRUE);
    g_free(score);
}

struct qemu_plugin_vcpu_storage {
    qemu_plugin_id_t owner;
    struct qemu_plugin_scoreboard *score;
    size_t size, data_offset;
    qemu_plugin_vcpu_storage_dtor_t dtor;
    void *userdata;
};

static GPtrArray *plugin_vcpu_storages;

static uint8_t *plugin_storage_slot(struct qemu_plugin_vcpu_storage *storage,
                                    unsigned int vcpu_index)
{
    return qemu_plugin_scoreboard_find(storage->score, vcpu_index);
}

static void plugin_storage_destroy(struct qemu_plugin_vcpu_storage *storage)
{
    for (unsigned int i = 0; i < plugin.num_vcpus; i++) {
        uint8_t *slot = plugin_storage_slot(storage, i);
        if (slot[0] && storage->dtor) {
            storage->dtor(i, slot + storage->data_offset,
                          storage->userdata);
        }
    }
    plugin_scoreboard_free(storage->score);
    g_free(storage);
}

struct qemu_plugin_vcpu_storage *qemu_plugin_vcpu_storage_new(
    qemu_plugin_id_t id, size_t size, qemu_plugin_vcpu_storage_dtor_t dtor,
    void *userdata)
{
    struct qemu_plugin_vcpu_storage *storage;
    size_t align = __alignof__(max_align_t);
    size_t offset = QEMU_ALIGN_UP(1, align);

    if (!size || size > SIZE_MAX - offset) {
        return NULL;
    }
    QEMU_LOCK_GUARD(&plugin.lock);
    plugin_id_to_ctx_locked(id);
    if (!plugin_vcpu_storages) {
        plugin_vcpu_storages = g_ptr_array_new();
    }
    storage = g_new0(struct qemu_plugin_vcpu_storage, 1);
    storage->owner = id;
    storage->size = size;
    storage->data_offset = offset;
    storage->dtor = dtor;
    storage->userdata = userdata;
    storage->score = plugin_scoreboard_new(QEMU_ALIGN_UP(offset + size, align));
    g_ptr_array_add(plugin_vcpu_storages, storage);
    return storage;
}

void *qemu_plugin_vcpu_storage_get(struct qemu_plugin_vcpu_storage *storage,
                                   unsigned int vcpu_index)
{
    uint8_t *slot;

    if (!storage || vcpu_index >= qemu_plugin_num_vcpus()) {
        return NULL;
    }
    slot = plugin_storage_slot(storage, vcpu_index);
    slot[0] = 1;
    return slot + storage->data_offset;
}

void qemu_plugin_vcpu_storage_free(struct qemu_plugin_vcpu_storage *storage)
{
    if (!storage) {
        return;
    }
    QEMU_LOCK_GUARD(&plugin.lock);
    g_assert(plugin_vcpu_storages);
    g_assert(g_ptr_array_remove_fast(plugin_vcpu_storages, storage));
    plugin_storage_destroy(storage);
}

void plugin_vcpu_storage_exit(unsigned int vcpu_index)
{
    QEMU_LOCK_GUARD(&plugin.lock);
    if (!plugin_vcpu_storages) {
        return;
    }
    for (guint i = 0; i < plugin_vcpu_storages->len; i++) {
        struct qemu_plugin_vcpu_storage *storage =
            g_ptr_array_index(plugin_vcpu_storages, i);
        uint8_t *slot = plugin_storage_slot(storage, vcpu_index);
        if (slot[0]) {
            if (storage->dtor) {
                storage->dtor(vcpu_index, slot + storage->data_offset,
                              storage->userdata);
            }
            memset(slot, 0, storage->data_offset + storage->size);
        }
    }
}

void plugin_vcpu_storage_cleanup(qemu_plugin_id_t id)
{
    QEMU_LOCK_GUARD(&plugin.lock);
    if (!plugin_vcpu_storages) {
        return;
    }
    for (guint i = 0; i < plugin_vcpu_storages->len;) {
        struct qemu_plugin_vcpu_storage *storage =
            g_ptr_array_index(plugin_vcpu_storages, i);
        if (storage->owner == id) {
            g_ptr_array_remove_index_fast(plugin_vcpu_storages, i);
            plugin_storage_destroy(storage);
        } else {
            i++;
        }
    }
}

enum qemu_plugin_cb_flags tcg_call_to_qemu_plugin_cb_flags(int flags)
{
    if (flags & TCG_CALL_NO_RWG) {
        return QEMU_PLUGIN_CB_NO_REGS;
    } else if (flags & TCG_CALL_NO_WG) {
        return QEMU_PLUGIN_CB_R_REGS;
    } else {
        return QEMU_PLUGIN_CB_RW_REGS_PC;
    }
}
