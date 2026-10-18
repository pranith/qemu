/* Local AI-assisted plugin API experiment; not for upstream submission. */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    uint64_t before;
    uint64_t after;
    uint64_t memory;
    uint64_t edges;
    uint64_t branches;
    uint64_t known_conditional_branches;
    uint64_t records;
    uint64_t auto_before, auto_after, auto_memory;
    uint64_t enabled;
    uint64_t context_done;
    uint64_t exclusive_done;
} VcpuCounts;

static struct qemu_plugin_scoreboard *counts;
static qemu_plugin_id_t plugin_id;
static struct qemu_plugin_trace_buffer *buffer;
static struct qemu_plugin_trace_buffer *auto_buffer;
static struct qemu_plugin_vcpu_storage *vcpu_storage;
static unsigned int storage_destructors;
static int translated_memory;
static int decoded_insns;
static bool use_after = true;
static bool use_cond = true;
static bool use_image;
static bool require_decode;
static bool require_source;
static bool use_exclusive = true;
static uint64_t target_symbol_addr;
static uint64_t temp_image_id;
static uint64_t temp_image_addr;
static unsigned int temp_image_loads, temp_image_unloads;
static unsigned int temp_image_remaps;
static unsigned int routine_entries, routine_returns;
static unsigned int fault_signals, exceptions;
static uint64_t replacement_pc;
static unsigned int redirect_registrations;
static bool image_metadata_checked;
static int exclusive_calls;
static int exclusive_requests;
static int max_exclusive_vcpus;
static unsigned int require_min_vcpus;

static void section_info(const struct qemu_plugin_user_image_section *section,
                         void *userdata)
{
    bool *found = userdata;

    if (g_str_equal(section->name, ".text") && section->size) {
        g_assert(section->has_guest_addr);
        *found = true;
    }
}

static void symbol_info(const struct qemu_plugin_user_image_symbol *symbol,
                        void *userdata)
{
    bool *found = userdata;

    if (g_str_equal(symbol->name, "analysis_target")) {
        g_assert(symbol->has_guest_addr);
        target_symbol_addr = symbol->guest_addr;
        *found = true;
    }
}

static void batch(unsigned int vcpu, const void *records,
                  size_t count, void *userdata)
{
    const uint64_t *values = records;
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);

    for (size_t i = 0; i < count; i++) {
        g_assert_cmpuint(values[i], ==, 0x70696e);
    }
    state->records += count;
}

static void auto_batch(unsigned int vcpu, const void *records,
                       size_t count, void *userdata)
{
    const struct qemu_plugin_trace_record *trace = records;
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);

    for (size_t i = 0; i < count; i++) {
        g_assert_cmpuint(trace[i].pc, >, 0);
        switch (trace[i].kind) {
        case QEMU_PLUGIN_TRACE_INSN_BEFORE:
            state->auto_before++;
            break;
        case QEMU_PLUGIN_TRACE_INSN_AFTER:
            state->auto_after++;
            break;
        case QEMU_PLUGIN_TRACE_MEMORY:
            g_assert_cmpuint(trace[i].size, >, 0);
            state->auto_memory++;
            break;
        default:
            g_assert_not_reached();
        }
    }
}

static void start(unsigned int vcpu, void *userdata)
{
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);
    state->enabled = 1;
    g_assert(qemu_plugin_vcpu_storage_get(vcpu_storage, vcpu));
}

static void storage_dtor(unsigned int vcpu, void *state, void *userdata)
{
    storage_destructors++;
}

static void stop(unsigned int vcpu, void *userdata)
{
    qemu_plugin_trace_buffer_flush(buffer, vcpu);
    qemu_plugin_trace_buffer_flush(auto_buffer, vcpu);
}

static void before(unsigned int vcpu, void *userdata)
{
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);
    state->before++;
    if (!state->context_done) {
        struct qemu_plugin_cpu_context *ctx =
            qemu_plugin_cpu_context_capture();
        GArray *regs = qemu_plugin_get_registers();
        GByteArray *value = g_byte_array_new();

        g_assert(ctx);
        g_assert_cmpuint(qemu_plugin_cpu_context_pc(ctx), >, 0);
        if (use_image && !image_metadata_checked) {
            uint64_t image_id;
            bool section_found = false, symbol_found = false;

            if (qemu_plugin_user_image_lookup(
                    qemu_plugin_cpu_context_pc(ctx), &image_id,
                    NULL, NULL)) {
                g_autofree char *source_path = NULL;
                uint32_t line, column;

                g_assert(qemu_plugin_user_image_sections(
                    image_id, section_info, &section_found));
                g_assert(qemu_plugin_user_image_symbols(
                    image_id, symbol_info, &symbol_found));
                if (require_source) {
                    g_assert(qemu_plugin_user_image_source(
                        image_id, target_symbol_addr, &source_path,
                        &line, &column));
                    g_assert_cmpuint(line, >, 0);
                    g_assert(g_str_has_suffix(source_path,
                                             "test-plugin-analysis-api.c"));
                }
                image_metadata_checked = section_found && symbol_found;
            }
        }
        for (guint i = 0; i < regs->len; i++) {
            qemu_plugin_reg_descriptor *reg =
                &g_array_index(regs, qemu_plugin_reg_descriptor, i);
            if (!reg->is_readonly &&
                qemu_plugin_cpu_context_get(ctx, reg->name, value)) {
                g_assert(qemu_plugin_cpu_context_set(ctx, reg->name, value));
                break;
            }
        }
        g_assert(qemu_plugin_cpu_context_apply(ctx));
        qemu_plugin_cpu_context_free(ctx);
        g_byte_array_unref(value);
        g_array_unref(regs);
        state->context_done = !use_image || image_metadata_checked;
    }
}

static void exclusive(unsigned int requester, void *userdata)
{
    unsigned int captured = 0;


    for (unsigned int i = 0; i < qemu_plugin_num_vcpus(); i++) {
        struct qemu_plugin_cpu_context *ctx =
            qemu_plugin_cpu_context_capture_vcpu(i);
        if (ctx) {
            g_assert_cmpuint(qemu_plugin_cpu_context_pc(ctx), >, 0);
            g_assert(qemu_plugin_cpu_context_apply(ctx));
            qemu_plugin_cpu_context_free(ctx);
            captured++;
        }
    }
    g_assert_cmpuint(captured, >, 0);
    int old_max = g_atomic_int_get(&max_exclusive_vcpus);
    while (captured > old_max &&
           !g_atomic_int_compare_and_exchange(&max_exclusive_vcpus,
                                              old_max, captured)) {
        old_max = g_atomic_int_get(&max_exclusive_vcpus);
    }
    g_atomic_int_inc(&exclusive_calls);
}

static void request_exclusive(unsigned int vcpu, void *userdata)
{
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);

    if (use_exclusive && !state->exclusive_done &&
        qemu_plugin_num_vcpus() >= MAX(require_min_vcpus, 1)) {
        state->exclusive_done = 1;
        g_atomic_int_inc(&exclusive_requests);
        g_assert(qemu_plugin_request_exclusive(
            plugin_id, (uintptr_t)userdata, exclusive, NULL));
    }
}

static void after(unsigned int vcpu, void *userdata)
{
    const uint64_t record = 0x70696e;
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);

    state->after++;
    g_assert(qemu_plugin_trace_buffer_append(buffer, vcpu, &record));
}

static void memory(unsigned int vcpu, qemu_plugin_meminfo_t info,
                   uint64_t addr, void *userdata)
{
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);
    state->memory++;
}

static void edge(unsigned int vcpu, const struct qemu_plugin_tb_edge *event,
                 void *userdata)
{
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);

    g_assert_cmpuint(event->from_pc, >, 0);
    g_assert_cmpuint(event->to_pc, >, 0);
    state->edges++;
}

static void branch(unsigned int vcpu,
                   const struct qemu_plugin_branch_event *event,
                   void *userdata)
{
    VcpuCounts *state = qemu_plugin_scoreboard_find(counts, vcpu);

    g_assert(event->edge.from_properties & QEMU_PLUGIN_INSN_BRANCH);
    if (event->outcome_known && event->conditional) {
        g_assert(event->edge.has_direct_target);
        g_assert_cmpint(event->taken, ==,
                        event->edge.to_pc == event->edge.direct_target);
        state->known_conditional_branches++;
    }
    state->branches++;
}

static void image_event(const struct qemu_plugin_user_image_event *event,
                        void *userdata)
{
    uint64_t id, offset;
    g_autofree char *path = NULL;

    if (!event->path ||
        !g_str_has_prefix(event->path, "/tmp/qemu-analysis-image-")) {
        return;
    }
    if (event->type == QEMU_PLUGIN_USER_IMAGE_LOAD) {
        g_assert(qemu_plugin_user_image_lookup(event->executable_addr,
                                               &id, &offset, &path));
        g_assert_cmpuint(id, ==, event->image_id);
        g_assert_cmpuint(offset, ==, 0);
        g_assert_cmpstr(path, ==, event->path);
        temp_image_id = id;
        temp_image_addr = event->executable_addr;
        temp_image_loads++;
    } else {
        g_assert_cmpuint(event->image_id, ==, temp_image_id);
        temp_image_unloads++;
    }
}

static void mapping_event(const struct qemu_plugin_user_mapping_event *event,
                          void *userdata)
{
    uint64_t id, offset;

    if (event->type != QEMU_PLUGIN_USER_REMAP ||
        event->old_addr != temp_image_addr) {
        return;
    }
    g_assert(qemu_plugin_user_image_lookup(event->addr, &id, &offset, NULL));
    g_assert_cmpuint(id, ==, temp_image_id);
    g_assert_cmpuint(offset, ==, 0);
    temp_image_remaps++;
}

static void routine_event(const struct qemu_plugin_routine_event *event,
                          void *userdata)
{
    if (g_strcmp0(event->name, "analysis_target") != 0) {
        return;
    }
    if (event->type == QEMU_PLUGIN_ROUTINE_ENTRY) {
        routine_entries++;
    } else {
        routine_returns++;
    }
}

static void task_event(const struct qemu_plugin_user_task_event *event,
                       void *userdata)
{
    if (event->type == QEMU_PLUGIN_USER_FORK_CHILD) {
        uint64_t id;
        g_autofree char *path = NULL;

        g_assert(qemu_plugin_user_image_lookup(qemu_plugin_start_code(),
                                               &id, NULL, &path));
        g_assert_cmpuint(id, >, 0);
        g_assert(path);
    }
}

static void signal_event(const struct qemu_plugin_user_signal_event *event,
                         void *userdata)
{
    if (event->signo == 11 && event->has_fault_addr) {
        g_assert_cmpuint(event->fault_addr, >, 0);
        fault_signals++;
    }
}

static void exception_event(const struct qemu_plugin_exception_event *event,
                            void *userdata)
{
    g_assert_cmpuint(event->from_pc, >, 0);
    exceptions++;
}

static void translate(struct qemu_plugin_tb *tb, void *userdata)
{
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        const char *symbol = qemu_plugin_insn_symbol(insn);
        uint32_t props = qemu_plugin_insn_get_properties(insn);
        struct qemu_plugin_insn_decode decoded = {
            .struct_size = sizeof(decoded),
        };
        qemu_plugin_u64 enabled = qemu_plugin_scoreboard_u64_in_struct(
            counts, VcpuCounts, enabled);

        if (props & QEMU_PLUGIN_INSN_TRANSLATED_MEMORY) {
            g_atomic_int_inc(&translated_memory);
        }
        if (qemu_plugin_insn_decode(insn, &decoded)) {
            g_assert(decoded.mnemonic[0]);
            g_assert_cmpuint(decoded.operand_count, <=,
                             QEMU_PLUGIN_DECODE_MAX_OPERANDS);
            g_atomic_int_inc(&decoded_insns);
        }
        if (use_image && i == 0 &&
            g_strcmp0(symbol, "analysis_replacement") == 0) {
            replacement_pc = qemu_plugin_insn_vaddr(insn);
        }
        if (use_image && i == 0 && replacement_pc &&
            g_strcmp0(symbol, "analysis_original") == 0) {
            qemu_plugin_register_vcpu_insn_redirect(insn, replacement_pc);
            g_atomic_int_inc(&redirect_registrations);
        }
        qemu_plugin_register_vcpu_insn_exec_cb(insn, request_exclusive,
                                               QEMU_PLUGIN_CB_RW_REGS_PC,
                                               (void *)(uintptr_t)
                                               qemu_plugin_insn_vaddr(insn));
        qemu_plugin_register_vcpu_insn_exec_cb(insn, before,
                                               QEMU_PLUGIN_CB_RW_REGS_PC,
                                               NULL);
        g_assert(qemu_plugin_register_vcpu_insn_trace(
            insn, auto_buffer, QEMU_PLUGIN_TRACE_INSN_BEFORE));
        if (use_after) {
            qemu_plugin_register_vcpu_insn_after_cb(
                insn, after, QEMU_PLUGIN_CB_NO_REGS, NULL);
            g_assert(qemu_plugin_register_vcpu_insn_trace(
                insn, auto_buffer, QEMU_PLUGIN_TRACE_INSN_AFTER));
        }
        g_assert(qemu_plugin_register_vcpu_mem_trace(
            insn, auto_buffer, QEMU_PLUGIN_MEM_RW));
        if (use_cond) {
            qemu_plugin_register_vcpu_mem_cond_cb(
                insn, memory, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW,
                QEMU_PLUGIN_COND_EQ, enabled, 1, NULL);
        } else {
            qemu_plugin_register_vcpu_mem_cb(
                insn, memory, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW,
                NULL);
        }
    }
}

static void finish(void *userdata)
{
    uint64_t before_count = 0, after_count = 0, memory_count = 0;
    uint64_t edge_count = 0;
    uint64_t branch_count = 0, known_conditional_count = 0;

    for (unsigned int i = 0; i < qemu_plugin_num_vcpus(); i++) {
        VcpuCounts *state = qemu_plugin_scoreboard_find(counts, i);
        qemu_plugin_trace_buffer_flush(buffer, i);
        qemu_plugin_trace_buffer_flush(auto_buffer, i);
        before_count += state->before;
        after_count += state->after;
        memory_count += state->memory;
        edge_count += state->edges;
        branch_count += state->branches;
        known_conditional_count += state->known_conditional_branches;
        g_assert_cmpuint(state->after, ==, state->records);
        g_assert_cmpuint(state->auto_before, ==, state->before);
        g_assert_cmpuint(state->auto_after, ==, state->after);
        g_assert_cmpuint(state->auto_memory, ==, state->memory);
    }
    g_assert_cmpuint(before_count, >, 0);
    if (use_after) {
        g_assert_cmpuint(after_count, >, 0);
    }
    g_assert_cmpuint(before_count, >=, after_count);
    g_assert_cmpuint(memory_count, >, 0);
    g_assert_cmpuint(edge_count, >, 0);
    g_assert_cmpuint(branch_count, >, 0);
    g_assert_cmpuint(known_conditional_count, >, 0);
    if (use_exclusive) {
        g_assert_cmpint(g_atomic_int_get(&exclusive_requests), ==,
                        g_atomic_int_get(&exclusive_calls));
        g_assert_cmpint(g_atomic_int_get(&exclusive_calls), >, 0);
    }
    if (use_exclusive && require_min_vcpus) {
        g_assert_cmpint(g_atomic_int_get(&max_exclusive_vcpus), >=,
                        require_min_vcpus);
    }
    g_assert_cmpint(g_atomic_int_get(&translated_memory), >, 0);
    if (require_decode) {
        g_assert_cmpint(g_atomic_int_get(&decoded_insns), >, 0);
    }
    qemu_plugin_vcpu_storage_free(vcpu_storage);
    g_assert_cmpuint(storage_destructors, >, 0);
    if (use_image) {
        g_assert_cmpuint(temp_image_loads, ==, 1);
        g_assert_cmpuint(temp_image_unloads, ==, 1);
        g_assert_cmpuint(temp_image_remaps, ==, 1);
        g_assert_cmpuint(routine_entries, ==, 16);
        g_assert_cmpuint(routine_returns, ==, 16);
        g_assert_cmpuint(fault_signals, >, 0);
        g_assert_cmpint(g_atomic_int_get(&redirect_registrations), >, 0);
        g_assert(image_metadata_checked);
    }
    qemu_plugin_trace_buffer_free(buffer);
    qemu_plugin_trace_buffer_free(auto_buffer);
    qemu_plugin_scoreboard_free(counts);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    plugin_id = id;
    for (int i = 0; i < argc; i++) {
        if (g_str_equal(argv[i], "after=off")) {
            use_after = false;
        } else if (g_str_equal(argv[i], "cond=off")) {
            use_cond = false;
        } else if (g_str_equal(argv[i], "image=on")) {
            use_image = true;
        } else if (g_str_equal(argv[i], "decode=required")) {
            require_decode = true;
        } else if (g_str_equal(argv[i], "source=required")) {
            require_source = true;
        } else if (g_str_equal(argv[i], "exclusive=off")) {
            use_exclusive = false;
        } else if (g_str_has_prefix(argv[i], "min_vcpus=")) {
            require_min_vcpus = atoi(argv[i] + strlen("min_vcpus="));
        }
    }
    counts = qemu_plugin_scoreboard_new(sizeof(VcpuCounts));
    vcpu_storage = qemu_plugin_vcpu_storage_new(id, sizeof(uint64_t),
                                                storage_dtor, NULL);
    g_assert(vcpu_storage);
    buffer = qemu_plugin_trace_buffer_new(sizeof(uint64_t), 16, batch, NULL);
    g_assert(buffer);
    auto_buffer = qemu_plugin_trace_buffer_new(
        sizeof(struct qemu_plugin_trace_record), 32, auto_batch, NULL);
    g_assert(auto_buffer);
    qemu_plugin_register_vcpu_init_cb(id, start, NULL);
    qemu_plugin_register_vcpu_exit_cb(id, stop, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate, NULL);
    qemu_plugin_register_vcpu_tb_edge_cb(id, edge, NULL);
    qemu_plugin_register_vcpu_branch_cb(id, branch, NULL);
    if (use_image) {
        qemu_plugin_register_user_image_cb(id, image_event, NULL);
        qemu_plugin_register_user_mapping_cb(id, mapping_event, NULL);
        qemu_plugin_register_user_task_cb(id, task_event, NULL);
        qemu_plugin_register_user_signal_cb(id, signal_event, NULL);
        qemu_plugin_register_exception_cb(id, exception_event, NULL);
        qemu_plugin_register_routine_cb(id, routine_event, NULL);
    }
    qemu_plugin_register_atexit_cb(id, finish, NULL);
    return 0;
}
