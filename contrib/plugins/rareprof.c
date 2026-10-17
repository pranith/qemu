/*
 * Local ARM64 kernel rare-stall flight recorder; not for upstream submission.
 *
 * Run with -d plugin -D report.log -plugin librareprof.so,
 * pc_start=KERNEL_START,pc_end=KERNEL_END. Optional markers=1 enables
 * MOVZ XZR,#0x6a11 (start) and #0x6a12 (stop). MOVZ XZR,#0x6a13
 * explicitly triggers a snapshot. Automatic triggers detect bursts of
 * failed atomic compare-and-swap and unchanged polling loads. Options:
 * history=N, post=N, triggers=N, cas_fail=N, poll=N, markers=0|1.
 * Set cas_fail=0 or poll=0 to disable that automatic trigger. Markers
 * scope recording per vCPU. Run with -d plugin to retain the report.
 *
 * Event sequence numbers are local to each vCPU. For 16-byte accesses,
 * the report includes only the low 64 bits of the value. Events describe
 * TCG execution, not hardware cycles or elapsed time.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <inttypes.h>
#include <stdio.h>
#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_HISTORY 1024
#define MAX_POST 1024
#define MAX_TRIGGERS 16
#define TRACKERS 256
#define MARK_START UINT32_C(0xd28d423f)
#define MARK_STOP UINT32_C(0xd28d425f)
#define MARK_TRIGGER UINT32_C(0xd28d427f)

typedef enum { EVENT_TB, EVENT_READ, EVENT_WRITE, EVENT_MARK } EventKind;
typedef enum { TRIGGER_CAS, TRIGGER_POLL, TRIGGER_MARK } TriggerKind;

typedef struct {
    uint64_t seq;
    uint64_t pc;
    uint64_t vaddr;
    uint64_t ram_addr;
    uint64_t value;
    uint8_t size;
    uint8_t kind;
    bool atomic;
    bool success;
} Event;

typedef struct {
    uint64_t pc;
    uint64_t addr;
    uint64_t value;
    uint64_t last_seq;
    uint64_t streak;
} Tracker;

typedef struct {
    Event *events;
    unsigned int count;
    unsigned int post_left;
} Capture;

typedef struct {
    unsigned int cpu;
    TriggerKind kind;
    uint64_t pc;
    uint64_t ram_addr;
    uint64_t seq;
    uint64_t streak;
    Capture *captures;
} Trigger;

typedef struct {
    bool active;
    uint64_t seq;
    Event *ring;
    unsigned int ring_pos;
    unsigned int ring_count;
    unsigned int seen_triggers;
    Tracker polls[TRACKERS];
    Tracker failures[TRACKERS];
} CpuState;

typedef struct {
    uint64_t pc;
} Site;

static CpuState *cpus;
static unsigned int ncpus;
static unsigned int history = 128;
static unsigned int post_events = 64;
static unsigned int max_triggers = 4;
static uint64_t cas_threshold = 64;
static uint64_t poll_threshold = 10000;
static uint64_t pc_start;
static uint64_t pc_end = UINT64_MAX;
static bool marker_scope;
static Trigger triggers[MAX_TRIGGERS];
static unsigned int published_triggers;
static GMutex trigger_lock;
static GMutex sites_lock;
static GHashTable *sites;

static void capture_new(unsigned int cpu)
{
    CpuState *state = &cpus[cpu];
    unsigned int published = __atomic_load_n(&published_triggers,
                                              __ATOMIC_ACQUIRE);

    while (state->seen_triggers < published) {
        Trigger *trigger = &triggers[state->seen_triggers++];
        Capture *capture = &trigger->captures[cpu];
        unsigned int first = (state->ring_pos + history -
                              state->ring_count) % history;

        capture->events = g_new(Event, history + post_events);
        capture->count = state->ring_count;
        capture->post_left = post_events;
        for (unsigned int i = 0; i < state->ring_count; i++) {
            capture->events[i] = state->ring[(first + i) % history];
        }
    }
}

static void record_event(unsigned int cpu, Event event)
{
    CpuState *state = &cpus[cpu];

    event.seq = ++state->seq;
    for (unsigned int i = 0; i < state->seen_triggers; i++) {
        Capture *capture = &triggers[i].captures[cpu];

        if (capture->post_left) {
            capture->events[capture->count++] = event;
            capture->post_left--;
        }
    }
    state->ring[state->ring_pos] = event;
    state->ring_pos = (state->ring_pos + 1) % history;
    state->ring_count = MIN(state->ring_count + 1, history);
    capture_new(cpu);
}

static void trigger_snapshot(unsigned int cpu, TriggerKind kind,
                             uint64_t pc, uint64_t ram_addr,
                             uint64_t streak)
{
    CpuState *state = &cpus[cpu];
    Trigger *trigger;
    unsigned int index;

    g_mutex_lock(&trigger_lock);
    index = published_triggers;
    if (index >= max_triggers) {
        g_mutex_unlock(&trigger_lock);
        return;
    }
    trigger = &triggers[index];
    trigger->cpu = cpu;
    trigger->kind = kind;
    trigger->pc = pc;
    trigger->ram_addr = ram_addr;
    trigger->seq = state->seq;
    trigger->streak = streak;
    trigger->captures = g_new0(Capture, ncpus);
    __atomic_store_n(&published_triggers, index + 1, __ATOMIC_RELEASE);
    g_mutex_unlock(&trigger_lock);
    capture_new(cpu);
}

static Site *get_site(uint64_t pc)
{
    Site *site;

    g_mutex_lock(&sites_lock);
    site = g_hash_table_lookup(sites, &pc);
    if (!site) {
        site = g_new0(Site, 1);
        site->pc = pc;
        g_hash_table_insert(sites, &site->pc, site);
    }
    g_mutex_unlock(&sites_lock);
    return site;
}

static void tb_exec(unsigned int cpu, void *userdata)
{
    Site *site = userdata;

    if (cpu < ncpus && cpus[cpu].active) {
        Event event = { .pc = site->pc, .kind = EVENT_TB };

        record_event(cpu, event);
    }
}

static void marker_exec(unsigned int cpu, void *userdata)
{
    unsigned int marker = GPOINTER_TO_UINT(userdata);
    CpuState *state;
    Event event = { .kind = EVENT_MARK, .value = marker };

    if (cpu >= ncpus) {
        return;
    }
    state = &cpus[cpu];
    if (marker == MARK_START) {
        for (unsigned int i = 0; i < state->seen_triggers; i++) {
            triggers[i].captures[cpu].post_left = 0;
        }
        state->active = true;
        state->ring_pos = 0;
        state->ring_count = 0;
        memset(state->polls, 0, sizeof(state->polls));
        memset(state->failures, 0, sizeof(state->failures));
    }
    if (state->active) {
        record_event(cpu, event);
        if (marker == MARK_TRIGGER) {
            trigger_snapshot(cpu, TRIGGER_MARK, 0, 0, 1);
        }
    }
    if (marker == MARK_STOP) {
        state->active = false;
    }
}

static void update_tracker(unsigned int cpu, Tracker *table,
                           uint64_t pc, uint64_t addr, uint64_t value,
                           uint64_t threshold, TriggerKind kind)
{
    CpuState *state = &cpus[cpu];
    unsigned int index = ((pc >> 2) ^ (addr >> 3)) % TRACKERS;
    Tracker *entry = &table[index];

    if (entry->pc == pc && entry->addr == addr &&
        entry->value == value && state->seq - entry->last_seq <= 128) {
        entry->streak++;
    } else {
        entry->pc = pc;
        entry->addr = addr;
        entry->value = value;
        entry->streak = 1;
    }
    entry->last_seq = state->seq;
    if (entry->streak == threshold) {
        trigger_snapshot(cpu, kind, pc, addr, entry->streak);
    }
}

static uint64_t value_low(qemu_plugin_mem_value value)
{
    switch (value.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:
        return value.data.u8;
    case QEMU_PLUGIN_MEM_VALUE_U16:
        return value.data.u16;
    case QEMU_PLUGIN_MEM_VALUE_U32:
        return value.data.u32;
    case QEMU_PLUGIN_MEM_VALUE_U64:
        return value.data.u64;
    case QEMU_PLUGIN_MEM_VALUE_U128:
        return value.data.u128.low;
    }
    return 0;
}

static void mem_access(unsigned int cpu, qemu_plugin_meminfo_t info,
                       uint64_t vaddr, void *userdata)
{
    Site *site = userdata;
    struct qemu_plugin_mem_access_info access;
    qemu_plugin_mem_value value;
    Event event;

    if (cpu >= ncpus || !cpus[cpu].active) {
        return;
    }
    qemu_plugin_mem_get_access_info(info, vaddr, &access);
    value = qemu_plugin_mem_get_value(info);
    event = (Event) {
        .pc = site->pc,
        .vaddr = vaddr,
        .ram_addr = access.has_ram_addr ? access.ram_addr : 0,
        .value = value_low(value),
        .size = MIN(access.size, UINT8_MAX),
        .kind = access.is_store ? EVENT_WRITE : EVENT_READ,
        .atomic = access.is_atomic,
        .success = access.atomic_success,
    };
    record_event(cpu, event);
    if (!access.has_ram_addr || access.is_io || access.is_store) {
        return;
    }
    if (access.is_atomic && cas_threshold) {
        update_tracker(cpu, cpus[cpu].failures, site->pc, access.ram_addr,
                       access.atomic_success,
                       access.atomic_success ? UINT64_MAX : cas_threshold,
                       TRIGGER_CAS);
    } else if (!access.is_atomic && poll_threshold) {
        update_tracker(cpu, cpus[cpu].polls, site->pc, access.ram_addr,
                       event.value, poll_threshold, TRIGGER_POLL);
    }
}

static void tb_trans(struct qemu_plugin_tb *tb, void *userdata)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);

    if (pc >= pc_start && pc < pc_end) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec,
                                              QEMU_PLUGIN_CB_NO_REGS,
                                              get_site(pc));
    }
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_pc = qemu_plugin_insn_vaddr(insn);
        uint32_t opcode;

        if (qemu_plugin_insn_size(insn) == 4 &&
            qemu_plugin_insn_data(insn, &opcode, 4) == 4) {
            opcode = GUINT32_FROM_LE(opcode);
            if (opcode == MARK_START || opcode == MARK_STOP ||
                opcode == MARK_TRIGGER) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, marker_exec, QEMU_PLUGIN_CB_NO_REGS,
                    GUINT_TO_POINTER(opcode));
                continue;
            }
        }
        if (insn_pc >= pc_start && insn_pc < pc_end) {
            qemu_plugin_register_vcpu_mem_cb(
                insn, mem_access, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW, get_site(insn_pc));
        }
    }
}

static void plugin_exit(void *userdata)
{
    static const char *const kinds[] = { "cas_fail", "poll", "marker" };
    static const char *const events[] = { "tb", "read", "write", "mark" };
    unsigned int count = __atomic_load_n(&published_triggers, __ATOMIC_ACQUIRE);

    for (unsigned int cpu = 0; cpu < ncpus; cpu++) {
        capture_new(cpu);
    }
    for (unsigned int i = 0; i < count; i++) {
        Trigger *trigger = &triggers[i];
        GString *out = g_string_new(NULL);

        g_string_append_printf(out,
            "rareprof trigger=%u reason=%s cpu=%u pc=%016"PRIx64
            " ram=%016"PRIx64" seq=%"PRIu64" streak=%"PRIu64"\n",
            i + 1, kinds[trigger->kind], trigger->cpu, trigger->pc,
            trigger->ram_addr, trigger->seq, trigger->streak);
        for (unsigned int cpu = 0; cpu < ncpus; cpu++) {
            Capture *capture = &trigger->captures[cpu];

            g_string_append_printf(out, " cpu=%u events=%u\n",
                                   cpu, capture->count);
            for (unsigned int j = 0; j < capture->count; j++) {
                Event *event = &capture->events[j];

                g_string_append_printf(out,
                    "  seq=%"PRIu64" kind=%s pc=%016"PRIx64
                    " va=%016"PRIx64" ram=%016"PRIx64
                    " value=%016"PRIx64" size=%u atomic=%u success=%u\n",
                    event->seq, events[event->kind], event->pc,
                    event->vaddr, event->ram_addr, event->value,
                    event->size, event->atomic, event->success);
            }
        }
        qemu_plugin_outs(out->str);
        g_string_free(out, true);
    }
    if (!count) {
        qemu_plugin_outs("rareprof: no triggers\n");
    }
}

static bool parse_number(const char *str, uint64_t *value)
{
    char *end;

    *value = g_ascii_strtoull(str, &end, 0);
    return end != str && *end == 0;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (!info->system_emulation ||
        g_strcmp0(info->target_name, "aarch64") != 0) {
        fprintf(stderr, "rareprof requires AArch64 system emulation\n");
        return -1;
    }
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        uint64_t value;

        if (!kv[1] || !parse_number(kv[1], &value)) {
            return -1;
        }
        if (g_strcmp0(kv[0], "pc_start") == 0) {
            pc_start = value;
        } else if (g_strcmp0(kv[0], "pc_end") == 0) {
            pc_end = value;
        } else if (g_strcmp0(kv[0], "history") == 0 &&
                   value >= 1 && value <= MAX_HISTORY) {
            history = value;
        } else if (g_strcmp0(kv[0], "post") == 0 && value <= MAX_POST) {
            post_events = value;
        } else if (g_strcmp0(kv[0], "triggers") == 0 &&
                   value >= 1 && value <= MAX_TRIGGERS) {
            max_triggers = value;
        } else if (g_strcmp0(kv[0], "cas_fail") == 0 &&
                   (value == 0 || value >= 2)) {
            cas_threshold = value;
        } else if (g_strcmp0(kv[0], "poll") == 0 &&
                   (value == 0 || value >= 2)) {
            poll_threshold = value;
        } else if (g_strcmp0(kv[0], "markers") == 0 && value <= 1) {
            marker_scope = value;
        } else {
            fprintf(stderr, "rareprof: bad option %s\n", argv[i]);
            return -1;
        }
    }
    if (pc_start >= pc_end) {
        return -1;
    }
    ncpus = MAX(info->system.max_vcpus, 1);
    cpus = g_new0(CpuState, ncpus);
    for (unsigned int cpu = 0; cpu < ncpus; cpu++) {
        cpus[cpu].active = !marker_scope;
        cpus[cpu].ring = g_new0(Event, history);
    }
    g_mutex_init(&trigger_lock);
    g_mutex_init(&sites_lock);
    sites = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
