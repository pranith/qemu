/*
 * Local AArch64 kernel lock experiment; not for upstream submission.
 *
 * Guest markers are MOVZ XZR,#0x6a11 (start) and #0x6a12 (stop).
 * Run with -d plugin -D report.log and -plugin liblockprof.so,
 * pc_start=0xffffffc080000000. Optional spin_start/end and rwsem_start/end
 * identify functions to attribute waits by lock address and caller. Set
 * va_bits to match the guest kernel when pointer authentication is enabled.
 * Counts describe TCG execution, not cycles.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <inttypes.h>
#include <stdio.h>
#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define SHARDS 64
#define LINE_SIZE 64
#define RECENT 256
#define LOCK_DEPTH 8
#define MARK_START UINT32_C(0xd28d423f)
#define MARK_STOP  UINT32_C(0xd28d425f)

typedef enum {
    LSE, EXCLUSIVE_LOAD, EXCLUSIVE_STORE, ACQUIRE_LOAD,
    RELEASE_STORE, PLAIN_LOAD, WAIT, BARRIER, OTHER
} Kind;

typedef struct {
    uint64_t pc;
    char mnemonic[16];
    Kind kind;
    uint64_t executions;
    uint64_t reads;
    uint64_t writes;
    uint64_t atomic_ops;
    uint64_t cas_failures;
    uint64_t exclusive_successes;
    uint64_t repeated_reads;
} Site;

typedef struct {
    uint64_t pc;
    uint64_t addr;
    uint64_t value;
    uint64_t event;
} ReadHistory;

typedef struct {
    uint64_t addr;
    uint64_t caller;
    uint64_t outer_caller;
    uint64_t site;
} LockKey;

typedef struct {
    LockKey key;
    uint64_t entries;
    uint64_t waits;
    uint64_t cpu_bits;
} LockGroup;

typedef struct {
    bool active;
    uint64_t starts;
    uint64_t stops;
    uint64_t events;
    ReadHistory recent[RECENT];
    struct qemu_plugin_register *reg_x0;
    struct qemu_plugin_register *reg_x29;
    struct qemu_plugin_register *reg_x30;
    GByteArray *regbuf;
    LockGroup *lock_stack[LOCK_DEPTH];
    unsigned int lock_depth;
    uint64_t missed_lock_entries;
    LockGroup *rwsem_stack[LOCK_DEPTH];
    unsigned int rwsem_depth;
    uint64_t missed_rwsem_entries;
} CpuState;

typedef struct {
    uint64_t line;
    uint64_t phys_line;
    uint64_t atomic_ops;
    uint64_t cas_failures;
    uint64_t exclusive_successes;
    uint64_t repeated_reads;
    uint64_t writes;
    uint64_t writer_handoffs;
    uint64_t cpu_bits;
    uint64_t top_pc;
    unsigned int last_writer;
    bool has_writer;
} Line;

typedef struct {
    GMutex mutex;
    GHashTable *lines;
} Shard;

static GMutex sites_mutex;
static GHashTable *sites_by_pc;
static GPtrArray *sites;
static GMutex locks_mutex;
static GHashTable *locks;
static GHashTable *rwsems;
static Shard shards[SHARDS];
static CpuState *cpus;
static unsigned int ncpus;
static unsigned int max_lines = 16384;
static unsigned int limit = 20;
static uint64_t pc_start;
static uint64_t pc_end = UINT64_MAX;
static uint64_t spin_start;
static uint64_t spin_end;
static uint64_t rwsem_start;
static uint64_t rwsem_end;
static unsigned int va_bits = 39;
static uint64_t dropped_lines;

static uint64_t strip_kernel_pac(uint64_t addr)
{
    uint64_t mask = (UINT64_C(1) << va_bits) - 1;

    addr &= mask;
    if (addr & (UINT64_C(1) << (va_bits - 1))) {
        addr |= ~mask;
    }
    return addr;
}

static guint lock_key_hash(gconstpointer ptr)
{
    const LockKey *key = ptr;
    uint64_t a = key->addr ^ (key->addr >> 32);
    uint64_t b = key->caller ^ (key->caller >> 32);

    uint64_t c = key->outer_caller ^ (key->outer_caller >> 32);
    uint64_t d = key->site ^ (key->site >> 32);

    return (guint)(a * UINT64_C(0x9e3779b1) ^
                   b * UINT64_C(0x85ebca6b) ^ c ^ d);
}

static gboolean lock_key_equal(gconstpointer a, gconstpointer b)
{
    const LockKey *left = a;
    const LockKey *right = b;

    return left->addr == right->addr && left->caller == right->caller &&
           left->outer_caller == right->outer_caller &&
           left->site == right->site;
}

static LockGroup *get_lock_group(GHashTable *table, uint64_t addr,
                                 uint64_t caller, uint64_t outer_caller,
                                 uint64_t site)
{
    LockKey key = {addr, caller, outer_caller, site};
    LockGroup *group;

    g_mutex_lock(&locks_mutex);
    group = g_hash_table_lookup(table, &key);
    if (!group) {
        group = g_new0(LockGroup, 1);
        group->key = key;
        g_hash_table_insert(table, &group->key, group);
    }
    g_mutex_unlock(&locks_mutex);
    return group;
}

static bool read_u64(CpuState *state, struct qemu_plugin_register *reg,
                     uint64_t *value)
{
    uint64_t raw;

    if (!reg || !state->regbuf) {
        return false;
    }
    g_byte_array_set_size(state->regbuf, 0);
    if (!qemu_plugin_read_register(reg, state->regbuf) ||
        state->regbuf->len < sizeof(raw)) {
        return false;
    }
    memcpy(&raw, state->regbuf->data, sizeof(raw));
    *value = GUINT64_FROM_LE(raw);
    return true;
}

static bool read_guest_u64(CpuState *state, uint64_t addr, uint64_t *value)
{
    uint64_t raw;

    if (addr > UINT64_MAX - sizeof(raw) ||
        !qemu_plugin_read_memory_vaddr(addr, state->regbuf, sizeof(raw)) ||
        state->regbuf->len < sizeof(raw)) {
        return false;
    }
    memcpy(&raw, state->regbuf->data, sizeof(raw));
    *value = GUINT64_FROM_LE(raw);
    return true;
}

static void unwind_callers(CpuState *state, uint64_t *outer, uint64_t *site)
{
    uint64_t fp, next_fp;

    *outer = *site = 0;
    if (read_u64(state, state->reg_x29, &fp) &&
        fp <= UINT64_MAX - 8 &&
        read_guest_u64(state, fp + 8, outer)) {
        *outer = strip_kernel_pac(*outer);
        if (read_guest_u64(state, fp, &next_fp) && next_fp != fp &&
            next_fp <= UINT64_MAX - 8 &&
            read_guest_u64(state, next_fp + 8, site)) {
            *site = strip_kernel_pac(*site);
        }
    }
}

static void vcpu_init(unsigned int cpu, void *userdata)
{
    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    CpuState *state;

    if (cpu >= ncpus) {
        return;
    }
    state = &cpus[cpu];
    state->regbuf = g_byte_array_new();
    if (!regs) {
        return;
    }
    for (unsigned int i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *reg =
            &g_array_index(regs, qemu_plugin_reg_descriptor, i);

        if (g_strcmp0(reg->name, "x0") == 0) {
            state->reg_x0 = reg->handle;
        } else if (g_strcmp0(reg->name, "x29") == 0) {
            state->reg_x29 = reg->handle;
        } else if (g_strcmp0(reg->name, "x30") == 0 ||
                   g_strcmp0(reg->name, "lr") == 0) {
            state->reg_x30 = reg->handle;
        }
    }
}

static void spin_entry(unsigned int cpu, void *userdata)
{
    CpuState *state;
    LockGroup *group = NULL;
    uint64_t addr, caller, outer_caller, site;

    if (cpu >= ncpus || !cpus[cpu].active) {
        return;
    }
    state = &cpus[cpu];
    if (read_u64(state, state->reg_x0, &addr) &&
        read_u64(state, state->reg_x30, &caller)) {
        unwind_callers(state, &outer_caller, &site);
        group = get_lock_group(locks, addr, caller, outer_caller, site);
        __atomic_fetch_add(&group->entries, 1, __ATOMIC_RELAXED);
        if (cpu < 64) {
            __atomic_fetch_or(&group->cpu_bits, UINT64_C(1) << cpu,
                              __ATOMIC_RELAXED);
        }
    } else {
        state->missed_lock_entries++;
    }
    if (state->lock_depth < LOCK_DEPTH) {
        state->lock_stack[state->lock_depth] = group;
    } else {
        state->missed_lock_entries++;
    }
    state->lock_depth++;
}

static void spin_return(unsigned int cpu, void *userdata)
{
    CpuState *state;

    if (cpu >= ncpus || !cpus[cpu].active) {
        return;
    }
    state = &cpus[cpu];
    if (state->lock_depth) {
        state->lock_depth--;
    }
}

static void rwsem_entry(unsigned int cpu, void *userdata)
{
    CpuState *state;
    LockGroup *group = NULL;
    uint64_t addr, caller, outer_caller, site;

    if (cpu >= ncpus || !cpus[cpu].active) {
        return;
    }
    state = &cpus[cpu];
    if (read_u64(state, state->reg_x0, &addr) &&
        read_u64(state, state->reg_x30, &caller)) {
        unwind_callers(state, &outer_caller, &site);
        group = get_lock_group(rwsems, addr, caller, outer_caller, site);
        __atomic_fetch_add(&group->entries, 1, __ATOMIC_RELAXED);
        if (cpu < 64) {
            __atomic_fetch_or(&group->cpu_bits, UINT64_C(1) << cpu,
                              __ATOMIC_RELAXED);
        }
    } else {
        state->missed_rwsem_entries++;
    }
    if (state->rwsem_depth < LOCK_DEPTH) {
        state->rwsem_stack[state->rwsem_depth] = group;
    } else {
        state->missed_rwsem_entries++;
    }
    state->rwsem_depth++;
}

static void rwsem_return(unsigned int cpu, void *userdata)
{
    if (cpu < ncpus && cpus[cpu].active && cpus[cpu].rwsem_depth) {
        cpus[cpu].rwsem_depth--;
    }
}

static bool starts(const char *s, const char *prefix)
{
    return g_str_has_prefix(s, prefix);
}

static Kind classify(const char *m)
{
    if (starts(m, "cas") || starts(m, "swp") ||
        starts(m, "ldadd") || starts(m, "stadd") ||
        starts(m, "ldclr") || starts(m, "stclr") ||
        starts(m, "ldset") || starts(m, "stset") ||
        starts(m, "ldeor") || starts(m, "steor") ||
        starts(m, "ldsmax") || starts(m, "stsmax") ||
        starts(m, "ldsmin") || starts(m, "stsmin") ||
        starts(m, "ldumax") || starts(m, "stumax") ||
        starts(m, "ldumin") || starts(m, "stumin")) {
        return LSE;
    }
    if (starts(m, "ldaxr") || starts(m, "ldxr") ||
        starts(m, "ldaxp") || starts(m, "ldxp")) {
        return EXCLUSIVE_LOAD;
    }
    if (starts(m, "stlxr") || starts(m, "stxr") ||
        starts(m, "stlxp") || starts(m, "stxp")) {
        return EXCLUSIVE_STORE;
    }
    if (starts(m, "ldar") || starts(m, "ldapr")) {
        return ACQUIRE_LOAD;
    }
    if (starts(m, "stlr")) {
        return RELEASE_STORE;
    }
    if (starts(m, "ldr") || starts(m, "ldur")) {
        return PLAIN_LOAD;
    }
    if (starts(m, "wfe") || starts(m, "sevl") ||
        starts(m, "yield")) {
        return WAIT;
    }
    if (starts(m, "dmb") || starts(m, "dsb") || starts(m, "isb")) {
        return BARRIER;
    }
    return OTHER;
}

static uint64_t value_low(qemu_plugin_mem_value value)
{
    switch (value.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8: return value.data.u8;
    case QEMU_PLUGIN_MEM_VALUE_U16: return value.data.u16;
    case QEMU_PLUGIN_MEM_VALUE_U32: return value.data.u32;
    case QEMU_PLUGIN_MEM_VALUE_U64: return value.data.u64;
    case QEMU_PLUGIN_MEM_VALUE_U128: return value.data.u128.low;
    }
    return 0;
}

static void record_line(unsigned int cpu, Site *site,
                        const struct qemu_plugin_mem_access_info *access,
                        bool repeated)
{
    uint64_t key = access->ram_addr & ~(uint64_t)(LINE_SIZE - 1);
    Shard *shard = &shards[(key >> 6) % SHARDS];
    Line *line;

    g_mutex_lock(&shard->mutex);
    line = g_hash_table_lookup(shard->lines, &key);
    if (!line) {
        if (g_hash_table_size(shard->lines) >= max_lines / SHARDS) {
            __atomic_fetch_add(&dropped_lines, 1, __ATOMIC_RELAXED);
            g_mutex_unlock(&shard->mutex);
            return;
        }
        line = g_new0(Line, 1);
        line->line = key;
        line->phys_line = access->phys_addr & ~(uint64_t)(LINE_SIZE - 1);
        g_hash_table_insert(shard->lines, &line->line, line);
    }
    if (!line->top_pc) {
        line->top_pc = site->pc;
    }
    if (cpu < 64) {
        line->cpu_bits |= UINT64_C(1) << cpu;
    }
    if (site->kind == LSE && access->is_atomic && !access->is_store) {
        line->atomic_ops++;
        line->cas_failures += !access->atomic_success;
    }
    if (site->kind == EXCLUSIVE_STORE && access->is_store) {
        line->exclusive_successes++;
    }
    line->repeated_reads += repeated;
    if (access->is_store && access->atomic_success) {
        line->writes++;
        if (line->has_writer && line->last_writer != cpu) {
            line->writer_handoffs++;
        }
        line->has_writer = true;
        line->last_writer = cpu;
    }
    g_mutex_unlock(&shard->mutex);
}

static void marker(unsigned int cpu, void *userdata)
{
    bool start = GPOINTER_TO_INT(userdata);

    if (cpu >= ncpus) {
        return;
    }
    cpus[cpu].active = start;
    if (start) {
        cpus[cpu].starts++;
    } else {
        cpus[cpu].stops++;
    }
}

static void insn_exec(unsigned int cpu, void *userdata)
{
    Site *site = userdata;

    if (cpu < ncpus && cpus[cpu].active) {
        __atomic_fetch_add(&site->executions, 1, __ATOMIC_RELAXED);
        if (site->pc >= spin_start && site->pc < spin_end &&
            starts(site->mnemonic, "wfe") && cpus[cpu].lock_depth &&
            cpus[cpu].lock_depth <= LOCK_DEPTH) {
            LockGroup *group =
                cpus[cpu].lock_stack[cpus[cpu].lock_depth - 1];

            if (group) {
                __atomic_fetch_add(&group->waits, 1, __ATOMIC_RELAXED);
            }
        }
        if (site->pc >= rwsem_start && site->pc < rwsem_end &&
            starts(site->mnemonic, "yield") && cpus[cpu].rwsem_depth &&
            cpus[cpu].rwsem_depth <= LOCK_DEPTH) {
            LockGroup *group =
                cpus[cpu].rwsem_stack[cpus[cpu].rwsem_depth - 1];

            if (group) {
                __atomic_fetch_add(&group->waits, 1, __ATOMIC_RELAXED);
            }
        }
    }
}

static void mem_access(unsigned int cpu, qemu_plugin_meminfo_t info,
                       uint64_t vaddr, void *userdata)
{
    Site *site = userdata;
    struct qemu_plugin_mem_access_info access;
    CpuState *state;
    bool repeated = false;

    if (cpu >= ncpus || !cpus[cpu].active) {
        return;
    }
    state = &cpus[cpu];
    state->events++;
    qemu_plugin_mem_get_access_info(info, vaddr, &access);
    if (!access.has_ram_addr || access.is_io) {
        return;
    }
    if (access.is_store) {
        __atomic_fetch_add(&site->writes, 1, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_add(&site->reads, 1, __ATOMIC_RELAXED);
    }
    if (site->kind == PLAIN_LOAD || site->kind == ACQUIRE_LOAD ||
        site->kind == EXCLUSIVE_LOAD) {
        ReadHistory *last = &state->recent[(site->pc >> 2) % RECENT];
        uint64_t value = value_low(qemu_plugin_mem_get_value(info));

        repeated = last->pc == site->pc &&
                   last->addr == access.ram_addr &&
                   last->value == value &&
                   state->events - last->event <= 64;
        last->pc = site->pc;
        last->addr = access.ram_addr;
        last->value = value;
        last->event = state->events;
        if (repeated) {
            __atomic_fetch_add(&site->repeated_reads, 1,
                               __ATOMIC_RELAXED);
        }
    }
    if (site->kind == LSE && access.is_atomic && !access.is_store) {
        __atomic_fetch_add(&site->atomic_ops, 1, __ATOMIC_RELAXED);
        if (!access.atomic_success) {
            __atomic_fetch_add(&site->cas_failures, 1,
                               __ATOMIC_RELAXED);
        }
    }
    if (site->kind == EXCLUSIVE_STORE && access.is_store) {
        __atomic_fetch_add(&site->exclusive_successes, 1,
                           __ATOMIC_RELAXED);
    }
    if (site->kind != PLAIN_LOAD || repeated) {
        record_line(cpu, site, &access, repeated);
    }
}

static Site *get_site(uint64_t pc, const char *mnemonic, Kind kind)
{
    Site *site;

    g_mutex_lock(&sites_mutex);
    site = g_hash_table_lookup(sites_by_pc, &pc);
    if (!site) {
        site = g_new0(Site, 1);
        site->pc = pc;
        site->kind = kind;
        g_strlcpy(site->mnemonic, mnemonic, sizeof(site->mnemonic));
        g_hash_table_insert(sites_by_pc, &site->pc, site);
        g_ptr_array_add(sites, site);
    }
    g_mutex_unlock(&sites_mutex);
    return site;
}

static void tb_trans(struct qemu_plugin_tb *tb, void *userdata)
{
    size_t count = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < count; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        uint32_t opcode;
        char mnemonic[16] = {0};
        g_autofree char *disas = NULL;
        Kind kind;
        Site *site;

        if (qemu_plugin_insn_size(insn) == 4 &&
            qemu_plugin_insn_data(insn, &opcode, 4) == 4) {
            opcode = GUINT32_FROM_LE(opcode);
            if (opcode == MARK_START || opcode == MARK_STOP) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, marker, QEMU_PLUGIN_CB_NO_REGS,
                    GINT_TO_POINTER(opcode == MARK_START));
                continue;
            }
        }
        if (pc < pc_start || pc >= pc_end) {
            continue;
        }
        disas = qemu_plugin_insn_disas(insn);
        if (!disas || sscanf(disas, "%15[a-z0-9]", mnemonic) != 1) {
            continue;
        }
        if (spin_start && pc == spin_start) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, spin_entry, QEMU_PLUGIN_CB_R_REGS, NULL);
        }
        if (spin_start && pc >= spin_start && pc < spin_end &&
            g_strcmp0(mnemonic, "ret") == 0) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, spin_return, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        if (rwsem_start && pc == rwsem_start) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, rwsem_entry, QEMU_PLUGIN_CB_R_REGS, NULL);
        }
        if (rwsem_start && pc >= rwsem_start && pc < rwsem_end &&
            g_strcmp0(mnemonic, "ret") == 0) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, rwsem_return, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        kind = classify(mnemonic);
        if (kind == OTHER) {
            continue;
        }
        site = get_site(pc, mnemonic, kind);
        if (kind == EXCLUSIVE_STORE || kind == WAIT || kind == BARRIER) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, insn_exec, QEMU_PLUGIN_CB_NO_REGS, site);
        }
        if (kind != WAIT && kind != BARRIER) {
            qemu_plugin_register_vcpu_mem_cb(
                insn, mem_access, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_MEM_RW, site);
        }
    }
}

static gint compare_sites(gconstpointer a, gconstpointer b, gpointer userdata)
{
    const Site *sa = *(Site *const *)a;
    const Site *sb = *(Site *const *)b;
    int mode = GPOINTER_TO_INT(userdata);
    uint64_t av = mode == 0 ? sa->atomic_ops :
                  mode == 1 ? sa->cas_failures :
                  mode == 2 ? sa->executions :
                  mode == 3 ? sa->repeated_reads : sa->executions;
    uint64_t bv = mode == 0 ? sb->atomic_ops :
                  mode == 1 ? sb->cas_failures :
                  mode == 2 ? sb->executions :
                  mode == 3 ? sb->repeated_reads : sb->executions;

    if (mode == 2) {
        av = sa->kind == EXCLUSIVE_STORE ? av : 0;
        bv = sb->kind == EXCLUSIVE_STORE ? bv : 0;
    }
    if (mode == 4) {
        av = sa->kind == WAIT || sa->kind == BARRIER ? av : 0;
        bv = sb->kind == WAIT || sb->kind == BARRIER ? bv : 0;
    }
    return (bv > av) - (bv < av);
}

static gint compare_lines(gconstpointer a, gconstpointer b)
{
    const Line *la = *(Line *const *)a;
    const Line *lb = *(Line *const *)b;
    uint64_t av = la->atomic_ops + la->exclusive_successes +
                  la->repeated_reads;
    uint64_t bv = lb->atomic_ops + lb->exclusive_successes +
                  lb->repeated_reads;

    return (bv > av) - (bv < av);
}

static gint compare_lock_groups(gconstpointer a, gconstpointer b)
{
    const LockGroup *left = *(LockGroup *const *)a;
    const LockGroup *right = *(LockGroup *const *)b;

    if (left->waits != right->waits) {
        return (right->waits > left->waits) - (right->waits < left->waits);
    }
    return (right->entries > left->entries) -
           (right->entries < left->entries);
}

static void plugin_exit(void *userdata)
{
    static const char *sections[] = {
        "atomic RMWs", "failed CAS", "exclusive store attempts",
        "repeated reads", "waits and barriers"
    };
    g_autoptr(GString) out = g_string_new("lockprof: AArch64 access counts\n");
    GPtrArray *lines = g_ptr_array_new();
    GPtrArray *groups = g_ptr_array_new();
    GPtrArray *rw_groups = g_ptr_array_new();
    uint64_t starts = 0, stops = 0;
    uint64_t missed_lock_entries = 0;
    uint64_t missed_rwsem_entries = 0;
    uint64_t total_rmw = 0, total_cas_fail = 0;
    uint64_t total_exclusive = 0, total_exclusive_success = 0;
    uint64_t total_waits = 0;

    for (unsigned int cpu = 0; cpu < ncpus; cpu++) {
        starts += cpus[cpu].starts;
        stops += cpus[cpu].stops;
        missed_lock_entries += cpus[cpu].missed_lock_entries;
        missed_rwsem_entries += cpus[cpu].missed_rwsem_entries;
    }
    {
        GHashTableIter iter;
        gpointer value;

        g_hash_table_iter_init(&iter, locks);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            g_ptr_array_add(groups, value);
        }
        g_hash_table_iter_init(&iter, rwsems);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            g_ptr_array_add(rw_groups, value);
        }
    }
    for (unsigned int i = 0; i < SHARDS; i++) {
        GHashTableIter iter;
        gpointer value;

        g_hash_table_iter_init(&iter, shards[i].lines);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            g_ptr_array_add(lines, value);
        }
    }
    g_string_append_printf(out,
        "markers_start=%"PRIu64" markers_stop=%"PRIu64
        " sites=%u lines=%u dropped_lines=%"PRIu64"\n",
        starts, stops, sites->len, lines->len, dropped_lines);
    for (unsigned int i = 0; i < sites->len; i++) {
        Site *site = g_ptr_array_index(sites, i);

        total_rmw += site->atomic_ops;
        total_cas_fail += site->cas_failures;
        if (site->kind == EXCLUSIVE_STORE) {
            total_exclusive += site->executions;
            total_exclusive_success += site->exclusive_successes;
        }
        if (site->kind == WAIT) {
            total_waits += site->executions;
        }
    }
    g_string_append_printf(out,
        "rmw=%"PRIu64" cas_fail=%"PRIu64
        " exclusive_attempts=%"PRIu64" exclusive_success=%"PRIu64
        " waits=%"PRIu64"\n",
        total_rmw, total_cas_fail, total_exclusive,
        total_exclusive_success, total_waits);
    for (unsigned int mode = 0; mode < G_N_ELEMENTS(sections); mode++) {
        unsigned int printed = 0;

        g_ptr_array_sort_with_data(sites, compare_sites,
                                   GINT_TO_POINTER(mode));
        g_string_append_printf(out, "%s:\n", sections[mode]);
        for (unsigned int i = 0; i < sites->len && printed < limit; i++) {
            Site *site = g_ptr_array_index(sites, i);
            uint64_t score = mode == 0 ? site->atomic_ops :
                             mode == 1 ? site->cas_failures :
                             mode == 2 && site->kind == EXCLUSIVE_STORE ?
                                 site->executions :
                             mode == 3 ? site->repeated_reads :
                             mode == 4 && (site->kind == WAIT ||
                                           site->kind == BARRIER) ?
                                 site->executions : 0;

            if (!score) {
                break;
            }
            g_string_append_printf(out,
                "  pc=%016"PRIx64" op=%s score=%"PRIu64
                " exec=%"PRIu64" reads=%"PRIu64" write_callbacks=%"PRIu64
                " rmw=%"PRIu64" cas_fail=%"PRIu64
                " stxr_success=%"PRIu64" stxr_retry=%"PRIu64
                " repeated=%"PRIu64"\n",
                site->pc, site->mnemonic, score, site->executions,
                site->reads, site->writes, site->atomic_ops,
                site->cas_failures, site->exclusive_successes,
                site->kind == EXCLUSIVE_STORE &&
                site->executions > site->exclusive_successes ?
                    site->executions - site->exclusive_successes : 0,
                site->repeated_reads);
            printed++;
        }
    }
    g_ptr_array_sort(groups, compare_lock_groups);
    g_string_append_printf(out,
        "spinlock groups=%u missed_entries=%"PRIu64"\n",
        groups->len, missed_lock_entries);
    for (unsigned int i = 0; i < groups->len && i < limit; i++) {
        LockGroup *group = g_ptr_array_index(groups, i);

        g_string_append_printf(out,
            "  lock=%016"PRIx64" caller=%016"PRIx64
            " outer_caller=%016"PRIx64" site=%016"PRIx64
            " entries=%"PRIu64" wfe=%"PRIu64" cpus=%u\n",
            group->key.addr, group->key.caller, group->key.outer_caller,
            group->key.site,
            group->entries,
            group->waits, __builtin_popcountll(group->cpu_bits));
    }
    g_ptr_array_sort(rw_groups, compare_lock_groups);
    g_string_append_printf(out,
        "rwsem groups=%u missed_entries=%"PRIu64"\n",
        rw_groups->len, missed_rwsem_entries);
    for (unsigned int i = 0; i < rw_groups->len && i < limit; i++) {
        LockGroup *group = g_ptr_array_index(rw_groups, i);

        g_string_append_printf(out,
            "  sem=%016"PRIx64" caller=%016"PRIx64
            " outer_caller=%016"PRIx64" site=%016"PRIx64
            " entries=%"PRIu64" yield=%"PRIu64" cpus=%u\n",
            group->key.addr, group->key.caller, group->key.outer_caller,
            group->key.site, group->entries,
            group->waits, __builtin_popcountll(group->cpu_bits));
    }
    g_ptr_array_sort(lines, compare_lines);
    g_string_append(out, "lock lines:\n");
    for (unsigned int i = 0; i < lines->len && i < limit; i++) {
        Line *line = g_ptr_array_index(lines, i);

        g_string_append_printf(out,
            "  ram_line=%016"PRIx64" phys_line=%016"PRIx64
            " rmw=%"PRIu64" cas_fail=%"PRIu64
            " stxr_success=%"PRIu64" repeated=%"PRIu64
            " writes=%"PRIu64" writer_cpu_changes=%"PRIu64
            " cpus=%u first_pc=%016"PRIx64"\n",
            line->line, line->phys_line, line->atomic_ops,
            line->cas_failures, line->exclusive_successes,
            line->repeated_reads, line->writes, line->writer_handoffs,
            __builtin_popcountll(line->cpu_bits), line->top_pc);
    }
    qemu_plugin_outs(out->str);
    g_ptr_array_free(lines, true);
    g_ptr_array_free(groups, true);
    g_ptr_array_free(rw_groups, true);
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
        fprintf(stderr, "lockprof requires AArch64 system emulation\n");
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
        } else if (g_strcmp0(kv[0], "limit") == 0 && value <= 1000) {
            limit = value;
        } else if (g_strcmp0(kv[0], "lines") == 0 &&
                   value >= SHARDS && value <= 1000000) {
            max_lines = value;
        } else if (g_strcmp0(kv[0], "spin_start") == 0) {
            spin_start = value;
        } else if (g_strcmp0(kv[0], "spin_end") == 0) {
            spin_end = value;
        } else if (g_strcmp0(kv[0], "rwsem_start") == 0) {
            rwsem_start = value;
        } else if (g_strcmp0(kv[0], "rwsem_end") == 0) {
            rwsem_end = value;
        } else if (g_strcmp0(kv[0], "va_bits") == 0 &&
                   value >= 32 && value <= 52) {
            va_bits = value;
        } else {
            fprintf(stderr, "lockprof: bad option %s\n", argv[i]);
            return -1;
        }
    }
    if (pc_start >= pc_end || (spin_start && spin_end <= spin_start) ||
        (!spin_start && spin_end) ||
        (rwsem_start && rwsem_end <= rwsem_start) ||
        (!rwsem_start && rwsem_end)) {
        return -1;
    }
    ncpus = MAX(info->system.max_vcpus, 1);
    cpus = g_new0(CpuState, ncpus);
    sites = g_ptr_array_new_with_free_func(g_free);
    sites_by_pc = g_hash_table_new(g_int64_hash, g_int64_equal);
    locks = g_hash_table_new_full(lock_key_hash, lock_key_equal,
                                  NULL, g_free);
    rwsems = g_hash_table_new_full(lock_key_hash, lock_key_equal,
                                   NULL, g_free);
    g_mutex_init(&sites_mutex);
    g_mutex_init(&locks_mutex);
    for (unsigned int i = 0; i < SHARDS; i++) {
        g_mutex_init(&shards[i].mutex);
        shards[i].lines = g_hash_table_new_full(g_int64_hash,
                                                 g_int64_equal, NULL, g_free);
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
