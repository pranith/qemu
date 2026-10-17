/*
 * Local TCG memory profiling experiment; not for upstream submission.
 *
 * Use with -d plugin -D report.log and -plugin libmemprof.so. Options:
 * sample=N, lines=N, limit=N, pc_start=ADDR, pc_end=ADDR, objects=FILE.
 * The objects file contains nonoverlapping virtual ranges as
 * "0xSTART 0xEND name". For useful sharing and stride results, use sample=1.
 * The cache model is an 8 KiB direct mapped cache with an equally sized
 * fully associative shadow. Counts are access patterns, not hardware events.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define LINE_BYTES 64
#define SHARDS 64
#define MODEL_LINES 128
#define RECENT_LINES 4096
#define RECENT_PAGES 4096
#define MAX_STRIDE_SITES 4096
#define SKETCH_ROWS 4
#define SKETCH_COLS 4096

typedef struct {
    uint64_t tag;
    uint64_t last;
    bool valid;
} Recent;

typedef struct {
    uint64_t pc;
    uint64_t last_vaddr;
    int64_t last_delta;
    uint64_t accesses;
    uint64_t model_misses;
    uint64_t conflict_misses;
    uint64_t streaming;
    uint64_t sparse;
    size_t last_size;
    bool seen;
} StrideSite;

typedef struct {
    uint64_t pc;
    uint64_t votes;
} PcVote;

typedef struct {
    uint64_t callbacks;
    uint64_t accesses;
    size_t target_page_size;
    uint64_t model_hits;
    uint64_t model_misses;
    uint64_t conflict_misses;
    uint64_t cold_misses;
    uint64_t short_reuse;
    uint64_t long_reuse;
    uint64_t page_revisits;
    uint64_t streaming;
    uint64_t sparse;
    uint64_t skipped_pages;
    Recent direct[MODEL_LINES];
    Recent shadow[MODEL_LINES];
    Recent recent[RECENT_LINES];
    Recent pages[RECENT_PAGES];
    GHashTable *page_set;
    GHashTable *stride_sites;
} CpuStats;

typedef struct {
    uint64_t line;
    uint64_t phys_line;
    uint64_t weight;
    uint64_t reads;
    uint64_t writes;
    uint64_t atomic_stores;
    uint64_t false_transitions;
    uint64_t true_transitions;
    uint64_t same_value_stores;
    uint64_t cpu_bits;
    PcVote top_pc[2];
    uint64_t last_pc;
    uint64_t pair_pc;
    uint64_t previous_pc;
    uint64_t last_addr;
    qemu_plugin_mem_value last_value;
    unsigned int last_cpu;
    unsigned int last_size;
    uint64_t last_mask;
    bool last_store;
    bool has_last;
    bool has_store;
} LineStats;

typedef struct {
    GMutex lock;
    GHashTable *lines;
    GPtrArray *entries;
    uint32_t *sketch;
    unsigned int cursor;
} LineShard;

typedef struct {
    uint64_t pc;
} InsnSite;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t reads;
    uint64_t writes;
    uint64_t cpu_bits;
    char *name;
} ObjectStats;

static LineShard shards[SHARDS];
static CpuStats **cpus;
static unsigned int ncpus;
static GMutex sites_lock;
static GPtrArray *sites;
static GPtrArray *objects;
static char *object_path;
static unsigned int max_lines = 65536;
static unsigned int limit = 20;
static unsigned int sample = 1;
static uint64_t pc_start;
static uint64_t pc_end = UINT64_MAX;
static uint64_t skipped_cross_page;
static uint64_t skipped_no_phys;
static uint64_t dropped_lines;
static uint64_t evicted_lines;

static void object_free(gpointer ptr)
{
    ObjectStats *object = ptr;
    g_free(object->name);
    g_free(object);
}

static gint compare_objects_by_start(gconstpointer a, gconstpointer b)
{
    const ObjectStats *oa = *(ObjectStats *const *)a;
    const ObjectStats *ob = *(ObjectStats *const *)b;

    return (oa->start > ob->start) - (oa->start < ob->start);
}

static bool load_objects(const char *path)
{
    g_autofree char *contents = NULL;
    g_auto(GStrv) lines = NULL;

    if (!g_file_get_contents(path, &contents, NULL, NULL)) {
        return false;
    }
    lines = g_strsplit(contents, "\n", -1);
    for (unsigned int i = 0; lines[i]; i++) {
        uint64_t start, end;
        char name[256];
        char *line = g_strstrip(lines[i]);
        ObjectStats *object;

        if (!*line || *line == '#') {
            continue;
        }
        if (sscanf(line, "%"SCNx64" %"SCNx64" %255s",
                   &start, &end, name) != 3 || start >= end) {
            fprintf(stderr, "memprof: invalid object range at line %u\n",
                    i + 1);
            return false;
        }
        object = g_new0(ObjectStats, 1);
        object->start = start;
        object->end = end;
        object->name = g_strdup(name);
        g_ptr_array_add(objects, object);
    }
    g_ptr_array_sort(objects, compare_objects_by_start);
    for (unsigned int i = 1; i < objects->len; i++) {
        ObjectStats *prev = g_ptr_array_index(objects, i - 1);
        ObjectStats *cur = g_ptr_array_index(objects, i);
        if (prev->end > cur->start) {
            fprintf(stderr, "memprof: overlapping object ranges\n");
            return false;
        }
    }
    return true;
}

static ObjectStats *find_object(uint64_t vaddr)
{
    unsigned int lo = 0, hi = objects->len;

    while (lo < hi) {
        unsigned int mid = lo + (hi - lo) / 2;
        ObjectStats *object = g_ptr_array_index(objects, mid);

        if (vaddr < object->start) {
            hi = mid;
        } else if (vaddr >= object->end) {
            lo = mid + 1;
        } else {
            return object;
        }
    }
    return NULL;
}

static void record_object(unsigned int cpu_index, uint64_t vaddr, bool store)
{
    ObjectStats *object = find_object(vaddr);

    if (!object) {
        return;
    }
    if (store) {
        __atomic_fetch_add(&object->writes, 1, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_add(&object->reads, 1, __ATOMIC_RELAXED);
    }
    if (cpu_index < 64) {
        __atomic_fetch_or(&object->cpu_bits, UINT64_C(1) << cpu_index,
                          __ATOMIC_RELAXED);
    }
}

static uint64_t mix64(uint64_t x)
{
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static uint32_t sketch_increment(LineShard *shard, uint64_t line)
{
    uint32_t estimate = UINT32_MAX;

    for (unsigned int row = 0; row < SKETCH_ROWS; row++) {
        unsigned int col = mix64(line + row * UINT64_C(0x9e3779b97f4a7c15))
                           % SKETCH_COLS;
        uint32_t *slot = &shard->sketch[row * SKETCH_COLS + col];
        if (*slot != UINT32_MAX) {
            ++*slot;
        }
        estimate = MIN(estimate, *slot);
    }
    return estimate;
}

static bool value_equal(qemu_plugin_mem_value a, qemu_plugin_mem_value b)
{
    if (a.type != b.type) {
        return false;
    }
    switch (a.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:
        return a.data.u8 == b.data.u8;
    case QEMU_PLUGIN_MEM_VALUE_U16:
        return a.data.u16 == b.data.u16;
    case QEMU_PLUGIN_MEM_VALUE_U32:
        return a.data.u32 == b.data.u32;
    case QEMU_PLUGIN_MEM_VALUE_U64:
        return a.data.u64 == b.data.u64;
    case QEMU_PLUGIN_MEM_VALUE_U128:
        return a.data.u128.low == b.data.u128.low &&
               a.data.u128.high == b.data.u128.high;
    default:
        return false;
    }
}

/* 0: direct hit, 1: direct miss but fully associative shadow hit, 2: miss. */
static int model_line(CpuStats *cpu, uint64_t line, uint64_t phys_line)
{
    Recent *direct = &cpu->direct[(phys_line >> 6) % MODEL_LINES];
    Recent *recent = &cpu->recent[(line >> 6) % RECENT_LINES];
    int shadow_hit = -1;
    int victim = -1;
    uint64_t oldest = UINT64_MAX;
    bool seen_recent = recent->valid && recent->tag == line;
    int result = 0;
    unsigned int i;

    cpu->accesses++;
    if (seen_recent) {
        uint64_t distance = cpu->accesses - recent->last;
        if (distance <= 32) {
            cpu->short_reuse++;
        } else {
            cpu->long_reuse++;
        }
    }
    recent->tag = line;
    recent->last = cpu->accesses;
    recent->valid = true;

    for (i = 0; i < MODEL_LINES; i++) {
        Recent *entry = &cpu->shadow[i];
        if (entry->valid && entry->tag == line) {
            shadow_hit = i;
        }
        if (!entry->valid) {
            victim = i;
            break;
        }
        if (entry->last < oldest) {
            oldest = entry->last;
            victim = i;
        }
    }

    if (direct->valid && direct->tag == line) {
        cpu->model_hits++;
    } else {
        cpu->model_misses++;
        if (shadow_hit >= 0) {
            cpu->conflict_misses++;
            result = 1;
        } else if (!seen_recent) {
            /* This is a bounded first-seen estimate, not exact cold misses. */
            cpu->cold_misses++;
            result = 2;
        } else {
            result = 2;
        }
    }
    direct->valid = true;
    direct->tag = line;
    direct->last = cpu->accesses;

    if (shadow_hit >= 0) {
        cpu->shadow[shadow_hit].last = cpu->accesses;
    } else {
        cpu->shadow[victim].tag = line;
        cpu->shadow[victim].last = cpu->accesses;
        cpu->shadow[victim].valid = true;
    }
    return result;
}

static void model_page(CpuStats *cpu, uint64_t page)
{
    Recent *recent = &cpu->pages[(page >> 12) % RECENT_PAGES];

    if (recent->valid && recent->tag == page) {
        cpu->page_revisits++;
    }
    recent->tag = page;
    recent->valid = true;
    if (g_hash_table_size(cpu->page_set) < 16384) {
        if (!g_hash_table_contains(cpu->page_set, &page)) {
            uint64_t *saved = g_new(uint64_t, 1);
            *saved = page;
            g_hash_table_add(cpu->page_set, saved);
        }
    } else if (!g_hash_table_contains(cpu->page_set, &page)) {
        cpu->skipped_pages++;
    }
}

static StrideSite *model_stride(CpuStats *cpu, uint64_t pc,
                                uint64_t vaddr, size_t size)
{
    StrideSite *site = g_hash_table_lookup(cpu->stride_sites, &pc);

    if (!site) {
        if (g_hash_table_size(cpu->stride_sites) >= MAX_STRIDE_SITES) {
            return NULL;
        }
        site = g_new0(StrideSite, 1);
        site->pc = pc;
        g_hash_table_insert(cpu->stride_sites, &site->pc, site);
    }
    site->accesses++;
    if (site->seen && sample == 1 && site->last_size == size) {
        int64_t delta = (int64_t)(vaddr - site->last_vaddr);
        if (delta == site->last_delta && delta == (int64_t)size) {
            site->streaming++;
            cpu->streaming++;
        } else if (delta == site->last_delta &&
                   (delta > LINE_BYTES || delta < -LINE_BYTES)) {
            site->sparse++;
            cpu->sparse++;
        }
        site->last_delta = delta;
    }
    site->last_vaddr = vaddr;
    site->last_size = size;
    site->seen = true;
    return site;
}

static void record_pc_vote(LineStats *line, uint64_t pc)
{
    for (unsigned int i = 0; i < 2; i++) {
        if (line->top_pc[i].votes && line->top_pc[i].pc == pc) {
            line->top_pc[i].votes++;
            return;
        }
    }
    for (unsigned int i = 0; i < 2; i++) {
        if (!line->top_pc[i].votes) {
            line->top_pc[i].pc = pc;
            line->top_pc[i].votes = 1;
            return;
        }
    }
    line->top_pc[0].votes--;
    line->top_pc[1].votes--;
}

static uint64_t byte_mask(unsigned int offset, size_t size)
{
    if (size == LINE_BYTES) {
        return UINT64_MAX;
    }
    return ((UINT64_C(1) << size) - 1) << offset;
}

static void record_line(unsigned int cpu_index, uint64_t pc,
                        uint64_t addr, uint64_t paddr, size_t size,
                        bool store, bool atomic,
                        bool whole_access, qemu_plugin_mem_value value)
{
    uint64_t line = addr & ~(uint64_t)(LINE_BYTES - 1);
    unsigned int offset = addr & (LINE_BYTES - 1);
    uint64_t mask = byte_mask(offset, size);
    LineShard *shard = &shards[(line >> 6) % SHARDS];
    LineStats *s;
    uint32_t estimate;

    g_mutex_lock(&shard->lock);
    estimate = sketch_increment(shard, line);
    s = g_hash_table_lookup(shard->lines, &line);
    if (!s) {
        if (g_hash_table_size(shard->lines) >= max_lines / SHARDS) {
            unsigned int best = 0;
            uint64_t lightest = UINT64_MAX;

            for (unsigned int i = 0; i < 8; i++) {
                unsigned int pos = (shard->cursor + i) % shard->entries->len;
                LineStats *candidate = g_ptr_array_index(shard->entries, pos);
                if (candidate->weight < lightest) {
                    lightest = candidate->weight;
                    best = pos;
                }
            }
            shard->cursor = (shard->cursor + 8) % shard->entries->len;
            if (estimate <= lightest) {
                __atomic_fetch_add(&dropped_lines, 1, __ATOMIC_RELAXED);
                g_mutex_unlock(&shard->lock);
                return;
            }
            LineStats *victim = g_ptr_array_index(shard->entries, best);
            g_hash_table_remove(shard->lines, &victim->line);
            s = g_new0(LineStats, 1);
            s->line = line;
            s->phys_line = paddr & ~(uint64_t)(LINE_BYTES - 1);
            s->weight = estimate;
            g_ptr_array_index(shard->entries, best) = s;
            __atomic_fetch_add(&evicted_lines, 1, __ATOMIC_RELAXED);
        } else {
            s = g_new0(LineStats, 1);
            s->line = line;
            s->phys_line = paddr & ~(uint64_t)(LINE_BYTES - 1);
            s->weight = estimate;
            g_ptr_array_add(shard->entries, s);
        }
        g_hash_table_insert(shard->lines, &s->line, s);
    } else {
        s->weight = MAX(s->weight + 1, estimate);
    }
    if (store) {
        s->writes++;
        s->atomic_stores += atomic;
    } else {
        s->reads++;
    }
    record_pc_vote(s, pc);
    if (cpu_index < 64) {
        s->cpu_bits |= UINT64_C(1) << cpu_index;
    }
    if (s->has_last && s->last_cpu != cpu_index &&
        (store || s->last_store)) {
        if (mask & s->last_mask) {
            s->true_transitions++;
        } else {
            s->false_transitions++;
        }
        s->pair_pc = s->last_pc;
        s->previous_pc = pc;
    }
    if (store && whole_access) {
        if (s->has_store && s->last_addr == addr &&
            s->last_size == size && value_equal(s->last_value, value)) {
            s->same_value_stores++;
        }
        s->has_store = true;
        s->last_addr = addr;
        s->last_size = size;
        s->last_value = value;
    } else if (store) {
        s->has_store = false;
    }
    s->last_pc = pc;
    s->last_cpu = cpu_index;
    s->last_mask = mask;
    s->last_store = store;
    s->has_last = true;
    g_mutex_unlock(&shard->lock);
}

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *userdata)
{
    InsnSite *site = userdata;
    struct qemu_plugin_mem_access_info access;
    CpuStats *cpu;
    qemu_plugin_mem_value value = {0};
    StrideSite *profile;
    uint64_t addr;
    uint64_t paddr;
    size_t remaining;

    if (cpu_index >= ncpus) {
        return;
    }
    cpu = cpus[cpu_index];
    cpu->callbacks++;
    if (cpu->callbacks % sample != 0) {
        return;
    }
    qemu_plugin_mem_get_access_info(info, vaddr, &access);
    if (!cpu->target_page_size) {
        cpu->target_page_size = qemu_plugin_target_page_size();
    }
    if (!access.has_phys_addr || !access.has_ram_addr || access.is_io) {
        __atomic_fetch_add(&skipped_no_phys, 1, __ATOMIC_RELAXED);
        return;
    }
    if ((vaddr & (cpu->target_page_size - 1)) + access.size >
        cpu->target_page_size) {
        __atomic_fetch_add(&skipped_cross_page, 1, __ATOMIC_RELAXED);
        return;
    }
    if (access.is_store) {
        value = qemu_plugin_mem_get_value(info);
    }
    if (objects->len) {
        record_object(cpu_index, vaddr, access.is_store);
    }
    profile = model_stride(cpu, site->pc, vaddr, access.size);
    addr = access.ram_addr;
    paddr = access.phys_addr;
    remaining = access.size;
    while (remaining) {
        size_t n = MIN(remaining, LINE_BYTES - (addr & (LINE_BYTES - 1)));
        uint64_t line = addr & ~(uint64_t)(LINE_BYTES - 1);

        int model_result = model_line(cpu, line,
                                      paddr & ~(uint64_t)(LINE_BYTES - 1));
        if (profile && model_result) {
            profile->model_misses++;
            profile->conflict_misses += model_result == 1;
        }
        model_page(cpu, paddr & ~UINT64_C(4095));
        record_line(cpu_index, site->pc, addr, paddr, n, access.is_store,
                    access.is_atomic, n == access.size, value);
        remaining -= n;
        addr += n;
        paddr += n;
    }
}

static void vcpu_tb_trans(struct qemu_plugin_tb *tb, void *userdata)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        InsnSite *site;

        if (pc < pc_start || pc >= pc_end) {
            continue;
        }
        site = g_new(InsnSite, 1);
        site->pc = pc;
        g_mutex_lock(&sites_lock);
        g_ptr_array_add(sites, site);
        g_mutex_unlock(&sites_lock);
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, site);
    }
}

static void plugin_flush(void *userdata)
{
    g_mutex_lock(&sites_lock);
    g_ptr_array_set_size(sites, 0);
    g_mutex_unlock(&sites_lock);
}

static uint64_t line_score(const LineStats *s, unsigned int mode)
{
    switch (mode) {
    case 0: return s->reads + s->writes;
    case 1: return s->false_transitions;
    case 2: return s->true_transitions;
    default: return s->same_value_stores;
    }
}

static gint compare_lines(gconstpointer a, gconstpointer b, gpointer userdata)
{
    const LineStats *sa = *(LineStats *const *)a;
    const LineStats *sb = *(LineStats *const *)b;
    unsigned int mode = GPOINTER_TO_UINT(userdata);
    uint64_t av = line_score(sa, mode), bv = line_score(sb, mode);

    return (bv > av) - (bv < av);
}

static gint compare_sites(gconstpointer a, gconstpointer b, gpointer userdata)
{
    const StrideSite *sa = *(StrideSite *const *)a;
    const StrideSite *sb = *(StrideSite *const *)b;
    uint64_t av = sa->model_misses, bv = sb->model_misses;

    return (bv > av) - (bv < av);
}

static gint compare_patterns(gconstpointer a, gconstpointer b,
                             gpointer userdata)
{
    const StrideSite *sa = *(StrideSite *const *)a;
    const StrideSite *sb = *(StrideSite *const *)b;
    uint64_t av = sa->streaming + sa->sparse;
    uint64_t bv = sb->streaming + sb->sparse;

    return (bv > av) - (bv < av);
}

static gint compare_objects_by_access(gconstpointer a, gconstpointer b,
                                      gpointer userdata)
{
    const ObjectStats *oa = *(ObjectStats *const *)a;
    const ObjectStats *ob = *(ObjectStats *const *)b;
    uint64_t av = oa->reads + oa->writes;
    uint64_t bv = ob->reads + ob->writes;

    return (bv > av) - (bv < av);
}

static void plugin_exit(void *userdata)
{
    static const char *titles[] = {
        "hot lines", "false sharing candidates",
        "true sharing candidates", "same-value stores"
    };
    GPtrArray *all = g_ptr_array_new();
    GString *out = g_string_new("memprof: modeled guest memory accesses\n");

    for (unsigned int i = 0; i < SHARDS; i++) {
        GHashTableIter iter;
        gpointer value;

        g_hash_table_iter_init(&iter, shards[i].lines);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            g_ptr_array_add(all, value);
        }
    }
    g_string_append_printf(out, "sample=%u tracked_lines=%u "
                           "dropped_lines=%"PRIu64" evicted_lines=%"PRIu64
                           " cross_page=%"PRIu64" "
                           "no_phys_or_io=%"PRIu64"\n",
                           sample, all->len, dropped_lines, evicted_lines,
                           skipped_cross_page, skipped_no_phys);
    g_string_append(out, "cache_model=8KiB direct mapped with 8KiB "
                         "fully associative shadow; pages=4KiB\n");
    if (sample != 1) {
        g_string_append(out, "stride statistics disabled while sampling\n");
    }
    for (unsigned int mode = 0; mode < G_N_ELEMENTS(titles); mode++) {
        unsigned int printed = 0;

        g_ptr_array_sort_with_data(all, compare_lines, GUINT_TO_POINTER(mode));
        g_string_append_printf(out, "%s:\n", titles[mode]);
        for (unsigned int i = 0; i < all->len && printed < limit; i++) {
            LineStats *s = g_ptr_array_index(all, i);
            if (!line_score(s, mode)) {
                break;
            }
            g_string_append_printf(out,
                "  ram_line=%016"PRIx64" phys_line=%016"PRIx64
                " reads=%"PRIu64" writes=%"PRIu64
                " cpus=%u false=%"PRIu64" true=%"PRIu64
                " atomic_stores=%"PRIu64" same_value=%"PRIu64
                " top_pcs=%016"PRIx64",%016"PRIx64
                " last_pair=%016"PRIx64",%016"PRIx64"\n",
                s->line, s->phys_line, s->reads, s->writes,
                __builtin_popcountll(s->cpu_bits),
                s->false_transitions, s->true_transitions,
                s->atomic_stores, s->same_value_stores,
                s->top_pc[0].pc, s->top_pc[1].pc,
                s->pair_pc, s->previous_pc);
            printed++;
        }
    }
    for (unsigned int i = 0; i < ncpus; i++) {
        CpuStats *cpu = cpus[i];
        if (!cpu || !cpu->accesses) {
            continue;
        }
        g_string_append_printf(out,
            "vcpu=%u callbacks=%"PRIu64" model_hits=%"PRIu64
            " model_misses=%"PRIu64" conflict=%"PRIu64
            " cold_est=%"PRIu64" short_reuse=%"PRIu64
            " long_reuse=%"PRIu64" pages=%u page_revisits=%"PRIu64
            " streaming=%"PRIu64" sparse=%"PRIu64
            " page_cap_skips=%"PRIu64"\n",
            i, cpu->callbacks, cpu->model_hits, cpu->model_misses,
            cpu->conflict_misses, cpu->cold_misses,
            cpu->short_reuse, cpu->long_reuse,
            g_hash_table_size(cpu->page_set), cpu->page_revisits,
            cpu->streaming, cpu->sparse, cpu->skipped_pages);
        GPtrArray *site_list = g_ptr_array_new();
        GHashTableIter iter;
        gpointer value;

        g_hash_table_iter_init(&iter, cpu->stride_sites);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            g_ptr_array_add(site_list, value);
        }
        g_ptr_array_sort_with_data(site_list, compare_sites, NULL);
        for (unsigned int j = 0; j < site_list->len && j < limit; j++) {
            StrideSite *site = g_ptr_array_index(site_list, j);
            if (!site->model_misses) {
                break;
            }
            g_string_append_printf(out,
                "  pc=%016"PRIx64" accesses=%"PRIu64
                " model_misses=%"PRIu64" conflict=%"PRIu64
                " streaming=%"PRIu64" sparse=%"PRIu64"\n",
                site->pc, site->accesses, site->model_misses,
                site->conflict_misses, site->streaming, site->sparse);
        }
        if (sample == 1) {
            g_ptr_array_sort_with_data(site_list, compare_patterns, NULL);
            g_string_append(out, "  leading address patterns:\n");
            for (unsigned int j = 0; j < site_list->len && j < limit; j++) {
                StrideSite *site = g_ptr_array_index(site_list, j);
                if (!site->streaming && !site->sparse) {
                    break;
                }
                g_string_append_printf(out,
                    "    pc=%016"PRIx64" streaming=%"PRIu64
                    " sparse=%"PRIu64"\n",
                    site->pc, site->streaming, site->sparse);
            }
        }
        g_ptr_array_free(site_list, true);
    }
    if (objects->len) {
        g_ptr_array_sort_with_data(objects, compare_objects_by_access, NULL);
        g_string_append(out, "annotated objects and fields:\n");
        for (unsigned int i = 0; i < objects->len && i < limit; i++) {
            ObjectStats *object = g_ptr_array_index(objects, i);
            if (!object->reads && !object->writes) {
                break;
            }
            g_string_append_printf(out,
                "  %s va=%016"PRIx64"..%016"PRIx64
                " reads=%"PRIu64" writes=%"PRIu64" cpus=%u\n",
                object->name, object->start, object->end,
                object->reads, object->writes,
                __builtin_popcountll(object->cpu_bits));
        }
    }
    qemu_plugin_outs(out->str);
    g_string_free(out, true);
    g_ptr_array_free(all, true);
    for (unsigned int i = 0; i < SHARDS; i++) {
        g_hash_table_destroy(shards[i].lines);
        g_ptr_array_free(shards[i].entries, true);
        g_free(shards[i].sketch);
        g_mutex_clear(&shards[i].lock);
    }
    for (unsigned int i = 0; i < ncpus; i++) {
        if (cpus[i]) {
            g_hash_table_destroy(cpus[i]->page_set);
            g_hash_table_destroy(cpus[i]->stride_sites);
            g_free(cpus[i]);
        }
    }
    g_free(cpus);
    g_ptr_array_free(sites, true);
    g_ptr_array_free(objects, true);
    g_free(object_path);
    g_mutex_clear(&sites_lock);
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
    if (!info->system_emulation) {
        fprintf(stderr, "memprof requires system emulation\n");
        return -1;
    }
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        uint64_t value;

        if (kv[1] && g_strcmp0(kv[0], "objects") == 0) {
            g_free(object_path);
            object_path = g_strdup(kv[1]);
            continue;
        }
        if (!kv[1] || !parse_number(kv[1], &value)) {
            return -1;
        }
        if (g_strcmp0(kv[0], "sample") == 0 && value > 0 &&
            value <= UINT32_MAX) {
            sample = value;
        } else if (g_strcmp0(kv[0], "lines") == 0 &&
                   value >= SHARDS && value <= UINT32_MAX) {
            max_lines = value;
        } else if (g_strcmp0(kv[0], "limit") == 0 &&
                   value <= UINT32_MAX) {
            limit = value;
        } else if (g_strcmp0(kv[0], "pc_start") == 0) {
            pc_start = value;
        } else if (g_strcmp0(kv[0], "pc_end") == 0) {
            pc_end = value;
        } else {
            fprintf(stderr, "memprof: unknown or invalid option: %s\n",
                    argv[i]);
            return -1;
        }
    }
    objects = g_ptr_array_new_with_free_func(object_free);
    if (object_path && !load_objects(object_path)) {
        return -1;
    }
    ncpus = MAX(info->system.max_vcpus, 1);
    g_mutex_init(&sites_lock);
    cpus = g_new0(CpuStats *, ncpus);
    for (unsigned int i = 0; i < ncpus; i++) {
        cpus[i] = g_new0(CpuStats, 1);
        cpus[i]->page_set = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                                   g_free, NULL);
        cpus[i]->stride_sites = g_hash_table_new_full(g_int64_hash,
                                                       g_int64_equal, NULL,
                                                       g_free);
    }
    sites = g_ptr_array_new_with_free_func(g_free);
    for (unsigned int i = 0; i < SHARDS; i++) {
        g_mutex_init(&shards[i].lock);
        shards[i].lines = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                                 NULL, g_free);
        shards[i].entries = g_ptr_array_new();
        shards[i].sketch = g_new0(uint32_t, SKETCH_ROWS * SKETCH_COLS);
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans, NULL);
    qemu_plugin_register_flush_cb(id, plugin_flush, NULL);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
