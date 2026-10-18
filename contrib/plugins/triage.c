/*
 * Local TCG performance triage experiment; not for upstream submission.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Usage: -d plugin -D triage.log -plugin libtriage.so[,top=20]
 * Options: top=N, sites=N, lines=N, pc_start=ADDR, pc_end=ADDR,
 * symbols=System.map. Use nokaslr for kernel symbol addresses.
 * Events are architectural observations, not hardware timing samples.
 */
#include <glib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define LINE_SIZE 64
#define WRITERS 8

typedef struct {
    uint64_t pid;
    uint64_t pc;
} SiteKey;

typedef struct {
    SiteKey key;
    GList *lru_link;
    char mnemonic[32];
    char *symbol;
    char *image;
    uint32_t properties;
    bool metadata_ready;
    uint64_t insns, reads, writes, atomics, failed_atomics;
    uint64_t taken, not_taken, unknown_branches;
} Site;

typedef struct {
    uint64_t space;
    uint64_t number;
} LineKey;

typedef struct {
    unsigned int vcpu;
    uint64_t bytes;
    uint64_t writes;
} Writer;

typedef struct {
    LineKey key;
    GList *lru_link;
    uint64_t reads, writes, atomics, failed_atomics;
    uint64_t first_pc, last_pc;
    unsigned int n_writers;
    Writer writer[WRITERS];
    bool writer_overflow;
    unsigned int n_atomic_vcpus;
    unsigned int atomic_vcpu[WRITERS];
    bool atomic_overflow;
} Line;

typedef struct {
    uint64_t addr;
    char *name;
} Symbol;

static GMutex lock;
static GHashTable *sites;
static GHashTable *lines;
static GQueue site_lru;
static GQueue line_lru;
static GArray *kernel_symbols;
static char *symbol_path;
static struct qemu_plugin_trace_buffer *buffer;
static bool system_emulation;
static unsigned int top = 20;
static unsigned int max_sites = 100000;
static unsigned int max_lines = 65536;
static uint64_t pc_start, pc_end = UINT64_MAX;
static uint64_t evicted_sites, evicted_lines, lost_virtual_identity;
static uint64_t task_starts, task_forks, task_execs;

static guint pair_hash(gconstpointer value)
{
    const uint64_t *pair = value;
    return (guint) (pair[0] ^ (pair[0] >> 32) ^ pair[1] ^
                   (pair[1] >> 32));
}

static gint compare_symbol(gconstpointer a, gconstpointer b)
{
    const Symbol *sa = a, *sb = b;
    return (sa->addr > sb->addr) - (sa->addr < sb->addr);
}

static bool load_symbols(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[512], type, name[384];
    uint64_t addr;

    if (!file) {
        return false;
    }
    kernel_symbols = g_array_new(false, false, sizeof(Symbol));
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%" SCNx64 " %c %383s", &addr, &type, name) == 3 &&
            strchr("TtWw", type)) {
            Symbol symbol = { addr, g_strdup(name) };
            g_array_append_val(kernel_symbols, symbol);
        }
    }
    fclose(file);
    g_array_sort(kernel_symbols, compare_symbol);
    return kernel_symbols->len != 0;
}

static const Symbol *find_symbol(uint64_t pc)
{
    size_t lo = 0, hi;

    if (!kernel_symbols) {
        return NULL;
    }
    hi = kernel_symbols->len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        Symbol *symbol = &g_array_index(kernel_symbols, Symbol, mid);

        if (symbol->addr <= pc) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (!lo) {
        return NULL;
    }
    const Symbol *symbol = &g_array_index(kernel_symbols, Symbol, lo - 1);
    return pc - symbol->addr < 0x100000 ? symbol : NULL;
}

static gboolean pair_equal(gconstpointer a, gconstpointer b)
{
    return memcmp(a, b, sizeof(uint64_t) * 2) == 0;
}

static void site_free(gpointer value)
{
    Site *site = value;
    g_free(site->symbol);
    g_free(site->image);
    g_free(site);
}

static uint64_t current_pid(void)
{
    struct qemu_plugin_exec_context context = { 0 };

    if (!system_emulation &&
        qemu_plugin_get_exec_context(&context, sizeof(context)) &&
        (context.valid_fields & QEMU_PLUGIN_CONTEXT_PID)) {
        return context.pid;
    }
    return 0;
}

/* Call with lock held. PID zero is also the translation-time fallback. */
static Site *get_site(uint64_t pid, uint64_t pc, bool create)
{
    SiteKey key = { pid, pc };
    Site *site = g_hash_table_lookup(sites, &key);

    if (site) {
        g_queue_unlink(&site_lru, site->lru_link);
        g_queue_push_tail_link(&site_lru, site->lru_link);
        return site;
    }
    if (!create) {
        return NULL;
    }
    if (g_hash_table_size(sites) >= max_sites) {
        Site *old = g_queue_pop_head(&site_lru);
        g_hash_table_remove(sites, &old->key);
        evicted_sites++;
    }
    site = g_new0(Site, 1);
    site->key = key;
    g_hash_table_insert(sites, &site->key, site);
    g_queue_push_tail(&site_lru, site);
    site->lru_link = g_queue_peek_tail_link(&site_lru);
    return site;
}

static Site *runtime_site(uint64_t pid, uint64_t pc)
{
    Site *site = get_site(pid, pc, true);
    Site *template;

    if (!site || site->metadata_ready || !pid) {
        return site;
    }
    template = get_site(0, pc, false);
    if (template && template->metadata_ready) {
        memcpy(site->mnemonic, template->mnemonic, sizeof(site->mnemonic));
        site->properties = template->properties;
        site->symbol = g_strdup(template->symbol);
        site->image = g_strdup(template->image);
        site->metadata_ready = true;
    }
    return site;
}

static Line *get_line(LineKey key)
{
    Line *line = g_hash_table_lookup(lines, &key);

    if (line) {
        g_queue_unlink(&line_lru, line->lru_link);
        g_queue_push_tail_link(&line_lru, line->lru_link);
        return line;
    }
    if (g_hash_table_size(lines) >= max_lines) {
        Line *old = g_queue_pop_head(&line_lru);
        g_hash_table_remove(lines, &old->key);
        evicted_lines++;
    }
    line = g_new0(Line, 1);
    line->key = key;
    g_hash_table_insert(lines, &line->key, line);
    g_queue_push_tail(&line_lru, line);
    line->lru_link = g_queue_peek_tail_link(&line_lru);
    return line;
}

static uint64_t byte_mask(unsigned int offset, unsigned int length)
{
    uint64_t mask = length == 64 ? UINT64_MAX : (1ULL << length) - 1;
    return mask << offset;
}

static void record_memory(unsigned int vcpu, uint64_t pid,
                          const struct qemu_plugin_trace_record *record)
{
    uint64_t address, space;
    uint32_t remaining = record->size;
    Site *site = runtime_site(pid, record->pc);

    if (site) {
        site->reads += !record->is_store;
        site->writes += record->is_store;
        site->atomics += record->is_atomic;
        site->failed_atomics += record->is_atomic &&
                                !record->atomic_success;
    }
    if (record->is_io || !remaining) {
        return;
    }
    if (record->has_ram_addr) {
        address = record->ram_addr;
        space = 1;
    } else if (record->has_phys_addr) {
        address = record->phys_addr;
        space = 2;
    } else {
        address = record->vaddr;
        space = pid ? (pid << 3) | 3 : ((uint64_t) vcpu << 3) | 4;
        lost_virtual_identity += !pid;
    }
    /* Bound unusual vector accesses and avoid wrapping the address. */
    remaining = MIN(remaining, 4096);
    while (remaining && address <= UINT64_MAX - remaining) {
        unsigned int offset = address & (LINE_SIZE - 1);
        unsigned int chunk = MIN(remaining, LINE_SIZE - offset);
        LineKey key = { space, address / LINE_SIZE };
        Line *line = get_line(key);

        if (line) {
            line->first_pc = line->first_pc ?: record->pc;
            line->last_pc = record->pc;
            line->reads += !record->is_store;
            line->writes += record->is_store;
            line->atomics += record->is_atomic;
            line->failed_atomics += record->is_atomic &&
                                    !record->atomic_success;
            if (record->is_atomic) {
                unsigned int i;
                for (i = 0; i < line->n_atomic_vcpus; i++) {
                    if (line->atomic_vcpu[i] == vcpu) {
                        break;
                    }
                }
                if (i == line->n_atomic_vcpus) {
                    if (i == WRITERS) {
                        line->atomic_overflow = true;
                    } else {
                        line->atomic_vcpu[i] = vcpu;
                        line->n_atomic_vcpus++;
                    }
                }
            }
            if (record->is_store) {
                unsigned int i;
                for (i = 0; i < line->n_writers; i++) {
                    if (line->writer[i].vcpu == vcpu) {
                        break;
                    }
                }
                if (i == line->n_writers) {
                    if (i == WRITERS) {
                        line->writer_overflow = true;
                        goto next_line;
                    }
                    line->writer[i].vcpu = vcpu;
                    line->n_writers++;
                }
                line->writer[i].bytes |= byte_mask(offset, chunk);
                line->writer[i].writes++;
            }
        }
next_line:
        address += chunk;
        remaining -= chunk;
    }
}

static void trace_batch(unsigned int vcpu, const void *records,
                        size_t count, void *userdata)
{
    const struct qemu_plugin_trace_record *trace = records;
    uint64_t pid = current_pid();

    g_mutex_lock(&lock);
    for (size_t i = 0; i < count; i++) {
        const struct qemu_plugin_trace_record *record = &trace[i];
        Site *site;

        if (record->pc < pc_start || record->pc > pc_end) {
            continue;
        }
        if (record->kind == QEMU_PLUGIN_TRACE_MEMORY) {
            record_memory(vcpu, pid, record);
        } else if (record->kind == QEMU_PLUGIN_TRACE_INSN_BEFORE) {
            site = runtime_site(pid, record->pc);
            if (site) {
                site->insns++;
            }
        }
    }
    g_mutex_unlock(&lock);
}

static void translate(struct qemu_plugin_tb *tb, void *userdata)
{
    uint64_t pid = current_pid();

    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        struct qemu_plugin_insn_decode decoded = {
            .struct_size = sizeof(decoded),
        };
        const char *symbol;
        Site *site;

        if (pc < pc_start || pc > pc_end) {
            continue;
        }
        g_mutex_lock(&lock);
        site = get_site(pid, pc, true);
        if (site && !site->metadata_ready) {
            if (qemu_plugin_insn_decode(insn, &decoded)) {
                g_strlcpy(site->mnemonic, decoded.mnemonic,
                          sizeof(site->mnemonic));
                site->properties = decoded.properties;
            } else {
                site->properties = qemu_plugin_insn_get_properties(insn);
            }
            symbol = qemu_plugin_insn_symbol(insn);
            if (symbol) {
                site->symbol = g_strdup(symbol);
            }
            if (!system_emulation) {
                char *path = NULL;
                if (qemu_plugin_user_image_lookup(pc, NULL, NULL, &path)) {
                    site->image = path;
                }
            }
            site->metadata_ready = true;
        }
        g_mutex_unlock(&lock);
        qemu_plugin_register_vcpu_insn_trace(insn, buffer,
                                              QEMU_PLUGIN_TRACE_INSN_BEFORE);
        qemu_plugin_register_vcpu_mem_trace(insn, buffer, QEMU_PLUGIN_MEM_RW);
    }
}

static void branch(unsigned int vcpu,
                   const struct qemu_plugin_branch_event *event,
                   void *userdata)
{
    uint64_t pid, pc = event->edge.from_pc;
    Site *site;

    if (pc < pc_start || pc > pc_end || !event->conditional) {
        return;
    }
    pid = current_pid();
    g_mutex_lock(&lock);
    site = runtime_site(pid, pc);
    if (site) {
        if (!event->outcome_known) {
            site->unknown_branches++;
        } else if (event->taken) {
            site->taken++;
        } else {
            site->not_taken++;
        }
    }
    g_mutex_unlock(&lock);
}

static void task_event(const struct qemu_plugin_user_task_event *event,
                       void *userdata)
{
    g_mutex_lock(&lock);
    task_starts += event->type == QEMU_PLUGIN_USER_THREAD_START;
    task_forks += event->type == QEMU_PLUGIN_USER_FORK_CHILD;
    task_execs += event->type == QEMU_PLUGIN_USER_EXEC_ATTEMPT;
    g_mutex_unlock(&lock);
}

static void image_event(const struct qemu_plugin_user_image_event *event,
                        void *userdata)
{
    /* Registration enables lookup from the translation callback. */
}

static void vcpu_exit(unsigned int vcpu, void *userdata)
{
    qemu_plugin_trace_buffer_flush(buffer, vcpu);
}

static gint compare_insns(gconstpointer a, gconstpointer b)
{
    const Site *sa = a, *sb = b;
    return (sa->insns < sb->insns) - (sa->insns > sb->insns);
}

static gint compare_memory(gconstpointer a, gconstpointer b)
{
    const Site *sa = a, *sb = b;
    uint64_t am = sa->reads + sa->writes;
    uint64_t bm = sb->reads + sb->writes;
    return (am < bm) - (am > bm);
}

static gint compare_atomic(gconstpointer a, gconstpointer b)
{
    const Site *sa = a, *sb = b;
    return (sa->atomics < sb->atomics) - (sa->atomics > sb->atomics);
}

static uint64_t branch_mix(const Site *site)
{
    return MIN(site->taken, site->not_taken);
}

static gint compare_branch(gconstpointer a, gconstpointer b)
{
    return (branch_mix(a) < branch_mix(b)) -
           (branch_mix(a) > branch_mix(b));
}

static unsigned int disjoint_writer_pairs(const Line *line)
{
    unsigned int pairs = 0;

    for (unsigned int i = 0; i < line->n_writers; i++) {
        for (unsigned int j = i + 1; j < line->n_writers; j++) {
            pairs += !(line->writer[i].bytes & line->writer[j].bytes);
        }
    }
    return pairs;
}

static gint compare_lines(gconstpointer a, gconstpointer b)
{
    const Line *la = a, *lb = b;
    uint64_t ascore = la->writes * disjoint_writer_pairs(la);
    uint64_t bscore = lb->writes * disjoint_writer_pairs(lb);
    return (ascore < bscore) - (ascore > bscore);
}

static gint compare_atomic_lines(gconstpointer a, gconstpointer b)
{
    const Line *la = a, *lb = b;
    uint64_t ascore = la->n_atomic_vcpus >= 2 ? la->atomics : 0;
    uint64_t bscore = lb->n_atomic_vcpus >= 2 ? lb->atomics : 0;

    return (ascore < bscore) - (ascore > bscore);
}

static void append_site(GString *out, const Site *site, uint64_t primary)
{
    const Symbol *symbol = site->symbol ? NULL : find_symbol(site->key.pc);

    g_string_append_printf(out,
        "%12" PRIu64 "  pid=%-6" PRIu64 " pc=%016" PRIx64
        "  ins=%" PRIu64 " r=%" PRIu64 " w=%" PRIu64
        " atomic=%" PRIu64 " fail=%" PRIu64,
        primary, site->key.pid, site->key.pc, site->insns,
        site->reads, site->writes, site->atomics, site->failed_atomics);
    if (site->mnemonic[0]) {
        g_string_append_printf(out, "  %s", site->mnemonic);
    }
    if (site->symbol) {
        g_string_append_printf(out, "  %s", site->symbol);
    } else if (symbol) {
        g_string_append_printf(out, "  %s+0x%" PRIx64,
                               symbol->name, site->key.pc - symbol->addr);
    }
    if (site->image) {
        g_string_append_printf(out, "  [%s]", site->image);
    }
    g_string_append_c(out, '\n');
}

static void format_line_space(char *out, size_t size, uint64_t space)
{
    if (space == 1) {
        g_strlcpy(out, "ram", size);
    } else if (space == 2) {
        g_strlcpy(out, "phys", size);
    } else if ((space & 7) == 3) {
        g_snprintf(out, size, "virt-pid:%" PRIu64, space >> 3);
    } else {
        g_snprintf(out, size, "virt-vcpu:%" PRIu64, space >> 3);
    }
}

static void report_sites(GString *out, GList *all, const char *title,
                         GCompareFunc compare, unsigned int category)
{
    unsigned int shown = 0;
    GList *sorted = g_list_sort(g_list_copy(all), compare);

    g_string_append_printf(out, "\n%s\n", title);
    for (GList *it = sorted; it && shown < top; it = it->next) {
        Site *site = it->data;
        uint64_t score = category == 0 ? site->insns :
                         category == 1 ? site->reads + site->writes :
                         category == 2 ? site->atomics : branch_mix(site);

        if (!score) {
            break;
        }
        append_site(out, site, score);
        if (category == 3) {
            g_string_append_printf(out,
                "              taken=%" PRIu64 " not_taken=%" PRIu64
                " unknown=%" PRIu64 "\n", site->taken, site->not_taken,
                site->unknown_branches);
        }
        shown++;
    }
    g_list_free(sorted);
}

static void finish(void *userdata)
{
    GString *out = g_string_new("triage: architectural event report\n");
    GList *all_sites, *all_lines, *sorted_lines;
    unsigned int shown = 0;

    for (unsigned int i = 0; i < qemu_plugin_num_vcpus(); i++) {
        qemu_plugin_trace_buffer_flush(buffer, i);
    }
    g_mutex_lock(&lock);
    all_sites = g_hash_table_get_values(sites);
    all_lines = g_hash_table_get_values(lines);
    g_string_append_printf(out,
        "sites=%u lines=%u evicted_sites=%" PRIu64
        " evicted_lines=%" PRIu64 " virtual_without_pid=%" PRIu64 "\n",
        g_hash_table_size(sites), g_hash_table_size(lines),
        evicted_sites, evicted_lines, lost_virtual_identity);
    if (!system_emulation) {
        g_string_append_printf(out,
            "user events: thread_starts=%" PRIu64 " forks=%" PRIu64
            " exec_attempts=%" PRIu64 "\n",
            task_starts, task_forks, task_execs);
    }
    report_sites(out, all_sites, "hot instructions (executions)",
                 compare_insns, 0);
    report_sites(out, all_sites, "hot memory sites (accesses)",
                 compare_memory, 1);
    report_sites(out, all_sites, "atomic sites (memory events)",
                 compare_atomic, 2);
    report_sites(out, all_sites, "mixed conditional branches (minority count)",
                 compare_branch, 3);
    sorted_lines = g_list_sort(g_list_copy(all_lines), compare_atomic_lines);
    g_string_append(out, "\nmulti-vCPU atomic lines (memory events)\n");
    for (GList *it = sorted_lines; it && shown < top; it = it->next) {
        Line *line = it->data;
        char space[48];

        if (line->n_atomic_vcpus < 2 || !line->atomics) {
            break;
        }
        format_line_space(space, sizeof(space), line->key.space);
        g_string_append_printf(out,
            "atomic=%" PRIu64 " fail=%" PRIu64
            " space=%s line=%016" PRIx64
            " atomic_vcpus=%u%s first_pc=%016" PRIx64
            " last_pc=%016" PRIx64 "\n",
            line->atomics, line->failed_atomics, space,
            line->key.number * LINE_SIZE, line->n_atomic_vcpus,
            line->atomic_overflow ? "+" : "", line->first_pc,
            line->last_pc);
        shown++;
    }
    g_list_free(sorted_lines);
    shown = 0;
    sorted_lines = g_list_sort(g_list_copy(all_lines), compare_lines);
    g_string_append(out, "\nshared line candidates (disjoint writer pairs)\n");
    for (GList *it = sorted_lines; it && shown < top; it = it->next) {
        Line *line = it->data;
        unsigned int pairs = disjoint_writer_pairs(line);
        char space[48];
        if (!pairs) {
            break;
        }
        format_line_space(space, sizeof(space), line->key.space);
        g_string_append_printf(out,
            "pairs=%u space=%s line=%016" PRIx64
            " writes=%" PRIu64 " atomic=%" PRIu64 " fail=%" PRIu64
            " writers=%u%s first_pc=%016" PRIx64 " last_pc=%016" PRIx64
            "\n", pairs, space, line->key.number * LINE_SIZE,
            line->writes, line->atomics, line->failed_atomics,
            line->n_writers, line->writer_overflow ? "+" : "",
            line->first_pc, line->last_pc);
        shown++;
    }
    g_string_append(out,
        "Interpretation: disjoint writer footprints suggest possible false "
        "sharing, not measured cache transfers. Multi-vCPU atomic lines "
        "suggest lock or counter contention, not measured waiting time. "
        "Atomic read-modify-write "
        "instructions can produce multiple memory events. Mixed branch "
        "outcomes are not measured mispredictions. No cycle or stall "
        "counts are inferred. Evicted site and line counts are partial.\n");
    qemu_plugin_outs(out->str);
    g_list_free(all_sites);
    g_list_free(all_lines);
    g_list_free(sorted_lines);
    g_string_free(out, true);
    g_mutex_unlock(&lock);
    qemu_plugin_trace_buffer_free(buffer);
    g_queue_clear(&site_lru);
    g_queue_clear(&line_lru);
    g_hash_table_destroy(sites);
    g_hash_table_destroy(lines);
    g_mutex_clear(&lock);
    if (kernel_symbols) {
        for (size_t i = 0; i < kernel_symbols->len; i++) {
            Symbol *symbol = &g_array_index(kernel_symbols, Symbol, i);
            g_free(symbol->name);
        }
        g_array_free(kernel_symbols, true);
    }
    g_free(symbol_path);
}

static bool parse_u64(const char *value, uint64_t *out)
{
    char *end;
    uint64_t number;

    if (!value[0] || value[0] == '-') {
        return false;
    }
    errno = 0;
    number = g_ascii_strtoull(value, &end, 0);
    if (*end || errno == ERANGE) {
        return false;
    }
    *out = number;
    return true;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        uint64_t value;
        char *equals = strchr(argv[i], '=');
        size_t keylen = equals ? equals - argv[i] : 0;

        if (keylen == 7 && !strncmp(argv[i], "symbols", keylen) &&
            equals[1] && !symbol_path) {
            symbol_path = g_strdup(equals + 1);
            continue;
        }
        if (!equals || !parse_u64(equals + 1, &value)) {
            return -1;
        }
        if (keylen == 3 && !strncmp(argv[i], "top", keylen) &&
            value >= 1 && value <= 1000) {
            top = value;
        } else if (keylen == 5 && !strncmp(argv[i], "sites", keylen) &&
                   value >= 1 && value <= 1000000) {
            max_sites = value;
        } else if (keylen == 5 && !strncmp(argv[i], "lines", keylen) &&
                   value >= 1 && value <= 1000000) {
            max_lines = value;
        } else if (keylen == 8 && !strncmp(argv[i], "pc_start", keylen)) {
            pc_start = value;
        } else if (keylen == 6 && !strncmp(argv[i], "pc_end", keylen)) {
            pc_end = value;
        } else {
            return -1;
        }
    }
    if (pc_start > pc_end) {
        return -1;
    }
    if (symbol_path && !load_symbols(symbol_path)) {
        return -1;
    }
    system_emulation = info->system_emulation;
    g_mutex_init(&lock);
    sites = g_hash_table_new_full(pair_hash, pair_equal, NULL, site_free);
    lines = g_hash_table_new_full(pair_hash, pair_equal, NULL, g_free);
    buffer = qemu_plugin_trace_buffer_new(
        sizeof(struct qemu_plugin_trace_record), 256, trace_batch, NULL);
    if (!buffer) {
        return -1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate, NULL);
    qemu_plugin_register_vcpu_branch_cb(id, branch, NULL);
    qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit, NULL);
    if (!system_emulation) {
        qemu_plugin_register_user_task_cb(id, task_event, NULL);
        qemu_plugin_register_user_image_cb(id, image_event, NULL);
    }
    qemu_plugin_register_atexit_cb(id, finish, NULL);
    return 0;
}
