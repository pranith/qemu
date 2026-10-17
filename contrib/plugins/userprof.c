/*
 * Local linux-user memory attribution experiment.
 *
 * Example: -plugin libuserprof.so,top=20,events=on,image=libc
 * Reports executed memory sites by image, file offset and guest thread.
 * Counts describe TCG-observed accesses, not host cache misses or cycles.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct Mapping {
    uint64_t id;
    uint64_t pid;
    uint64_t start;
    uint64_t len;
    uint64_t offset;
    uint64_t dev;
    uint64_t ino;
    char *path;
} Mapping;

typedef struct Site {
    uint64_t pid;
    uint64_t pc;
    uint64_t map_id;
    uint64_t image_offset;
    char *image;
    char *symbol;
    uint64_t reads;
    uint64_t writes;
    uint64_t atomics;
    uint64_t failed_cas;
    uint64_t thread_mask;
} Site;

typedef struct Counters {
    uint64_t reads;
    uint64_t writes;
    uint64_t atomics;
    uint64_t failed_cas;
} Counters;

typedef struct ThreadStats {
    uint32_t slot;
    GHashTable *counters; /* Site * -> Counters *; only this thread writes */
} ThreadStats;

static GMutex data_lock;
static GPtrArray *mappings;
static GPtrArray *thread_stats_all;
static GHashTable *sites;
static uint64_t next_map_id = 1;
static uint64_t task_events[QEMU_PLUGIN_USER_PROCESS_EXIT + 1];
static uint64_t mapping_events[QEMU_PLUGIN_USER_REMAP + 1];
static uint32_t next_thread_slot;
static __thread ThreadStats *thread_stats;
static char *image_filter;
static bool verbose_events;
static unsigned int top_n = 20;

static void mapping_free(gpointer ptr)
{
    Mapping *m = ptr;

    g_free(m->path);
    g_free(m);
}

static void site_free(gpointer ptr)
{
    Site *s = ptr;

    g_free(s->image);
    g_free(s->symbol);
    g_free(s);
}

static void thread_stats_free(gpointer ptr)
{
    ThreadStats *stats = ptr;

    g_hash_table_destroy(stats->counters);
    g_free(stats);
}

static ThreadStats *get_thread_stats(void)
{
    if (!thread_stats) {
        ThreadStats *stats = g_new0(ThreadStats, 1);

        stats->slot = __atomic_fetch_add(&next_thread_slot, 1,
                                         __ATOMIC_RELAXED);
        stats->counters = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                 NULL, g_free);
        g_mutex_lock(&data_lock);
        g_ptr_array_add(thread_stats_all, stats);
        g_mutex_unlock(&data_lock);
        thread_stats = stats;
    }
    return thread_stats;
}

static guint site_hash(gconstpointer ptr)
{
    const Site *s = ptr;
    uint64_t n = s->pc ^ (s->map_id * UINT64_C(0x9e3779b97f4a7c15));

    n ^= s->pid + (n << 6) + (n >> 2);
    return (guint)(n ^ (n >> 32));
}

static gboolean site_equal(gconstpointer a, gconstpointer b)
{
    const Site *x = a;
    const Site *y = b;

    return x->pid == y->pid && x->pc == y->pc && x->map_id == y->map_id;
}

static Mapping *mapping_clone(const Mapping *m)
{
    Mapping *copy = g_memdup2(m, sizeof(*m));

    copy->path = g_strdup(m->path);
    return copy;
}

static uint64_t range_end(uint64_t start, uint64_t len)
{
    return len > UINT64_MAX - start ? UINT64_MAX : start + len;
}

/* Keep unaffected left and right fragments when a range is replaced. */
static void mapping_remove_range(uint64_t pid, uint64_t start, uint64_t len)
{
    uint64_t end = range_end(start, len);

    for (guint i = 0; i < mappings->len;) {
        Mapping *m = g_ptr_array_index(mappings, i);
        uint64_t m_end = range_end(m->start, m->len);

        if (m->pid != pid || m_end <= start || end <= m->start) {
            i++;
            continue;
        }
        if (m->start < start && m_end > end) {
            Mapping *right = mapping_clone(m);

            right->offset += end - m->start;
            right->start = end;
            right->len = m_end - end;
            m->len = start - m->start;
            g_ptr_array_add(mappings, right);
            i++;
        } else if (m->start < start) {
            m->len = start - m->start;
            i++;
        } else if (m_end > end) {
            m->offset += end - m->start;
            m->start = end;
            m->len = m_end - end;
            i++;
        } else {
            g_ptr_array_remove_index_fast(mappings, i);
        }
    }
}

static Mapping *mapping_at(uint64_t pid, uint64_t addr)
{
    for (guint i = 0; i < mappings->len; i++) {
        Mapping *m = g_ptr_array_index(mappings, i);

        if (m->pid == pid && addr >= m->start &&
            addr - m->start < m->len) {
            return m;
        }
    }
    return NULL;
}

static void mapping_cb(const struct qemu_plugin_user_mapping_event *event,
                       void *userdata)
{
    uint64_t pid = event->context.pid;
    Mapping *m = NULL;

    g_mutex_lock(&data_lock);
    mapping_events[event->type]++;

    if (event->type == QEMU_PLUGIN_USER_REMAP) {
        Mapping *old = mapping_at(pid, event->old_addr);

        if (old) {
            m = mapping_clone(old);
            m->offset += event->old_addr - old->start;
        }
        if (event->old_len) {
            mapping_remove_range(pid, event->old_addr, event->old_len);
        }
    }

    if (event->type == QEMU_PLUGIN_USER_MAP ||
        event->type == QEMU_PLUGIN_USER_UNMAP ||
        event->type == QEMU_PLUGIN_USER_REMAP) {
        mapping_remove_range(pid, event->addr, event->len);
    }

    if (event->type == QEMU_PLUGIN_USER_MAP) {
        m = g_new0(Mapping, 1);
        m->offset = event->offset;
        m->dev = event->file_dev;
        m->ino = event->file_ino;
        m->path = g_strdup(event->path);
    }
    if (m) {
        m->id = next_map_id++;
        m->pid = pid;
        m->start = event->addr;
        m->len = event->len;
        g_ptr_array_add(mappings, m);
    }
    g_mutex_unlock(&data_lock);

    if (verbose_events) {
        g_autofree char *line = g_strdup_printf(
            "userprof map type=%u pid=%" PRIu64 " addr=%016" PRIx64
            " len=%" PRIu64 " old=%016" PRIx64 " path=%s\n",
            event->type, pid, event->addr, event->len, event->old_addr,
            event->path ? event->path : "-");
        qemu_plugin_outs(line);
    }
}

static void task_cb(const struct qemu_plugin_user_task_event *event,
                    void *userdata)
{
    if (event->type == QEMU_PLUGIN_USER_FORK_CHILD) {
        /* The child has a private copy of the parent's plugin state. */
        g_mutex_init(&data_lock);
        g_mutex_lock(&data_lock);
        for (guint i = 0; i < mappings->len; i++) {
            Mapping *m = g_ptr_array_index(mappings, i);

            m->pid = event->context.pid;
        }
        GHashTableIter iter;
        GHashTable *child_sites = g_hash_table_new_full(site_hash, site_equal,
                                                         NULL, site_free);
        gpointer value;

        g_hash_table_iter_init(&iter, sites);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            Site *s = value;

            g_hash_table_iter_steal(&iter);
            s->reads = s->writes = s->atomics = 0;
            s->failed_cas = s->thread_mask = 0;
            s->pid = event->context.pid;
            g_hash_table_insert(child_sites, s, s);
        }
        g_hash_table_destroy(sites);
        sites = child_sites;
        memset(task_events, 0, sizeof(task_events));
        memset(mapping_events, 0, sizeof(mapping_events));
        g_ptr_array_set_size(thread_stats_all, 0);
        thread_stats = NULL;
        next_thread_slot = 0;
        g_mutex_unlock(&data_lock);
        get_thread_stats();
    } else if (event->type == QEMU_PLUGIN_USER_THREAD_START) {
        get_thread_stats();
    }

    __atomic_fetch_add(&task_events[event->type], 1, __ATOMIC_RELAXED);
    if (verbose_events) {
        g_autofree char *line = g_strdup_printf(
            "userprof task type=%u pid=%" PRIu64 " tid=%" PRIu64
            " related=%" PRIu64 " path=%s\n",
            event->type, event->context.pid, event->context.tid,
            event->related_pid, event->path ? event->path : "-");
        qemu_plugin_outs(line);
    }
}

static void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                   uint64_t addr, void *userdata)
{
    Site *s = userdata;
    struct qemu_plugin_mem_access_info access;
    ThreadStats *stats = get_thread_stats();
    Counters *c = g_hash_table_lookup(stats->counters, s);

    if (!c) {
        c = g_new0(Counters, 1);
        g_hash_table_insert(stats->counters, s, c);
    }

    qemu_plugin_mem_get_access_info(info, addr, &access);
    if (access.is_store) {
        c->writes++;
    } else {
        c->reads++;
    }
    if (access.is_atomic) {
        c->atomics++;
        if (!access.atomic_success) {
            c->failed_cas++;
        }
    }
}

static void tb_cb(struct qemu_plugin_tb *tb, void *userdata)
{
    struct qemu_plugin_exec_context context;
    uint64_t pid = qemu_plugin_get_exec_context(&context,
                                                 sizeof(context)) ?
                   context.pid : 0;

    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        Site key = { .pid = pid, .pc = pc };
        Site *s;

        g_mutex_lock(&data_lock);
        Mapping *m = mapping_at(pid, pc);

        key.map_id = m ? m->id : 0;
        if (image_filter && (!m || !m->path ||
                             !strstr(m->path, image_filter))) {
            g_mutex_unlock(&data_lock);
            continue;
        }
        s = g_hash_table_lookup(sites, &key);
        if (!s) {
            s = g_new0(Site, 1);
            s->pid = pid;
            s->pc = pc;
            s->map_id = key.map_id;
            s->image = g_strdup(m && m->path ? m->path : "[anonymous]");
            s->image_offset = m ? m->offset + pc - m->start : 0;
            s->symbol = g_strdup(qemu_plugin_insn_symbol(insn));
            g_hash_table_insert(sites, s, s);
        }
        g_mutex_unlock(&data_lock);
        qemu_plugin_register_vcpu_mem_cb(insn, mem_cb,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, s);
    }
}

static gint site_compare(gconstpointer a, gconstpointer b)
{
    const Site *x = a;
    const Site *y = b;
    uint64_t xc = x->reads + x->writes;
    uint64_t yc = y->reads + y->writes;

    return xc < yc ? 1 : xc > yc ? -1 : 0;
}

static void finish_cb(void *userdata)
{
    g_autoptr(GString) out = g_string_new("userprof: TCG memory accesses\n");
    GList *sorted;
    unsigned int shown = 0;

    for (guint i = 0; i < thread_stats_all->len; i++) {
        ThreadStats *stats = g_ptr_array_index(thread_stats_all, i);
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, stats->counters);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            Site *s = key;
            Counters *c = value;

            s->reads += c->reads;
            s->writes += c->writes;
            s->atomics += c->atomics;
            s->failed_cas += c->failed_cas;
            if (stats->slot < 64) {
                s->thread_mask |= UINT64_C(1) << stats->slot;
            }
        }
    }
    sorted = g_hash_table_get_values(sites);
    sorted = g_list_sort(sorted, site_compare);
    g_string_append_printf(out,
        "task events: thread_start=%" PRIu64 " thread_exit=%" PRIu64
        " fork_parent=%" PRIu64 " fork_child=%" PRIu64
        " exec_attempt=%" PRIu64 " process_exit=%" PRIu64 "\n",
        task_events[QEMU_PLUGIN_USER_THREAD_START],
        task_events[QEMU_PLUGIN_USER_THREAD_EXIT],
        task_events[QEMU_PLUGIN_USER_FORK_PARENT],
        task_events[QEMU_PLUGIN_USER_FORK_CHILD],
        task_events[QEMU_PLUGIN_USER_EXEC_ATTEMPT],
        task_events[QEMU_PLUGIN_USER_PROCESS_EXIT]);
    g_string_append_printf(out,
        "mapping events: map=%" PRIu64 " unmap=%" PRIu64
        " protect=%" PRIu64 " remap=%" PRIu64 "\n",
        mapping_events[QEMU_PLUGIN_USER_MAP],
        mapping_events[QEMU_PLUGIN_USER_UNMAP],
        mapping_events[QEMU_PLUGIN_USER_PROTECT],
        mapping_events[QEMU_PLUGIN_USER_REMAP]);
    g_string_append(out,
        "       PC             offset    reads   writes  atomic failed threads image\n");
    for (GList *it = sorted; it && shown < top_n; it = it->next) {
        Site *s = it->data;
        uint64_t reads = s->reads;
        uint64_t writes = s->writes;

        if (!reads && !writes) {
            continue;
        }
        g_string_append_printf(out,
            "%016" PRIx64 " %10" PRIx64 " %8" PRIu64 " %8" PRIu64
            " %7" PRIu64 " %6" PRIu64 " %7d %s%s%s\n",
            s->pc, s->image_offset, reads, writes,
            s->atomics, s->failed_cas,
            __builtin_popcountll(s->thread_mask),
            s->image, s->symbol ? " " : "", s->symbol ? s->symbol : "");
        shown++;
    }
    qemu_plugin_outs(out->str);
    g_list_free(sorted);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (info->system_emulation) {
        fprintf(stderr, "userprof requires linux-user emulation\n");
        return -1;
    }
    for (int i = 0; i < argc; i++) {
        if (g_str_has_prefix(argv[i], "top=")) {
            top_n = g_ascii_strtoull(argv[i] + 4, NULL, 10);
        } else if (g_str_has_prefix(argv[i], "image=")) {
            image_filter = g_strdup(argv[i] + 6);
        } else if (!strcmp(argv[i], "events=on")) {
            verbose_events = true;
        } else {
            fprintf(stderr, "userprof: unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    g_mutex_init(&data_lock);
    mappings = g_ptr_array_new_with_free_func(mapping_free);
    thread_stats_all = g_ptr_array_new_with_free_func(thread_stats_free);
    sites = g_hash_table_new_full(site_hash, site_equal, NULL, site_free);
    qemu_plugin_register_user_task_cb(id, task_cb, NULL);
    qemu_plugin_register_user_mapping_cb(id, mapping_cb, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_cb, NULL);
    qemu_plugin_register_atexit_cb(id, finish_cb, NULL);
    return 0;
}
