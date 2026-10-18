/* Local AI-assisted plugin API experiment; not for upstream submission. */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "plugins/qemu-plugin.h"
#include "plugin.h"
#ifdef CONFIG_LIBDW
#include <elfutils/libdwfl.h>
#endif

typedef struct {
    PluginImageSnapshot image;
    GMappedFile *file;
    const uint8_t *data;
    size_t size;
    bool big_endian;
    bool elf64;
    uint64_t shoff;
    uint16_t shentsize, shnum, shstrndx;
} PluginElfView;

typedef struct {
    uint32_t name, type, link;
    uint64_t flags, addr, offset, size, entsize;
} PluginElfSection;

static bool elf_has(const PluginElfView *view, uint64_t offset, uint64_t size)
{
    return offset <= view->size && size <= view->size - offset;
}

static uint64_t elf_uint(const PluginElfView *view, uint64_t offset,
                         unsigned int width)
{
    uint64_t value = 0;

    if (view->big_endian) {
        for (unsigned int i = 0; i < width; i++) {
            value = (value << 8) | view->data[offset + i];
        }
    } else {
        for (unsigned int i = 0; i < width; i++) {
            value |= (uint64_t)view->data[offset + i] << (i * 8);
        }
    }
    return value;
}

static bool elf_section(const PluginElfView *view, unsigned int index,
                        PluginElfSection *out)
{
    uint64_t offset;

    if (index >= view->shnum) {
        return false;
    }
    offset = view->shoff + (uint64_t)index * view->shentsize;
    if (!elf_has(view, offset, view->elf64 ? 64 : 40)) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->name = elf_uint(view, offset, 4);
    out->type = elf_uint(view, offset + 4, 4);
    if (view->elf64) {
        out->flags = elf_uint(view, offset + 8, 8);
        out->addr = elf_uint(view, offset + 16, 8);
        out->offset = elf_uint(view, offset + 24, 8);
        out->size = elf_uint(view, offset + 32, 8);
        out->link = elf_uint(view, offset + 40, 4);
        out->entsize = elf_uint(view, offset + 56, 8);
    } else {
        out->flags = elf_uint(view, offset + 8, 4);
        out->addr = elf_uint(view, offset + 12, 4);
        out->offset = elf_uint(view, offset + 16, 4);
        out->size = elf_uint(view, offset + 20, 4);
        out->link = elf_uint(view, offset + 24, 4);
        out->entsize = elf_uint(view, offset + 36, 4);
    }
    return true;
}

static bool elf_string(const PluginElfView *view,
                       const PluginElfSection *strings, uint32_t offset,
                       const char **out)
{
    const char *start;

    if (offset >= strings->size ||
        !elf_has(view, strings->offset, strings->size)) {
        return false;
    }
    start = (const char *)view->data + strings->offset + offset;
    if (!memchr(start, 0, strings->size - offset)) {
        return false;
    }
    *out = start;
    return true;
}

static bool elf_guest_address(const PluginElfView *view,
                              uint64_t file_offset, uint64_t *addr)
{
    for (guint i = 0; i < view->image.maps->len; i++) {
        PluginImageMap *map = &g_array_index(view->image.maps,
                                              PluginImageMap, i);
        if (file_offset >= map->offset &&
            file_offset - map->offset < map->len &&
            file_offset - map->offset <= UINT64_MAX - map->start) {
            *addr = map->start + file_offset - map->offset;
            return true;
        }
    }
    return false;
}

static bool elf_open_image(uint64_t image_id, PluginElfView *view)
{
    memset(view, 0, sizeof(*view));
    if (!plugin_user_image_snapshot(image_id, &view->image)) {
        return false;
    }
    view->file = g_mapped_file_new(view->image.path, false, NULL);
    if (!view->file) {
        return false;
    }
    view->data = (const uint8_t *)g_mapped_file_get_contents(view->file);
    view->size = g_mapped_file_get_length(view->file);
    if (!elf_has(view, 0, 16) ||
        memcmp(view->data, "\177ELF", 4) != 0 ||
        (view->data[4] != 1 && view->data[4] != 2) ||
        (view->data[5] != 1 && view->data[5] != 2)) {
        return false;
    }
    view->elf64 = view->data[4] == 2;
    view->big_endian = view->data[5] == 2;
    if (!elf_has(view, 0, view->elf64 ? 64 : 52)) {
        return false;
    }
    view->shoff = elf_uint(view, view->elf64 ? 40 : 32,
                            view->elf64 ? 8 : 4);
    view->shentsize = elf_uint(view, view->elf64 ? 58 : 46, 2);
    view->shnum = elf_uint(view, view->elf64 ? 60 : 48, 2);
    view->shstrndx = elf_uint(view, view->elf64 ? 62 : 50, 2);
    return view->shnum && view->shstrndx < view->shnum &&
           view->shentsize >= (view->elf64 ? 64 : 40) &&
           elf_has(view, view->shoff,
                   (uint64_t)view->shentsize * view->shnum);
}

static void elf_close_image(PluginElfView *view)
{
    if (view->file) {
        g_mapped_file_unref(view->file);
    }
    plugin_user_image_snapshot_free(&view->image);
}

bool qemu_plugin_user_image_sections(uint64_t image_id,
    qemu_plugin_user_image_section_cb_t cb, void *userdata)
{
    PluginElfView view;
    PluginElfSection strings, section;
    bool valid;

    if (!cb) {
        return false;
    }
    valid = elf_open_image(image_id, &view);
    if (!valid || !elf_section(&view, view.shstrndx, &strings)) {
        elf_close_image(&view);
        return false;
    }
    for (unsigned int i = 0; i < view.shnum; i++) {
        const char *name;

        if (!elf_section(&view, i, &section) ||
            !elf_string(&view, &strings, section.name, &name)) {
            continue;
        }
        struct qemu_plugin_user_image_section event = {
            .name = name,
            .file_offset = section.offset,
            .size = section.size,
            .flags = section.flags,
        };
        if (section.flags & 2) { /* SHF_ALLOC */
            event.has_guest_addr = elf_guest_address(
                &view, section.offset, &event.guest_addr);
        }
        cb(&event, userdata);
    }
    elf_close_image(&view);
    return true;
}

bool qemu_plugin_user_image_symbols(uint64_t image_id,
    qemu_plugin_user_image_symbol_cb_t cb, void *userdata)
{
    PluginElfView view;
    PluginElfSection table, strings, section;
    bool valid;

    if (!cb) {
        return false;
    }
    valid = elf_open_image(image_id, &view);
    if (!valid) {
        elf_close_image(&view);
        return false;
    }
    for (unsigned int i = 0; i < view.shnum; i++) {
        if (!elf_section(&view, i, &table) ||
            (table.type != 2 && table.type != 11) ||
            table.link >= view.shnum ||
            table.entsize < (view.elf64 ? 24 : 16) ||
            !elf_has(&view, table.offset, table.size) ||
            !elf_section(&view, table.link, &strings) ||
            !elf_has(&view, strings.offset, strings.size)) {
            continue;
        }
        for (uint64_t j = 0; j < table.size / table.entsize; j++) {
            uint64_t off = table.offset + j * table.entsize;
            uint32_t name_index = elf_uint(&view, off, 4);
            uint8_t info = view.data[off + (view.elf64 ? 4 : 12)];
            uint16_t section_index = elf_uint(&view,
                                               off + (view.elf64 ? 6 : 14), 2);
            const char *name;

            if ((info & 15) != 2 || /* STT_FUNC */
                !elf_string(&view, &strings, name_index, &name)) {
                continue;
            }
            uint64_t value = elf_uint(&view, off + (view.elf64 ? 8 : 4),
                                      view.elf64 ? 8 : 4);
            struct qemu_plugin_user_image_symbol event = {
                .name = name,
                .size = elf_uint(&view, off + (view.elf64 ? 16 : 8),
                                 view.elf64 ? 8 : 4),
            };

            if (elf_section(&view, section_index, &section) &&
                value >= section.addr &&
                value - section.addr <= UINT64_MAX - section.offset) {
                event.has_guest_addr = elf_guest_address(
                    &view, section.offset + value - section.addr,
                    &event.guest_addr);
            }
            cb(&event, userdata);
        }
    }
    elf_close_image(&view);
    return true;
}

bool qemu_plugin_user_image_source(uint64_t image_id, uint64_t guest_addr,
                                   char **path, uint32_t *line,
                                   uint32_t *column)
{
#ifdef CONFIG_LIBDW
    static const Dwfl_Callbacks callbacks = {
        .find_debuginfo = dwfl_standard_find_debuginfo,
    };
    PluginElfView view;
    PluginElfSection section;
    Dwfl *dwfl = NULL;
    Dwfl_Module *module;
    Dwfl_Line *source;
    const char *name;
    uint64_t file_offset = 0, elf_addr = 0;
    int source_line = 0, source_column = 0;
    bool found = false;

    if (!path || !line || !column) {
        return false;
    }
    if (!elf_open_image(image_id, &view)) {
        elf_close_image(&view);
        return false;
    }
    *path = NULL;
    *line = *column = 0;
    for (guint i = 0; i < view.image.maps->len; i++) {
        PluginImageMap *map = &g_array_index(view.image.maps,
                                              PluginImageMap, i);
        if (guest_addr >= map->start &&
            guest_addr - map->start < map->len &&
            guest_addr - map->start <= UINT64_MAX - map->offset) {
            file_offset = map->offset + guest_addr - map->start;
            found = true;
            break;
        }
    }
    if (!found) {
        goto out;
    }
    found = false;
    for (unsigned int i = 0; i < view.shnum; i++) {
        if (elf_section(&view, i, &section) && (section.flags & 2) &&
            file_offset >= section.offset &&
            file_offset - section.offset < section.size &&
            file_offset - section.offset <= UINT64_MAX - section.addr) {
            elf_addr = section.addr + file_offset - section.offset;
            break;
        }
    }
    if (!elf_addr) {
        goto out;
    }
    dwfl = dwfl_begin(&callbacks);
    if (!dwfl) {
        goto out;
    }
    dwfl_report_begin(dwfl);
    module = dwfl_report_offline(dwfl, view.image.path,
                                 view.image.path, -1);
    if (!module || dwfl_report_end(dwfl, NULL, NULL)) {
        goto out;
    }
    source = dwfl_module_getsrc(module, elf_addr);
    if (!source) {
        goto out;
    }
    name = dwfl_lineinfo(source, NULL, &source_line, &source_column,
                         NULL, NULL);
    if (!name || source_line <= 0) {
        goto out;
    }
    *path = g_strdup(name);
    *line = source_line;
    *column = MAX(source_column, 0);
    found = true;
out:
    if (dwfl) {
        dwfl_end(dwfl);
    }
    elf_close_image(&view);
    return found;
#else
    return false;
#endif
}
