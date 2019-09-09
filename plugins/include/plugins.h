#ifndef PLUGINS_INTERFACE_H
#define PLUGINS_INTERFACE_H

#include <stdbool.h>

/* Plugin interface */

bool plugin_init(const char *args);
bool plugin_needs_before_insn(uint64_t pc, void *cpu);
void plugin_before_insn(uint64_t pc, void *cpu);
void plugin_after_mem(void *cpu, uint64_t v, int s, int w);
void inst_cb(int c, uint32_t el, uint32_t tid, uint64_t v, uint64_t p, uint8_t l,
             const uint8_t *b);
void mem_cb(int c, uint32_t el, uint32_t tid, uint64_t v, uint64_t p, int size, int w);

/* QEMU interface */

void qemulib_log(const char *fmt, ...) /*GCC_FMT_ATTR(1, 2)*/;
uint64_t qemulib_memory_translate(void *cpu, uint64_t addr);
int qemulib_read_memory(void *cpu, uint64_t addr, uint8_t *buf, int len);
int qemulib_read_register(void *cpu, uint8_t *mem_buf, int reg);
uint64_t qemulib_translate_memory(void *cpu, uint64_t addr);
int qemulib_get_cpuid(void *cpu);
uint32_t qemulib_get_tid(void *cpu, uint32_t el);
uint32_t qemulib_get_current_el(void *cpu);

#endif /* PLUGINS_INTERFACE_H */
