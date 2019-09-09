#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __SIMPOINT_TRACE_H__

void simpoints_trace_init(const char *samples_file);

void simpoints_inst_cb(uint64_t pc, uint32_t el, const uint8_t *inst_buffer);

void simpoints_mem_cb(uint64_t virt_addr, uint64_t phys_addr);

#define __SIMPOINT_TRACE_H__


#endif //__SIMPOINT_TRACE_H__
