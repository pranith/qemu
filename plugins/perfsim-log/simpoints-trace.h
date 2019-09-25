#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
//#include "plugins.h"

#ifndef __SIMPOINT_TRACE_H__

inline bool simpoints_complete();
inline bool simpoints_before_mem_cb();
inline bool simpoints_before_inst_cb(uint32_t el);

void simpoints_trace_init(const char *samples_file, uint64_t progress_log_interval);

void simpoints_inst_cb(uint64_t pc, uint32_t el, const uint8_t *inst_buffer);

void simpoints_mem_cb(uint64_t virt_addr, uint64_t phys_addr);

#define __SIMPOINT_TRACE_H__


#endif //__SIMPOINT_TRACE_H__
