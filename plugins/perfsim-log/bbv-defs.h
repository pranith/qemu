#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "plugins.h"

#define MAX_BB_PER_INTERVAL 200000
#ifndef _BBV_DEFS_H_
#define _BBV_DEFS_H_

#define CHECK_BBV_IDX(bbv_idx) if((bbv_idx >= live_bb_count) || (bbv_idx < 0)) {\
    printf("invalid index: %d\n",bbv_idx); \
    assert(0);\
}
#define CHECK_BBV_IDX_LIMIT(bbv_idx) if(bbv_idx >= MAX_BB_PER_INTERVAL) {\
    printf("exceeded limit of %d\n",MAX_BB_PER_INTERVAL);\
    assert(0);\
}

#define BBV_GET_LAST(__index__)  (basic_block_vector[__index__].bbentry_pc + (basic_block_vector[__index__].size - 1) * 0x4)

#define BBV_ERR(cond, ...) \
    if( !(cond) ) {\
        printf( "BBVERR: " __VA_ARGS__); \
        assert(0); \
    }

//#define BBV_DEBUG 0

#ifdef BBV_DEBUG
#define DFPRINTF(dfile, ...) fprintf(dfile, __VA_ARGS__)
#else
#define DFPRINTF(dfile, ...)
#endif

enum termination_condition{
    INIT_VALUE=0,
    MAX_INSNS_REACHED,
    PAGE_BOUNDARY,
    JMP_REACHED,
    OTHER
};

struct BB_Entry {
    uint64_t bbentry_pc; //entry into the basic block
    uint64_t bbexit_pc; //exit out the basic block
    uint32_t  size; //Size in instructions
    uint32_t  freq; //Freq of execution
    enum termination_condition term_cond; //condition for termination
};

static struct BB_Entry basic_block_vector[MAX_BB_PER_INTERVAL];
static unsigned long int live_bb_count = 0;
static uint64_t bbv_interval_start_user_pc_count = 0;
static uint64_t bbv_interval_count = 0;

void bbv_commit(uint64_t commit_entry_pc, uint64_t commit_exit_pc, uint64_t term_cond, uint64_t size, FILE* bb_debugfile);
void bbv_set_size(int bbv_idx, int size,unsigned long int term_cond);
void bbv_incr_freq(uint64_t bbentry_pc, uint32_t bbv_index);
int bbv_find_array_entry(uint64_t bbentry_pc);
int bbv_find_endpoints(uint64_t start_pc, uint64_t end_pc, uint64_t *start_id, uint64_t *end_id);
void bbv_dump(FILE *bb_debugfile, FILE *bb_intervalfile, uint64_t interval_user_inst_count);
unsigned int bbv_create_array_entry(uint64_t bbentry_pc, FILE* bb_debugfile);
void bbv_init();

#endif  /* _BBV_H_ */
