#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "plugins.h"
#include "bbv-defs.h"
#include "simpoints-trace.h"

#define PLUGIN_OPEN_FILE(_file, _filename) \
    assert( _file == NULL && "Opening an already open file" ); \
    _file = fopen(_filename, "w"); \
    if(_file == NULL){ \
        printf("error opening file %s for writing bb debug logs\n", _filename); \
        assert(0); \
    }

#define PLUGIN_CLOSE_FILE(_file) \
    /*assert(_file == NULL && "Closing an already open file is not yet supported");*/\
    if(_file){ \
        fclose(_file); \
        _file = NULL; \
    }

/* List of env variables supported by this plugin
 * -----------------------------------------------
 *
 * BBV_INTERVAL
 * TRACELENGTH
 * STARTPC
 * TRACK_TID
 * SIMPOINT_SAMPLE_FILE
 * BBV_DEBUG_FILE
 * BBV_LOG_FILE
 * BBV_INTERVAL_FILE
 * PLUGIN_MODE
*/

bool plugin_update_env();
bool plugin_is_branch(uint32_t insn, uint64_t *term_cond);

enum{
    PLUGIN_MODE_BBV_GEN = 0,
    PLUGIN_MODE_TRACING
} plugin_mode_e;

char *DEFAULT_SIMPOINT_SAMPLEFILE = "trace-s0.txt";
char *DEFAULT_BBV_LOGFILE = "bbv_log.txt";
char *DEFAULT_BBV_DEBUGFILE = "bbv_debug.txt";
char *DEFAULT_BBV_INTERVALFILE = "bbv_interval.txt";

static uint64_t MAX_TRACE_LENGTH = 1000000000ull;

static uint64_t trace_length = 0ull;

static uint64_t inst_count = 0ull;
static uint64_t interval_inst_count = 0ull;
static uint8_t start_seen = 0;
static uint64_t startpc = 0;
static bool track_encoding = false;
static uint64_t startencoding = 0;

uint32_t plugin_mode = PLUGIN_MODE_BBV_GEN;

bool track_tid = true;

uint32_t tracked_tid = -1;
uint64_t bb_start_pc = -1;
uint64_t bb_prev_pc = -1;
uint64_t prev_insn = -1;
uint64_t bb_insns = 0ull;
uint64_t bbv_interval = 10000000ull;

FILE *bb_log_file = NULL;
FILE *bb_debug_file = NULL;
FILE *bb_interval_file = NULL;

extern bool enable_instrumentation;
bool instrumentation_flag = true;

// A copy of function from include/qemu/bitops.h
inline uint32_t plugin_extract32(uint32_t value, int start, int length){
    //assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

bool plugin_init(const char *args){
    return true;//plugin_update_env();
}

bool plugin_needs_before_insn(uint64_t pc, void *cpu){
    if (enable_instrumentation) {
        if( instrumentation_flag ){
            instrumentation_flag = false;
            plugin_update_env();
        }
        return true;
    }

    if( !instrumentation_flag ){
        // If in BBV Gen mode, write whatever is left
        if( plugin_mode == PLUGIN_MODE_BBV_GEN ){
            bbv_commit(bb_start_pc, bb_prev_pc, OTHER, bb_insns, bb_debug_file);
            bbv_dump(bb_log_file, bb_interval_file, interval_inst_count);
            fclose(bb_log_file);
            fclose(bb_interval_file);
            fclose(bb_debug_file);
            bb_log_file = NULL;
            bb_interval_file = NULL;
            bb_debug_file = NULL;
        }
        instrumentation_flag = true;
    }
    return false;
}

void plugin_before_insn(uint64_t pc, void *cpu){
    static uint64_t last_pc = 0;
    uint8_t inst_buffer[4];
    uint32_t el = qemulib_get_current_el(cpu);
    uint32_t tid = qemulib_get_tid(cpu, 0);

    if (!start_seen && (pc == startpc)) {
        qemulib_read_memory(cpu, pc, inst_buffer, sizeof(uint32_t));
        uint32_t insn = (inst_buffer[3] << 24) | (inst_buffer[2] << 16) | (inst_buffer[1] << 8) | inst_buffer[0];
        if(!track_encoding || (track_encoding && insn == startencoding)){
            printf("Encoding: %#lx, track_encoding: %d\n", startencoding, track_encoding);
            if(track_tid){
                tracked_tid = tid;
                printf("Starting PC seen at EL%d: %#lx with TID: %ld\n", el, pc, tracked_tid);
            } else{
                printf("Starting PC seen at EL%d: %#lx\n", el, pc);
            }
            inst_count = 0;
            start_seen = 1;
        }
    }

    if (!start_seen) return;
    bool log_inst = (!track_tid || (track_tid && tracked_tid == tid));
    if( !log_inst ) return;

    // Filtering out PC duplicates which maybe caused due to page faults, etc.
    if( el == 0 ) {
        if( last_pc == pc ) return;
        last_pc = pc;
        inst_count++;
    }

    if( plugin_mode == PLUGIN_MODE_TRACING ){ 
        if(!simpoints_before_inst_cb(el) || simpoints_complete()) return;
        qemulib_read_memory(cpu, pc, inst_buffer, sizeof(uint32_t));
    }

    inst_cb(/*qemulib_get_cpuid(cpu)*/0, el, tid, pc, /*qemulib_translate_memory(cpu, pc)*/0,
            sizeof(uint32_t), inst_buffer);
}

void plugin_after_mem(void *cpu, uint64_t v, int size, int type){
    if( plugin_mode != PLUGIN_MODE_TRACING ) return;

    if (!start_seen) return;
    uint32_t el = 0;//qemulib_get_current_el(cpu); // setting to 0 as its don't care
    uint32_t tid = qemulib_get_tid(cpu, el);

    bool log_inst = (!track_tid || (track_tid && tracked_tid == tid));
    if( !log_inst ) return;

    if( !simpoints_before_mem_cb() || simpoints_complete() ) return;
    mem_cb(/*qemulib_get_cpuid(cpu)*/0, el, tid, v,
            qemulib_translate_memory(cpu, v), size, type);
}

void inst_cb(int cpu_id, uint32_t el, uint32_t tid, uint64_t pc_va, uint64_t pc_pa, uint8_t insn_len, const uint8_t *insn_buff){
    // TODO: Opportunity for optimization - we don't need all 32 bits to decode; can probably
    // work with insn_buff[3]?
    uint32_t insn;// = (insn_buff[3] << 24) | (insn_buff[2] << 16) | (insn_buff[1] << 8) | insn_buff[0];

    switch( plugin_mode ){
        case PLUGIN_MODE_BBV_GEN: {
                                      // Create bbv's only in EL0 mode
                                      if( el != 0 ) return;

                                      uint64_t term_cond = OTHER;
                                      if( bb_start_pc == -1 ) {
                                          bb_start_pc = pc_va;
                                      }

                                      if( (bb_prev_pc != -1) && (/*plugin_is_branch(prev_insn, &term_cond) ||*/ (pc_va != (bb_prev_pc + 0x4))) ){
                                          bbv_commit(bb_start_pc, bb_prev_pc, term_cond, bb_insns, bb_debug_file);

                                          // On reaching a term condition, reset the tracked bbv
                                          bb_insns = 0;
                                          bb_start_pc = pc_va;
                                          term_cond = OTHER;

                                          // A "simPoint" can have more than bbv_interval instructions if the last
                                          // commit spills over the boundary

                                          // Check if sufficient instructions are reached to make a "simPoint"
                                          if( interval_inst_count >= bbv_interval ){
                                              bbv_dump(bb_log_file, bb_interval_file, interval_inst_count);
                                              interval_inst_count = 0;
                                          }
                                      }

                                      //// Hard-limiting the simpoint at the trace_length boundary; 
                                      //// might miss capturing the last bbv
                                      //if( inst_count > trace_length ){
                                      //    bbv_dump(bb_log_file, bb_interval_file, interval_inst_count);
                                      //    fclose(bb_log_file);
                                      //    fclose(bb_interval_file);
                                      //    fclose(bb_debug_file);
                                      //    bb_log_file = NULL;
                                      //    bb_interval_file = NULL;
                                      //    bb_debug_file = NULL;
                                      //}
                                      bb_insns++;
                                      interval_inst_count++;
                                      bb_prev_pc = pc_va;
                                      prev_insn = insn;
                                  } 
                                  break;
        case PLUGIN_MODE_TRACING:
                                  {
                                      simpoints_inst_cb(pc_va, el, insn_buff);
                                      break;
                                  }
        default:
                                  assert(0 && "Illegal plugin mode detected");
                                  break;
    }
}

void mem_cb(int cpu_id, uint32_t el, uint32_t tid, uint64_t va, uint64_t pa, int size, int type){
    simpoints_mem_cb(va, pa);
}

inline char *plugin_helper_str_default( char *input_str, char *default_str ){
    return (input_str == NULL) ? default_str : input_str;
}

bool plugin_update_env(){
    bbv_interval = atoll( plugin_helper_str_default( getenv("BBV_INTERVAL"), "10000000" ) );
    
    assert(bbv_interval > 0);

    const char *trace_length_str = getenv("TRACELENGTH");
    if (trace_length_str == NULL) {
        trace_length = MAX_TRACE_LENGTH;
    } else {
        trace_length = atoll(trace_length_str);
    }
    assert(trace_length > bbv_interval);

    const char *startpc_str = plugin_helper_str_default( getenv("STARTPC"), "0" );
    startpc = strtol(startpc_str, NULL, 16);
    start_seen = (startpc == 0);

    const char *startencoding_str = plugin_helper_str_default( getenv("STARTPC_ENCODING"), "0" );
    startencoding = strtol(startencoding_str, NULL, 16);
    track_encoding = (startencoding != 0);

    printf("Updating state from env vars: %d; startpc = 0x%016x; startpcencoding = 0x%016x; start_seen = %d\n", inst_count, startpc, startencoding, start_seen);


    track_tid = atoi( plugin_helper_str_default( getenv("TRACK_TID"), "1" ) );
    if( track_tid && start_seen ){
        printf("Disabling TID tracking as startpc is not provided\n");
        track_tid = false;
    }

    assert( !(start_seen && track_tid) && "Illegal config: track_tid is enabled while no startpc passed" );

    if( start_seen ){
        printf("Defaulting to start_seen as no startpc was specified\n");
    }

    const char *simpt_samples = plugin_helper_str_default( getenv("SIMPOINT_SAMPLE_FILE"), DEFAULT_SIMPOINT_SAMPLEFILE );

    plugin_mode = atoi( plugin_helper_str_default( getenv("PLUGIN_MODE"), "0") );

    // Reset the bbv vars
    bb_start_pc = -1;
    bb_prev_pc = -1;
    prev_insn = -1;
    bb_insns = 0;
    interval_inst_count = 0ull;
    tracked_tid = -1;

    inst_count = 0;

    // Check the mode; if tracing, call it's init
    switch( plugin_mode ){
        case PLUGIN_MODE_TRACING:
            {
                printf("Pluin mode: Tracing\n");
                simpoints_trace_init(simpt_samples, bbv_interval);
                break;
            }
        case PLUGIN_MODE_BBV_GEN:
            {
                const char *bbv_dfile = plugin_helper_str_default( getenv("BBV_DEBUG_FILE"), DEFAULT_BBV_DEBUGFILE );
                const char *bbv_lfile = plugin_helper_str_default( getenv("BBV_LOG_FILE"), DEFAULT_BBV_LOGFILE );
                const char *bbv_ifile = plugin_helper_str_default( getenv("BBV_INTERVAL_FILE"), DEFAULT_BBV_INTERVALFILE );

                PLUGIN_OPEN_FILE(bb_log_file, bbv_lfile);
                PLUGIN_OPEN_FILE(bb_debug_file, bbv_dfile);
                PLUGIN_OPEN_FILE(bb_interval_file, bbv_ifile);

                printf("Pluin mode: BBV Gen\n");
                bbv_init();
            }
            break;
        default:
            assert(0 && "Illegal plugin mode");
            break;
    }

    return true;
}

bool plugin_is_branch(uint32_t insn, uint64_t *term_cond){
    switch(plugin_extract32(insn, 25, 4)){
        case 0xa: case 0xb: /* Branch, exception generation and system insns */
            *term_cond = JMP_REACHED;
            return true;
            break;
    }
    return false;
}
