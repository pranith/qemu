#include "simpoints-trace.h"
#include<assert.h>

#define MAX_BUFF 4096
#define MAX_SIMPOINTS 256
#define SAMPLES_FILE_EXT ".samples"

enum modes { skip=0, trace=1 };
static enum modes mode = skip;

static uint64_t skip_counts[MAX_SIMPOINTS];
static uint64_t trace_counts[MAX_SIMPOINTS];
static uint64_t curr_simpoint = 0;
static uint64_t num_simpoints = 0;
static uint64_t curr_skip_count = 0;
static uint64_t curr_trace_count = 0;
static FILE *curr_tracefile = NULL;
static char base_tracename[MAX_BUFF];


void update_simpoints_tracing_state()
{
    char tracefile_name[MAX_BUFF];
    char tracefile_ext[10];

    if (mode == skip) {
        if (curr_skip_count == skip_counts[curr_simpoint]) { 
            //Switch to tracing mode
            //Trace file name consists of base name (fully-qualified name of samples 
            //file with .samples extension removed), and an extension of -s<sample>.txt
            snprintf(tracefile_name, strlen(base_tracename)+1, base_tracename);
            snprintf(tracefile_ext, 12, "-s%d.txt", curr_simpoint);
            strncat(tracefile_name, tracefile_ext, strlen(tracefile_ext));
            curr_tracefile = fopen(tracefile_name, "w"); //Open next trace file
            assert( curr_tracefile != NULL );

            //Set to trace mode and reset skipped instruction counter
            mode = trace;
            curr_skip_count =  0;
        }
        return;
    }
    if (mode == trace) {
        if (curr_trace_count == trace_counts[curr_simpoint]) { //Switch to skip mode
            fclose(curr_tracefile); //Close current trace file
            curr_tracefile = NULL;
            curr_simpoint++; //Advance to next simpoint

            //Set to skip mode and reset traced instruction counter
            mode = skip;
            curr_trace_count = 0;
        }
        return;
    }
}

//Called once for each new trace set to collect.
//The samples_fullpath string specified the .samples file,
//e.g. /path/to/602.gcc_s.samples.  This function will
//read and store the <skip_count,trace_count> lines
//for use in generating simpoint traces.  It will also
//strip .samples from the end of the string and then
//append “-s<id>.txt” for each generated simpoint trace.
void simpoints_trace_init(const char *samples_fullpath)
{
    if (strlen(samples_fullpath) > MAX_BUFF) {
        fprintf(stderr, "simpoints_trace_init() error: samples file name is too long\n");
        return;
    }

    FILE *samples_file = fopen(samples_fullpath, "r");
    assert( samples_file != NULL );

    // The following parsing assumes each line of the .samples file 
    // consists of two numbers: "num_to_skip, num_to_trace"
    char line[MAX_BUFF];
    char delim[] = " ,\n";
    char *token;
    while ( fgets(line, sizeof(line), samples_file) != NULL) {
        //First token is the instruction skip count for the sample
        token = strtok(line, delim);
        sscanf(token, "%llu", &skip_counts[num_simpoints]);
        //Second token is the instruction trace count for the sample
        token = strtok(NULL, delim);
        sscanf(token, "%llu", &trace_counts[num_simpoints]);
        num_simpoints++;
    }
    fclose(samples_file);

    //Remove ".samples" from samples file full path name and save for creating trace files
    size_t base_tracename_len = strlen(samples_fullpath) - strlen(SAMPLES_FILE_EXT);
    strncpy(base_tracename, samples_fullpath, base_tracename_len);

    return;
}


// This function assumes it is called during simpoints tracing for the same 
// sequence of instructions that were used to build the BBV info and
// create the .samples file via the simpoints tool. It also assumes that 
// only EL0 instructions were used during BBV generation, so only EL0
// instructions are considered when updating the count of skipped or
// traced instructions for the current simpoint trace.
void simpoints_inst_cb(uint64_t pc, uint32_t el, const uint8_t *inst_buffer)
{
    if (curr_simpoint == num_simpoints) { //All traces are complete
        return;
    }

    update_simpoints_tracing_state();

    if (mode == skip) {
        if (el == 0) curr_skip_count++;
    } else if (mode == trace) {
        //Output instruction info to trace file
        fprintf(curr_tracefile, "user=%d\n", el);
        fprintf(curr_tracefile, "0x%016lx:  --  0x%02x%02x%02x%02x    N/A\n", 
                pc, inst_buffer[3], inst_buffer[2], inst_buffer[1], inst_buffer[0]);

        if (el == 0) curr_trace_count++;
    } else {
        fprintf(stderr, "simpoints-trace entered an unknown mode: %d\n", (int)mode);
        assert(0);
    }
    return;
}


void simpoints_mem_cb(uint64_t virt_addr, uint64_t phys_addr) 
{
    if (curr_simpoint == num_simpoints) { //All traces are complete
        return;
    }

    if (mode == trace) {
        //Output address info to trace file
        fprintf(curr_tracefile, "va=%016lx\npa=%016lx\n", virt_addr, phys_addr);        
    }
    return;
}
