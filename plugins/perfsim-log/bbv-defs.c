#include "bbv-defs.h"

void bbv_commit(uint64_t commit_entry_pc, uint64_t commit_exit_pc, uint64_t term_cond, uint64_t size, FILE* bb_debugfile) {
    int64_t exit_pc_bbv_id, entry_pc_bbv_id;
    bool exit_pc_bbv_found, entry_pc_bbv_found;

    BBV_ERR(commit_entry_pc + ((size - 1) * 0x4) == commit_exit_pc, 
            "bbv_commit() Illegal basic block parameters; commit_entry_pc = 0x%016x; size = %d; commit_exit_pc = 0x%016x\n", commit_entry_pc, size, commit_exit_pc);

    // Search for entry pc and exit pc in the bbv table
    uint64_t hidden_bbv = bbv_find_endpoints(commit_entry_pc, commit_exit_pc, &entry_pc_bbv_id, &exit_pc_bbv_id);

    entry_pc_bbv_found = entry_pc_bbv_id != -1;
    exit_pc_bbv_found = exit_pc_bbv_id != -1;

    if( (!entry_pc_bbv_found || !exit_pc_bbv_found) && (hidden_bbv != -1) ){
        // This is the notorious case of hidden bbv's
        // Use recursion to align boundaries with hidden bbv's and return
        uint64_t size1 = (basic_block_vector[hidden_bbv].bbentry_pc - commit_entry_pc) / 0x4;
        uint64_t size2 = size - size1;

        DFPRINTF(bb_debugfile, "Recursing due to hidden bbv's\n");
        bbv_commit(commit_entry_pc, basic_block_vector[hidden_bbv].bbentry_pc - 0x4, OTHER, size1, bb_debugfile);
        bbv_commit(basic_block_vector[hidden_bbv].bbentry_pc, commit_exit_pc, term_cond, size2, bb_debugfile);
        return;
    }

    DFPRINTF(bb_debugfile, "commit: %016x %016x %d %d; entryid: %d exitid: %d - %d%d\n", commit_entry_pc, 
            commit_exit_pc, term_cond, 
            size, entry_pc_bbv_id, 
            exit_pc_bbv_id, 
            entry_pc_bbv_found,
            exit_pc_bbv_found);

    // #########################################################################
    //
    //    Case 0:    -------------                  
    //              |     NEW     |                 
    //               -------------                  
    //                               ------------   
    //                              |     OLD    |  
    //                               ------------   
    // #########################################################################
    if( !exit_pc_bbv_found && !entry_pc_bbv_found ){
        // Case 0 :: Corner case: - ;
        // This is the case of a completely new bbv
        // It's a new bbv, creata a new entry in the bbv table and update hash table
        uint64_t bbv_index = bbv_create_array_entry(commit_entry_pc, bb_debugfile);
        bbv_set_size(bbv_index, size, term_cond);
        bbv_incr_freq(commit_entry_pc, bbv_index);

        DFPRINTF(bb_debugfile, "-- case0: update(%016x %016x)\n", commit_entry_pc, commit_exit_pc);
    } 

    // #########################################################################
    //
    //   Case 1:    -------------
    //             |     NEW     |
    //              -------------
    //          -------------
    //         |     OLD     |
    //          -------------      
    // #########################################################################
    else if( !exit_pc_bbv_found && entry_pc_bbv_found ){
        DFPRINTF(bb_debugfile, "-- case1: ");
        // case 1 :: Corner case: entry pc of new matches entry pc of old;
        uint64_t old_size     = basic_block_vector[entry_pc_bbv_id].size;
        uint64_t old_entry_pc = basic_block_vector[entry_pc_bbv_id].bbentry_pc;
        uint64_t old_exit_pc  = basic_block_vector[entry_pc_bbv_id].bbexit_pc;

        uint64_t non_overlap_size = (commit_exit_pc - old_exit_pc) / 0x4;

        // Commit the non-overlapping part with 1 as its frequency
        uint64_t bbv_index = bbv_create_array_entry(old_exit_pc + 0x4, bb_debugfile);
        bbv_set_size(bbv_index, non_overlap_size, term_cond);
        bbv_incr_freq(old_exit_pc + 0x4, bbv_index);
        DFPRINTF(bb_debugfile, "non_overlap(%016x %016x) ", old_exit_pc + 4, old_exit_pc + 4 + (non_overlap_size - 1) * 0x4);

        if( old_entry_pc == commit_entry_pc ){
            bbv_incr_freq(commit_entry_pc, entry_pc_bbv_id);
            DFPRINTF(bb_debugfile, "update(%016x %016x) ", commit_entry_pc, old_exit_pc);
        } else{
            assert( old_entry_pc < commit_entry_pc );
            // Partial overlap, create 2 splits from here

            // Reduce the size of the existing bbv 
            bbv_set_size(entry_pc_bbv_id, old_size - (size - non_overlap_size), OTHER);

            // Create a split bbv for the carved bbv
            uint64_t split_bbv_index = bbv_create_array_entry(commit_entry_pc, bb_debugfile);
            bbv_set_size(split_bbv_index, (size - non_overlap_size), OTHER);
            basic_block_vector[split_bbv_index].freq = basic_block_vector[entry_pc_bbv_id].freq + 1;

            DFPRINTF(bb_debugfile, "update(%016x %016x) ", old_entry_pc, commit_entry_pc - 0x4);
            DFPRINTF(bb_debugfile, "carve_create(%016x %016x) ", commit_entry_pc, old_exit_pc);
        }
        DFPRINTF(bb_debugfile, "\n");
    }

    // #########################################################################
    //    Case 2:    -------------           
    //              |     NEW     |          
    //               -------------           
    //                       ------------    
    //                      |     OLD    |   
    //                       ------------    
    // #########################################################################
    else if( exit_pc_bbv_found && !entry_pc_bbv_found ){
        DFPRINTF(bb_debugfile, "-- case2: ");
        // case 2 :: Corner case: exit pc of new matches exit pc of old;
        uint64_t old_size     = basic_block_vector[exit_pc_bbv_id].size;
        uint64_t old_entry_pc = basic_block_vector[exit_pc_bbv_id].bbentry_pc;
        uint64_t old_exit_pc  = basic_block_vector[exit_pc_bbv_id].bbexit_pc;

        uint64_t non_overlap_size = (old_entry_pc - commit_entry_pc) / 0x4;

        // Commit the non-overlapping part with a frequency of 1
        uint64_t bbv_index = bbv_create_array_entry(commit_entry_pc, bb_debugfile);
        bbv_set_size(bbv_index, non_overlap_size, OTHER);
        bbv_incr_freq(commit_entry_pc, bbv_index);

        DFPRINTF(bb_debugfile, "non_overlap(%016x %016x) ", commit_entry_pc, commit_entry_pc + (non_overlap_size - 1) * 0x4);

        if( commit_exit_pc == old_exit_pc ){
            bbv_incr_freq(old_entry_pc, exit_pc_bbv_id);
            DFPRINTF(bb_debugfile, "update(%016x %016x) ", old_entry_pc, old_exit_pc);
        } else{
            assert( commit_exit_pc < old_exit_pc );
            // Reduce the size of the old bbv
            bbv_set_size(exit_pc_bbv_id, (size - non_overlap_size), term_cond);

            // Create a split bbv for the carved bbv
            uint64_t split_bbv_index = bbv_create_array_entry(commit_exit_pc + 0x4, bb_debugfile);
            bbv_set_size(split_bbv_index, old_size - (size - non_overlap_size), basic_block_vector[exit_pc_bbv_id].term_cond);
            basic_block_vector[split_bbv_index].freq = basic_block_vector[exit_pc_bbv_id].freq;

            bbv_incr_freq(old_entry_pc, exit_pc_bbv_id);

            DFPRINTF(bb_debugfile, "update(%016x %016x) ", old_entry_pc, commit_exit_pc);
            DFPRINTF(bb_debugfile, "carve_create(%016x %016x) ", commit_exit_pc + 0x4, old_exit_pc);
        }
        DFPRINTF(bb_debugfile, "\n");
    } 

    // #########################################################################
    //   Case 3a:  -------------     3b.    -----          3c.  -----------
    //            |     NEW     |          | NEW |             |    NEW    |
    //             -------------            -----               -----------
    //             -------------       ----------------   --------     --------
    //            |     OLD     |     |      OLD       | | OLD_P0 |   | OLD_P1 |
    //             -------------       ----------------   --------     --------
    // #########################################################################
    else {
        // case 3
        DFPRINTF(bb_debugfile, "-- case3: ");
        if( (commit_entry_pc == basic_block_vector[entry_pc_bbv_id].bbentry_pc) && (size == basic_block_vector[entry_pc_bbv_id].size) ){
            // case 3a
            // Same bbv, increment the frequency
            bbv_incr_freq(commit_entry_pc, entry_pc_bbv_id);
            DFPRINTF(bb_debugfile, "match(%016x %016x) ", commit_entry_pc, commit_exit_pc);
        } else if(entry_pc_bbv_id == exit_pc_bbv_id){
            // case 3b
            // Subset of a bigger bbv
            // Right split - create the right split after reducing the size of bigger bbv so as to not fire aseertions
            uint64_t right_size = (BBV_GET_LAST(exit_pc_bbv_id) - commit_exit_pc) / 0x4;

            if( commit_entry_pc == basic_block_vector[exit_pc_bbv_id].bbentry_pc ){
                // Left aligned split
                assert( right_size > 0 );
                assert(basic_block_vector[exit_pc_bbv_id].size - right_size == size);

                DFPRINTF(bb_debugfile, "left_align(%016x %016x) ", commit_entry_pc, 
                        commit_entry_pc + (basic_block_vector[exit_pc_bbv_id].size - right_size - 1) * 0x4);
                bbv_set_size(exit_pc_bbv_id, basic_block_vector[exit_pc_bbv_id].size - right_size, OTHER);
                bbv_incr_freq(commit_entry_pc, exit_pc_bbv_id);
            } else{
                // Left split
                bbv_set_size(exit_pc_bbv_id, basic_block_vector[exit_pc_bbv_id].size - size - right_size, OTHER);

                // Center split
                uint64_t center_split_bbv_index = bbv_create_array_entry(commit_entry_pc, bb_debugfile);
                bbv_set_size(center_split_bbv_index, size, OTHER);
                basic_block_vector[center_split_bbv_index].freq = basic_block_vector[exit_pc_bbv_id].freq + 1;
            }
            DFPRINTF(bb_debugfile, "triupdate(%016x %016x; %016x %016x) ", basic_block_vector[exit_pc_bbv_id].bbentry_pc, 
                    BBV_GET_LAST(exit_pc_bbv_id),
                    commit_entry_pc, exit);

            if( right_size > 0 ){
                DFPRINTF(bb_debugfile, "triupdate(%016x %016x) ", commit_exit_pc + 0x4, commit_exit_pc + right_size * 0x4);
                uint64_t right_split_bbv_index = bbv_create_array_entry(commit_exit_pc + 0x4, bb_debugfile);
                bbv_set_size(right_split_bbv_index, right_size, basic_block_vector[exit_pc_bbv_id].term_cond);
                basic_block_vector[right_split_bbv_index].freq = basic_block_vector[exit_pc_bbv_id].freq;
            }
        } else{
            // case 3c
            // Align the boundaries and commit
            uint64_t p1_end_pc = basic_block_vector[entry_pc_bbv_id].bbexit_pc;
            uint64_t p1_size = 1 + (p1_end_pc - commit_entry_pc) / 0x4;

            DFPRINTF(bb_debugfile, "Recursing due for case 3: (%016x %016x: %d) (%016x %016x:%d)\n", commit_entry_pc, p1_end_pc, 
                    p1_size, p1_end_pc + 0x4,
                    commit_exit_pc, size - p1_size);
            bbv_commit(commit_entry_pc, p1_end_pc, OTHER, p1_size, bb_debugfile);
            bbv_commit(p1_end_pc + 0x4, commit_exit_pc, term_cond, size - p1_size, bb_debugfile);
        }
        DFPRINTF(bb_debugfile, "\n");
    }
}

// Dump the BBs collected in this interval and clear out the bb vector
void bbv_dump(FILE *bb_logfile, FILE *bb_intervalfile, uint64_t bbv_interval_user_pc_count){
    uint64_t i;

    assert(bb_logfile && "NULL bb_logfile passed");
    assert(bb_intervalfile && "NULL bb_intervalfile passed");

    DFPRINTF(stdout, "Dumping in %d instructions with %d bbv's\n", bbv_interval_user_pc_count, live_bb_count);
    // Start with a literal "T" to mark the start of an interval
    fprintf(bb_logfile,"T");
    for( i = 0; i < live_bb_count; i++ ){
        if (basic_block_vector[i].freq) {
            // Dump and clear the basic block
            fprintf(bb_logfile, ":%"PRId64":%"PRId64" ", basic_block_vector[i].bbentry_pc, (basic_block_vector[i].freq) * (basic_block_vector[i].size));
        }
        basic_block_vector[i].bbentry_pc = 0x0;
        basic_block_vector[i].bbexit_pc  = 0x0;
        basic_block_vector[i].freq       = 0x0;
        basic_block_vector[i].size       = 0;
        basic_block_vector[i].term_cond  = INIT_VALUE;
    }
    // Insert a new line to mark the end of an interval
    fprintf (bb_logfile,"\n");

    // Dump stats to interval file
    fprintf(bb_intervalfile, "%"PRIu32":%"PRIu64":%"PRIu64 "\n", 
            bbv_interval_count, 
            bbv_interval_start_user_pc_count, 
            bbv_interval_user_pc_count);
    bbv_interval_start_user_pc_count += bbv_interval_user_pc_count;
    ++bbv_interval_count;

    // Clearing the bbv's
    live_bb_count = 0;

    // Flush both the files for sanity
    assert( (fflush(bb_logfile) == 0) && "Unable to fflush bb_logfile" );
    assert( (fflush(bb_intervalfile) == 0) && "Unable to fflush bb_intervalfile" );
}

// Update the frequency of this basic-block. We increment everytime we hit a pc which is within the range
// [ bbentry_pc : bbentry_pc+size]
void bbv_incr_freq(uint64_t bbentry_pc, uint32_t bbv_index){
    BBV_ERR(bbv_index != -1, "bbv_incr_freq() got -1 as bbv_index\n");

    uint64_t startpc = basic_block_vector[bbv_index].bbentry_pc;

    BBV_ERR(startpc == bbentry_pc, "bbv_incr_freq() found pc; PC=0x%016x BBV_PC=0x%016x\n", bbentry_pc, startpc);
    basic_block_vector[bbv_index].freq++;
}

// Set the size (in instructions) of the basic block that was recorded
void bbv_set_size(int bbv_idx, int size, unsigned long int term_cond){
    CHECK_BBV_IDX(bbv_idx);
    BBV_ERR(size > 0 && size < 4096, "bbv_set_size() illegal size passed %d\n", size);
    basic_block_vector[bbv_idx].size = size;
    basic_block_vector[bbv_idx].bbexit_pc = basic_block_vector[bbv_idx].bbentry_pc + (size - 1) * 0x4;
    basic_block_vector[bbv_idx].term_cond = term_cond;
}

//Looks through the basic block vector entries and finds the entry with the range of PCs containing this PC
int bbv_find_array_entry(uint64_t bbentry_pc){
    static int last_entry = -1;
    int i;

    if( (last_entry != -1) && (last_entry < live_bb_count)){
        // Check if the "last_entry" matches for this pc.
        if( (basic_block_vector[last_entry].bbentry_pc <= bbentry_pc) && (bbentry_pc <= basic_block_vector[last_entry].bbexit_pc) ){
            return(last_entry);
        }
    } else{
        last_entry = -1;
    }
    // Running inverted loop as we might break early due to temporal locality
    for( i = live_bb_count - 1; i >= 0; i-- ){
        if((basic_block_vector[i].bbentry_pc <= bbentry_pc) &&
                (bbentry_pc <= (basic_block_vector[i].bbexit_pc))){
            last_entry = i;
            return(i);
        }
    }
    return(-1);
}

#define BBV_PC_IN_RANGE( pc, startpc, endpc ) ( (startpc) <= (pc) && (pc) <= (endpc) )
int bbv_find_endpoints(uint64_t start_pc, uint64_t end_pc, uint64_t *start_id, uint64_t *end_id){
    static int last_hidden_entry = -1;
    int i;

    *start_id = -1;
    *end_id = -1;

    if( (last_hidden_entry != -1) && (last_hidden_entry < live_bb_count)){
        if( (basic_block_vector[last_hidden_entry].bbentry_pc > start_pc) && (basic_block_vector[last_hidden_entry].bbexit_pc < end_pc) ){
            return(last_hidden_entry);
        }
    } else{
        last_hidden_entry = -1;
    }

    // Running inverted loop as we might break early due to temporal locality
    for( i = live_bb_count - 1; i >= 0 && ( *start_id == -1 || *end_id == -1 ); i-- ){
        uint64_t bbstart =  basic_block_vector[i].bbentry_pc;
        uint64_t bbend =  basic_block_vector[i].bbexit_pc;

        if( BBV_PC_IN_RANGE( start_pc, bbstart, bbend ) )
            *start_id = i;

        if( BBV_PC_IN_RANGE( end_pc, bbstart, bbend ) )
            *end_id = i;

        // Search for hidden bbv's
        if( bbstart > start_pc && bbend < end_pc )
            return i;
    }

    return -1;
}

unsigned int bbv_create_array_entry(uint64_t bbentry_pc, FILE* bb_debugfile){
    // UM: removing this due to performance reasons
    //int prev_entry = bbv_find_array_entry(bbentry_pc) ;

    //BBV_ERR(prev_entry == -1, "create_bb_array_entry(): Found previous entry at: %d for %#lx\n",prev_entry,bbentry_pc);

    //create new entry
    CHECK_BBV_IDX_LIMIT(live_bb_count);
    basic_block_vector[live_bb_count].bbentry_pc = bbentry_pc;
    basic_block_vector[live_bb_count].freq       = 0;
    basic_block_vector[live_bb_count].term_cond  = INIT_VALUE;
    DFPRINTF(bb_debugfile, "   create_bb_array_entry(): Created NEW bb #%ld - pc: %#lx\n", live_bb_count,bbentry_pc);
    live_bb_count++;
    return(live_bb_count-1);
}

void bbv_init(){
    unsigned int i;
    for( i = 0; i < live_bb_count; i++ ){
        basic_block_vector[i].bbentry_pc = 0x0;
        basic_block_vector[i].bbexit_pc  = 0x0;
        basic_block_vector[i].freq       = 0x0;
        basic_block_vector[i].size       = 0;
        basic_block_vector[i].term_cond  = INIT_VALUE;
    }
    live_bb_count = 0;
    bbv_interval_start_user_pc_count = 0;
    bbv_interval_count = 0;
}
