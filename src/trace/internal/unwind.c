// See https://github.com/strace/strace/blob/master/src/unwind-libunwind.c

#define UNW_REMOTE_ONLY
#include <libunwind-ptrace.h>
#include <libiberty/demangle.h>								/* or g++ header `cxxabi.h` using `abi::__cxa_demangle` */

#include <stdio.h>
#include <stdlib.h>

#include "../../common/error.h"
#include "unwind.h"


/* -- Macros -- */
#define MAX_STACKTRACE_DEPTH 64


/* -- Globals -- */
static unw_addr_space_t unw_as;


/* -- Functions -- */
void unwind_init(void) {
    /* unw_create_addr_space(3): Create a new remote unwind address-space
     *  Gets initialized w/
     *    - `ap` pointer (= set of callback routines to access information required to unwind a chain of stackframes) +
     *    - specified byteorder (`0` = default byte-order of unwind target))
     */
    unw_as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!unw_as) {
        LOG_ERROR_AND_EXIT("Failed to create address space for stack tracing");
    }

    /*
     * unw_set_caching_policy(3): Sets the caching policy of address space, may be either ...
     *   - UNW_CACHE_NONE, UNW_CACHE_GLOBAL, UNW_CACHE_PER_THREAD
     *   WARNING: Caching requires appropriate calls to unw_flush_cache() to ensure cache validity
     */
    // unw_set_caching_policy(unw_as, UNW_CACHE_GLOBAL);
}

void unwind_fin(void) {
    unw_destroy_addr_space (unw_as);        // ?? TODO: Necessary ??
}



void unwind_print_backtrace_of_pid(pid_t pid) {
    if (!unw_as) {
        LOG_ERROR_AND_EXIT("Not init yet");
    }


/* -- TCB ?? init -- */
    /* Create new context ?? */
    void *context = _UPT_create(pid);


    /*
     * unw_init_remote(3): Initialize unwind cursor
     *   - pointed to by `cursor` for unwinding the created
     *   - address space identified by `unw_as`;
     *   - `context` void-pointer tells the address space exactly what entity should be unwound
     */
    unw_cursor_t cursor;
    if (0 > unw_init_remote(&cursor, unw_as, context)) {
        LOG_ERROR_AND_EXIT("Cannot initialize libunwind");
    }


/* -- Print frames in execution stack of process -- */
#ifdef MAX_STACKTRACE_DEPTH
    int stack_depth = 0;
#endif /* MAX_STACKTRACE_DEPTH */
    do {
#ifdef MAX_STACKTRACE_DEPTH
        if (stack_depth++ >= MAX_STACKTRACE_DEPTH) break;
#endif /* MAX_STACKTRACE_DEPTH */

    /* -- $$$   TODO: Print so path  (<path>)  $$$ --  */
        fprintf(stderr, " > ");


    /* -- Print function + offset in function --  */
        /*
         * unw_get_proc_name(3): Get name of function which created stackframe identified by `cursor`
         *   - `sym` = pointer to a char buffer which will hold the procedure name and
         *   - that is at least `len` bytes long
         *   - `offset` = pointer to word used to return **byte-offset of IP saved in the stackframe (identified by `cursor`), relative to start of procedure**
         */
        unw_word_t offset = 0;
        char symbol_buf[4096];
        if (!unw_get_proc_name(&cursor, symbol_buf, sizeof(symbol_buf), &offset)) {
            char *symbol = symbol_buf;
     	    if (!(symbol = cplus_demangle(symbol_buf, 0))) {
      	        symbol = symbol_buf;
    	    }

            fprintf(stderr, "(%s+0x%lx)", symbol, offset);
            if (symbol_buf != symbol) {													// $$$$$$$$$$$$$$$$$$$ TODO: `free` seems to be necessary (dyn. all. mem.) $$$$$$$$$$$$$$$$$$$
				// fprintf(stderr, "\n\n ---> %s\n\n", symbol);
				free(symbol);
				symbol = NULL;
			}
        } else {
            fprintf(stderr, "(-- found no symbol)");
        }


    /* -- Print IP -- */
        /*
         * unw_get_reg(3): Read the value of register `reg` in stackframe identified by `cursor` and store its value in the word pointed to by `pc`
         */
        unw_word_t pc = 0;
        if (0 > unw_get_reg(&cursor, UNW_REG_IP, &pc)) {
            LOG_ERROR_AND_EXIT("Cannot walk the stack of process %d", pid);
        }
        fprintf(stderr, " [0x%lx]\n", pc);


    /*
     * unw_step(3): Advances unwind `cursor` to the next older, less deeply nested stackframe
     */
    } while (unw_step(&cursor) > 0);


/* -- tcb_fin ?? (Destroy unwinding context of process) -- */
    _UPT_destroy(context);
}
