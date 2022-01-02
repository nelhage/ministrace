#define UNW_REMOTE_ONLY
#include <libunwind-ptrace.h>
#include <libiberty/demangle.h>								/* or g++ header `cxxabi.h` using `abi::__cxa_demangle` */

#include <stdlib.h>
#include <stdio.h>

#include "unwind.h"

#include "../../common/error.h"


void print_backtrace_of_tracee(pid_t pid) {
      /* Create a new unwind address-space representing the target process
       *  Gets initialized w/
       *    - `ap` pointer (= set of callback routines to access information required to unwind a chain of stackframes) +
       *    - specified byteorder (`0` = default byte-order of unwind target))
       */
    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);


    /* Create new context ?? */
    void *context = _UPT_create(pid);

    /*
     * Initialize unwind cursor
     *   - pointed to by `cursor` for unwinding the created
     *   - address space identified by `as`;
     *   - `context` void-pointer tells the address space exactly what entity should be unwound
     */
    unw_cursor_t cursor;
    if (0 > unw_init_remote(&cursor, as, context)) {
        LOG_ERROR_AND_EXIT("Init failed");
    }


    do {
        unw_word_t offset = 0, pc = 0;
        /*
         * Read the value of register `reg` in stackframe identified by `cursor` and store its value in the word pointed to by `pc`
         */
        if (0 > unw_get_reg(&cursor, UNW_REG_IP, &pc)) {
            LOG_ERROR_AND_EXIT("Reading IP failed");
        }

        fprintf(stderr, "0x%lx: ", pc);

        char symbol_buf[4096];
        /*
         * Get name of function which created stackframe identified by `cursor`
         *   - `sym` = pointer to a char buffer which will hold the procedure name and
         *   - that is at least `len` bytes long
         *   - `offset` = pointer to word used to return **byte-offset of IP saved in the stackframe (identified by `cursor`), relative to start of procedure**
         */
        if (!unw_get_proc_name(&cursor, symbol_buf, sizeof(symbol_buf), &offset)) {
            char *symbol = symbol_buf;
     	    if (!(symbol = cplus_demangle(symbol_buf, 0))) {
      	        symbol = symbol_buf;
    	    }

            fprintf(stderr, "(%s+0x%lx)\n", symbol, offset);
            if (symbol_buf != symbol) {													// $$$$$$$$$$$$$$$$$$$ TODO: `free` seems to be necessary (dyn. all. mem.) $$$$$$$$$$$$$$$$$$$
				// fprintf(stderr, "\n\n ---> %s\n\n", symbol);
				free(symbol);
				symbol = NULL;
			}
        } else {
            fprintf(stderr, "-- no symbol name found\n");
        }

        /*
         * Advances unwind `cursor` to the next older, less deeply nested stackframe
         */
    } while (unw_step(&cursor) > 0);

    /* Destroy context ?? */
    _UPT_destroy(context);
}