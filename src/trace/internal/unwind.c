/* For libdw usage examples / internals, see
 *   - https://github.com/strace/strace/blob/master/src/unwind-libdw.c
 *   - https://github.com/ganboing/elfutils/tree/master/libdwfl
 * Prerequisites: libunwind-dev, libdw-dev & libiberty-dev
 * TODO: Performance optimizations (see e.g., strace's `unwind-libdw.c`)
 */

#include <elfutils/libdwfl.h>
#define UNW_REMOTE_ONLY
#include <libunwind-ptrace.h>
#include <libiberty/demangle.h>                /* or g++ header `cxxabi.h` using `abi::__cxa_demangle` */

#include <stdio.h>
#include <stdlib.h>

#include "unwind.h"

#include <assert.h>
#include "../../common/error.h"


/* -- Macros / Globals  -- */
//#define MAX_STACKTRACE_DEPTH 64

static unw_addr_space_t unw_as;


/* -- Function prototypes -- */
static Dwfl* init_ldw_for_proc(pid_t tid);


/* -- Functions -- */
void unwind_init(void) {
    /* ELUCIDATION:
     *   `unw_create_addr_space`(3): Create a new remote unwind address-space; args:
     *      - `ap` pointer (= set of callback routines to access information required to unwind a chain of stackframes) +
     *      - specified byteorder (`0` = default byte-order of unwind target)
     */
    if (! (unw_as = unw_create_addr_space(&_UPT_accessors, 0)) ) {
        LOG_ERROR_AND_EXIT("libunwind -- failed to create address space for stack unwinding");
    }

    /* ELUCIDATION:
     *   `unw_set_caching_policy`(3): Sets the caching policy of address space, may be either ...
     *     - `UNW_CACHE_NONE`, `UNW_CACHE_GLOBAL`, `UNW_CACHE_PER_THREAD`
     *     WARNING: Caching requires appropriate calls to unw_flush_cache() to ensure cache validity
     */
    // unw_set_caching_policy(_unw_as, UNW_CACHE_GLOBAL);
}

void unwind_fin(void) {
    unw_destroy_addr_space(unw_as);        // ?? TODO: Necessary ??
}


void unwind_print_backtrace_of_proc(pid_t tid) {
    assert( unw_as && "Unwind context may be inited prior usage." );


/* 0. Init  */
    /* 0.1. libunwind */
    unw_context_t *unw_ctx = _UPT_create(tid);
    /* ELUCIDATION:
     *   `unw_init_remote`(3): Initialize unwind cursor
     *     - pointed to by `cursor` for unwinding the created
     *     - address space identified by `unw_as`;
     *     - `context` void-pointer tells the address space exactly what entity should be unwound
     */
    unw_cursor_t cursor;
    if (0 > unw_init_remote(&cursor, unw_as, unw_ctx)) {
        LOG_ERROR_AND_EXIT("libunwind -- failed to init context");
    }

    /* 0.2. libdw */
    Dwfl* dwfl = init_ldw_for_proc(tid);


/* 1. Print frames in execution stack of process */
#ifdef MAX_STACKTRACE_DEPTH
    int cur_stack_depth = 0;
    do {
        if (cur_stack_depth++ >= MAX_STACKTRACE_DEPTH) { break; }
#else
    do {
#endif /* MAX_STACKTRACE_DEPTH */

    /* 1.1. Get IP-address */
        /* ELUCIDATION:
         *   `unw_get_reg`(3): Read the value of register `reg` in stackframe identified by `cursor` and store its value in the word pointed to by `ip`
         */
        unw_word_t ip = 0;
        if (0 > unw_get_reg(&cursor, UNW_REG_IP, &ip)) {
            LOG_ERROR_AND_EXIT("libunwind -- failed to walk the stack of process %d", tid);
        }

    /* 1.2. Get + Print so filename */
        Dwfl_Module* module = dwfl_addrmodule(dwfl, (uintptr_t)ip);
        const char *module_name = dwfl_module_info(module, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        fprintf(stderr, " > %s", /*strrchr(module_name,'/') +1*/ module_name);

    /* 1.3. Print function (i.e., symbol) + offset in function */
        /* ELUCIDATION:
         *   `unw_get_proc_name`(3): Get name of function which created stackframe identified by `cursor`
         *     - `sym` = pointer to a char buffer which will hold the procedure name and
         *     - that is at least `len` bytes long
         *     - `offset` = pointer to word used to return **byte-offset of IP saved in the stackframe (identified by `cursor`), relative to start of procedure**
         */
        unw_word_t offset = 0;
        char symbol_buf[4096];
        if (! unw_get_proc_name(&cursor, symbol_buf, sizeof(symbol_buf), &offset) ) {
            // OPTIONALLY: Demangle C++ fct names
            char *symbol = symbol_buf;
            if (! (symbol = cplus_demangle(symbol_buf, 0)) ) {
                symbol = symbol_buf;
            }

            fprintf(stderr, "(%s+0x%lx)", symbol, offset);
            // Deallocate demangled C++ symbol name (if returned by `cplus_demangle`)
            if (symbol_buf != symbol) {
                free(symbol);
                symbol = NULL;
            }
        } else {
            fprintf(stderr, "(-- found no symbol)");
        }

    /* 1.4. Print IP-address */
        fprintf(stderr, " [0x%lx]\n", ip);


    /* ELUCIDATION:
     *   `unw_step`(3): Advances unwind `cursor` to the next older, less deeply nested stackframe
     */
    } while (unw_step(&cursor) > 0);


/* 2. Cleanup (destroy unwinding context of process) */
    dwfl_end(dwfl);
    _UPT_destroy(unw_ctx);
}


/* - Helpers - */
static Dwfl* init_ldw_for_proc(pid_t tid) {
    static const Dwfl_Callbacks dwfl_callbacks = {
        .find_elf = dwfl_linux_proc_find_elf,
        .find_debuginfo = dwfl_standard_find_debuginfo
    };

    Dwfl* dwfl;
    if ( (dwfl = dwfl_begin(&dwfl_callbacks))      &&
          !dwfl_linux_proc_attach(dwfl, tid, true) &&
          !dwfl_linux_proc_report(dwfl, tid)       &&
          !dwfl_report_end(dwfl, NULL, NULL) ) {
        return dwfl;
    }

    dwfl_end(dwfl);
    LOG_ERROR_AND_EXIT("libdw -- failed to init for process %d", tid);
}
