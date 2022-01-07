/**
 * CLI args parsing
 */
#ifndef CLI_H
#define CLI_H

#include <sys/types.h>

#include "generated/syscallents.h"


/* -- Types -- */
typedef struct cli_args {
    bool list_syscalls;
    pid_t attach_to_process;
    bool follow_fork;
    long pause_on_scall_nr;
#ifdef WITH_STACK_UNWINDING
    bool print_stack_traces;
#endif /* WITH_STACK_UNWINDING */

    bool trace_only_syscall_subset;
    bool to_be_traced_syscall_subset[SYSCALLS_ARR_SIZE];

    int exec_arg_offset;
} cli_args;


/* -- Function prototypes -- */
void parse_cli_args(int argc, char** argv,
                    cli_args* parsed_cli_args_ptr);

#endif /* CLI_H */
