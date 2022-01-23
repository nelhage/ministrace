/**
 * CLI args parsing
 */
#ifndef CLI_H
#define CLI_H

#include <stdbool.h>
#include <sys/types.h>

#include "generated/syscallents.h"


/* -- Types -- */
typedef struct {
    bool list_syscalls;
    pid_t pid_to_attach_to;
    bool follow_fork;
    long pause_on_scall_nr;
#ifdef WITH_STACK_UNWINDING
    bool print_stack_traces;
#endif /* WITH_STACK_UNWINDING */
    bool daemonize_tracer;

    bool trace_only_syscall_subset;
    bool to_be_traced_syscall_subset[SYSCALLS_ARR_SIZE];

    int exec_arg_offset;
} cli_args;


/* -- Function prototypes -- */
void parse_cli_args(int argc, char** argv,
                    cli_args* parsed_cli_args_ptr);

#endif /* CLI_H */
