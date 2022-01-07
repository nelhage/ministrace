#include <argp.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cli.h"
#include "common/string_utils.h"
#include "trace/internal/syscalls.h"


/* -- Functions -- */
bool __arg_was_passed_as_single_arg(char* arg) {
    return !strncmp("-", arg, strlen("-"));   /* CLI arg+option can be 1 arg when passed as `arg=val` or 2 when `arg val` */
}


static error_t parse_cli_opt(int key, char *arg, struct argp_state *state) {
    cli_args *arguments = state->input;

    switch(key) {
    /* List syscalls (and exit) */
        case 'l':
            arguments->list_syscalls = true;
            break;

    /* Follow `clone`'s */
        case 'f':
            arguments->follow_fork = true;
            arguments->exec_arg_offset++;
            break;

    /* Pause on specified syscall (passed as number) */
        case 'n':
            {
                long parsed_syscall_nr = -1;
                if ((-1 != arguments->pause_on_scall_nr)                  ||
                    (-1 == str_to_long(arg, &parsed_syscall_nr)) ||
                    (!syscalls_get_name(parsed_syscall_nr))) {
                    argp_usage(state);
                }
                arguments->pause_on_scall_nr = (int)parsed_syscall_nr;
                arguments->exec_arg_offset += __arg_was_passed_as_single_arg(state->argv[state->next - 1]) ? (1) : (2);
            }
            break;

    /* Pause on specified syscall (passed as name) */
        case 'a':
            {
                long syscall_nr = -1;
                if ((-1 != arguments->pause_on_scall_nr) ||
                    (-1 == (syscall_nr = syscalls_get_nr(arg)))) {
                    argp_usage(state);
                }
                arguments->pause_on_scall_nr = syscall_nr;
                arguments->exec_arg_offset += __arg_was_passed_as_single_arg(state->argv[state->next - 1]) ? (1) : (2);
            }
            break;

    /* Attach to already running process w/ corresponding pid */
        case 'p':
            {
                long parsed_attach_pid = -1;
                if (-1 == str_to_long(arg, &parsed_attach_pid)) {
                    argp_usage(state);
                }
                arguments->attach_to_process = (pid_t)parsed_attach_pid;
            }
            break;

#ifdef WITH_STACK_UNWINDING
    /* Print stack when printing syscall */
        case 'k':
            arguments->print_stack_traces = true;
            arguments->exec_arg_offset++;
            break;
#endif /* WITH_STACK_UNWINDING */

    /* Trace only subset of syscalls */
        case 'e':
            {
                arguments->trace_only_syscall_subset = true;
                memset(arguments->to_be_traced_syscall_subset, 0,
                       SYSCALLS_ARR_SIZE * sizeof(*(arguments->to_be_traced_syscall_subset)));

                if (strchr(arg, ',')) {
                    char* arg_copy = strdup(arg);

                    char* pch = NULL;
                    while ((pch = strtok((!pch) ? (arg_copy) : (NULL), ","))) {
                        const long scall_nr = syscalls_get_nr(pch);
                        if (-1 == scall_nr) {
                            argp_usage(state);
                        }
                        arguments->to_be_traced_syscall_subset[scall_nr] = true;
                    }

                    free(arg_copy);
                } else {
                    const long scall_nr = syscalls_get_nr(arg);
                    if (-1 == scall_nr) {
                        argp_usage(state);
                    }
                    arguments->to_be_traced_syscall_subset[scall_nr] = true;
                }
                arguments->exec_arg_offset += __arg_was_passed_as_single_arg(state->argv[state->next - 1]) ? (1) : (2);
            }
            break;

        case ARGP_KEY_ARG:
          /* Too many arguments */
          break;

        case ARGP_KEY_END:
          /* Not enough arguments */
          if (state->arg_num < 1 && (!arguments->list_syscalls && -1 == arguments->attach_to_process)) {
            argp_usage(state);
          }
          break;

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}


void parse_cli_args(int argc, char** argv,
                    cli_args* parsed_cli_args_ptr) {
    static const struct argp_option cli_options[] = {
        {"list-syscalls", 'l', NULL,          0, "List supported system calls", 0},
        {"attach",        'p', "pid",         0, "Attach to already running process", 1},
        {"follow-forks",  'f', NULL,          0, "Follow `fork`ed child processes", 2},
        {"pause-snr",     'n', "nr",          0, "Pause on specified system call nr", 3},
        {"pause-sname",   'a', "name",        0, "Pause on specified system call name", 3},
#ifdef WITH_STACK_UNWINDING
        {"stack-traces",  'k', NULL,          0, "Print the execution stack trace of the traced processes after each system call", 4},
#endif /* WITH_STACK_UNWINDING */
        {"trace",         'e', "syscall_set", 0, "Trace only the specified (as comma-list seperated) set of system calls", 4},
        {0}
    };

  /* Defaults */
    parsed_cli_args_ptr->list_syscalls = false;
    parsed_cli_args_ptr->attach_to_process = -1;
    parsed_cli_args_ptr->follow_fork = false;
#ifdef WITH_STACK_UNWINDING
    parsed_cli_args_ptr->print_stack_traces = false;
#endif /* WITH_STACK_UNWINDING */
    parsed_cli_args_ptr->pause_on_scall_nr = -1;
    parsed_cli_args_ptr->exec_arg_offset = 0;
    parsed_cli_args_ptr->trace_only_syscall_subset = false;

    static const struct argp argp = {
        cli_options, parse_cli_opt,
        "program",
        "A minimal toy implementation of strace(1)",
        .children = NULL, .help_filter = NULL, .argp_domain = NULL
    };

    argp_parse(&argp, argc, argv, 0, 0, parsed_cli_args_ptr);
}
