#include <argp.h>

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "cli.h"
#include "trace/internal/syscalls.h"


/* -- Functions -- */
bool __arg_was_passed_as_single_arg(char* arg) {
    return !strncmp("-", arg, strlen("-"));   /* CLI arg+option can be 1 arg when passed as `arg=val` or 2 when `arg val` */
}

int __str_to_long(char* str, long* num) {
    char *parse_end_ptr = NULL;
    if (NULL != (parse_end_ptr = str) && NULL != num) {
        char *p_end_ptr = NULL;
        const long parsed_number = (int)strtol(parse_end_ptr, &p_end_ptr, 10);

        if (parse_end_ptr != p_end_ptr && ERANGE != errno) {
            *num = parsed_number;
            return 0;
        }
    }
    return -1;
}


static error_t parse_cli_opt(int key, char *arg, struct argp_state *state) {
    cli_args *arguments = state->input;

    switch(key) {
    /* List syscalls and exit */
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
                if (__str_to_long(arg, &parsed_syscall_nr) < 0) {
                    argp_usage(state);
                }

                if (!syscalls_get_name(parsed_syscall_nr)) {
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
                if (0 <= (syscall_nr = syscalls_get_nr(arg))) {
                    arguments->pause_on_scall_nr = syscall_nr;
                    arguments->exec_arg_offset += __arg_was_passed_as_single_arg(state->argv[state->next - 1]) ? (1) : (2);
                    return 0;
                }
                argp_usage(state);
            }
            break;

    /* Attach to already running process w/ corresponding pid */
        case 'p':
            {
                long parsed_attach_pid = -1;
                if (__str_to_long(arg, &parsed_attach_pid) < 0) {
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
        {"list-syscalls", 'l', NULL,   0, "List supported syscalls", 0},
        {"attach",        'p', "pid",  0, "Attach to already running process", 1},
        {"follow-forks",  'f', NULL,   0, "Follow `fork`ed child processes", 2},
        {"pause-snr",     'n', "nr",   0, "Pause on specified syscall nr", 3},
        {"pause-sname",   'a', "name", 0, "Pause on specified syscall name", 3},
#ifdef WITH_STACK_UNWINDING
        {"stack-traces",  'k', NULL,   0, "Print the execution stack trace of the traced processes after each syscall", 4},
#endif /* WITH_STACK_UNWINDING */
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

    static const struct argp argp = {
        cli_options, parse_cli_opt,
        "program",
        "A minimal toy implementation of strace(1)",
        .children = NULL, .help_filter = NULL, .argp_domain = NULL
    };

    argp_parse(&argp, argc, argv, 0, 0, parsed_cli_args_ptr);
}
