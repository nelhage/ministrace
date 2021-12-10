#include <argp.h>

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "cli.h"
#include "__syscallents.h"



/* -- Functions -- */
bool _arg_was_passed_as_single_arg(char* arg) {
    return !strncmp("-", arg, strlen("-"));   /* CLI arg+option can be 1 arg when passed as `arg=val` or 2 when `arg val` */
}

int _str_to_long(char* str, long* num) {
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
        case 'l':
            arguments->list_syscalls = true;
            break;

        case 'f':
            arguments->follow_fork = true;
            arguments->exec_arg_offset++;
            break;

        case 'n':
            {
                long parsed_syscall_nr;
                if (_str_to_long(arg, &parsed_syscall_nr) < 0) {
                    argp_usage(state);
                }

                if ((parsed_syscall_nr > MAX_SYSCALL_NUM || parsed_syscall_nr < 0) ||
                    NULL == syscalls[parsed_syscall_nr].name) {
                    argp_usage(state);
                }
                arguments->pause_on_scall_nr = (int)parsed_syscall_nr;
                arguments->exec_arg_offset += _arg_was_passed_as_single_arg(state->argv[state->next -1]) ? (1) : (2);
            }
            break;

        case 'a':
            {
                for (int i = 0; i < SYSCALLS_ARR_SIZE; i++) {
                    const syscall_entry* const ent = &syscalls[i];
                    if (NULL != ent->name && !strcmp(arg, ent->name)) {  /* NOTE: Syscall-nrs may be non-consecutive (i.e., array has empty slots) */
                        arguments->pause_on_scall_nr = i;
                        arguments->exec_arg_offset += _arg_was_passed_as_single_arg(state->argv[state->next -1]) ? (1) : (2);
                        return 0;
                    }
                }
                argp_usage(state);
            }
            break;

        case ARGP_KEY_ARG:
          /* Too many arguments */
          break;

        case ARGP_KEY_END:
          /* Not enough arguments */
          if (state->arg_num < 1 && !arguments->list_syscalls) {
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
        {"list-syscalls", 'l', NULL,   0, "List supported syscalls",         0},
        {"follow-fork",   'f', NULL,   0, "Follow `fork`ed child processes", 1},
        {"pause-snr",     'n', "nr",   0, "Pause on specified syscall nr",   2},
        {"pause-sname",   'a', "name", 0, "Pause on specified syscall name", 2},
        {0}
    };

  /* Defaults */
    parsed_cli_args_ptr->list_syscalls = false;
    parsed_cli_args_ptr->follow_fork = false;
    parsed_cli_args_ptr->exec_arg_offset = 0;
    parsed_cli_args_ptr->pause_on_scall_nr = -1;

    static const struct argp argp = {
        cli_options, parse_cli_opt,
        "program",
        "A minimal toy implementation of strace(1)"
    };

    argp_parse(&argp, argc, argv, 0, 0, parsed_cli_args_ptr);
}
