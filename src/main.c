/*
 * TODOs:
 *   - CLI args of child are currently parsed (e.g., `./ministrace echo -e "kkl\tlkl\n"`) causing usage error (parsing must be stopped by using `--` before args)
 *   - Dynamically sized `tmap` (to make hard-coded size / cli arg unnecessary)
 *   - Issue: Return values of syscalls are always treated as `int` (but should be sometimes pointer, e.g., for `mmap`)
 *
 *   - Do we need PTRACE_DETATCH when using `-p` (i.e., `PTRACE_ATTACH`) option like strace does ??
 *
 *
 *  KNOWN ISSUES:
 *     - Buggy arm64 tracing support
 *     - Applications:
 *       - Running `wireshark` and attaching w/ follow flag (sudo ./src/ministrace -f -p `pidof wireshark`) crashes wireshark (when e.g., opening OS related UIs -> uid issue ??)
 *        Console: [1]  + 48133 suspended (signal)  wireshark
 *      - Running `firefox` w/ follow flag crashes (./src/ministrace -f firefox)
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "cli.h"
#include "trace/tracing.h"
#include "trace/internal/syscalls.h"

#include "common/error.h"



int main(int argc, char **argv) {
/* 0. Parse CLI args */
    cli_args parsed_cli_args;
    parse_cli_args(argc, argv, &parsed_cli_args);


/* Option 1: Print supported syscalls */
    if (parsed_cli_args.list_syscalls) {
        syscalls_print_all();
        return 0;

/* Option 2a: Attach to existing process */
    } else if (-1 != parsed_cli_args.attach_to_process) {
        return do_tracer(parsed_cli_args.attach_to_process, true, parsed_cli_args.pause_on_scall_nr, parsed_cli_args.follow_fork
#ifdef WITH_STACK_UNWINDING
                           , parsed_cli_args.print_stack_traces
#endif /* WITH_STACK_UNWINDING */
                );

/* Option 2b: Run command (i.e., new process) */
    } else {
        /* 1. Fork child (gets args passed) */
        int child_args_offset = 1 + parsed_cli_args.exec_arg_offset;    /* executable itself @ `argv[0]` + e.g., "--pause-snr", "<int>" */
        if (!strcmp("--", argv[child_args_offset])) {                   /* `--` for stop parsing cli args (otherwise args of to be traced program will be parsed) */
            child_args_offset++;
        }
        pid_t pid = DIE_WHEN_ERRNO(fork());
        return (!pid) ?
               (do_tracee(argc - child_args_offset, argv + child_args_offset)) :
               (do_tracer(pid, false, parsed_cli_args.pause_on_scall_nr, parsed_cli_args.follow_fork
#ifdef WITH_STACK_UNWINDING
                        , parsed_cli_args.print_stack_traces
#endif /* WITH_STACK_UNWINDING */
                ));
    }
}
