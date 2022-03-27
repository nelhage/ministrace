/*
 * - TODOs:
 *   - Fix arm64 tracing support (current implementation returns wrong syscall nr ??)
 *   - CLI args of child are currently parsed (e.g., `./ministrace echo -e "kkl\tlkl\n"`) causing usage error (parsing must be stopped by using `--` before args)
 *   - Pass also environment variables to tracee
 *   - Issue: Return values of syscalls are always treated as `int` (but should be sometimes pointer, e.g., for `mmap` + print flags (bitmask consts))
 *   - Do we need PTRACE_DETATCH when using `-p` (i.e., `PTRACE_ATTACH`) option like strace does ??
 *
 * - Known issues:
 *   - execve(2) offset calculation is off when passing CLI options together (e.g., -fk) (causes app to SEGFAULT) ==> Hence options must be passed separately
 *   - Tracing:
 *      - Daemon mode (-D) + attach (-p <pid>) causes ministrace to not react to ^C ?? (e.g., `sudo ./src/ministrace -D -p `pidof wireshark``)
 *      - Running `wireshark` and attaching w/ follow flag (sudo ./src/ministrace -f -p `pidof wireshark`) crashes wireshark (when e.g., opening OS related UIs)
 *          Console: [1]  + 48133 suspended (signal)  wireshark
 *      - Running `firefox` w/ follow option (./src/ministrace -f firefox) freezes UI
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/error.h"
#include "cli.h"
#include "trace/tracing.h"
#include "trace/internal/syscalls.h"



int main(int argc, char **argv) {
/* 0. Parse CLI args */
    cli_args_t parsed_cli_args;
    parse_cli_args(argc, argv, &parsed_cli_args);


/* Option 1: Print supported syscalls */
    if (parsed_cli_args.list_syscalls) {
        syscalls_print_all();
        return 0;
    }


    tracer_options_t tracer_options = {
        .tracee_pid = parsed_cli_args.pid_to_attach_to,           /* May be later overwritten when not attaching */
        .attach_to_tracee = (-1 != parsed_cli_args.pid_to_attach_to),
        .pause_on_syscall_nr = parsed_cli_args.pause_on_scall_nr,
        .syscall_subset_to_be_traced = (parsed_cli_args.trace_only_syscall_subset) ? (parsed_cli_args.syscall_subset_to_be_traced) : (NULL),
        .follow_fork = parsed_cli_args.follow_fork,
        .daemonize = parsed_cli_args.daemonize_tracer,
#ifdef WITH_STACK_UNWINDING
        .print_stacktrace = parsed_cli_args.print_stack_traces
#endif /* WITH_STACK_UNWINDING */
    };

/* Option 2a: Attach to existing process */
    if (tracer_options.attach_to_tracee) {
        return do_tracer(&tracer_options);

/* Option 2b: Run command (i.e., new process) */
    } else {
        /* 1. Fork child (gets args passed) */
        int child_args_offset = 1 + parsed_cli_args.exec_arg_offset;    /* executable itself @ `argv[0]` + e.g., "--pause-snr", "<int>" */
        if (!strcmp("--", argv[child_args_offset])) {                   /* `--` for stop parsing cli args (otherwise args of to be traced program will be parsed) */
            child_args_offset++;
        }

        const pid_t child_pid = DIE_WHEN_ERRNO(fork() );
        if (!tracer_options.daemonize) {
        /* Roles:  Tracer = Parent,  Tracee = Child */
            tracer_options.tracee_pid = child_pid;
            return (!child_pid) ?
                   (do_tracee(argc - child_args_offset, argv + child_args_offset, &tracer_options)) :
                   (do_tracer(&tracer_options));
        } else {
        /* Roles:  Tracee = Parent,  Tracer = (Grand)child */
            tracer_options.tracee_pid = getppid();
            return (!child_pid) ?
                   (do_tracer(&tracer_options)) :
                   (do_tracee(argc - child_args_offset, argv + child_args_offset, &tracer_options));
        }
    }
}
