/*
 * TODOs:
 *   - CLI args of child are currently parsed (e.g., `./ministrace echo -e "kkl\tlkl\n"`) causing usage error (parsing must be stopped by using `--` before args)
 *   - Dynamically sized `tmap` (to make hard-coded size / cli arg unnecessary)
 */
#include "trace_ptrace.h"
#include <sys/wait.h>
#include <signal.h>
#include "trace_syscalls.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "cli.h"
#include "error.h"

// #include "trace_tmap.h"

/* -- Global consts -- */
// #define DEFAULT_TMAP_MAX_SIZE 500


/* -- Function prototypes -- */
void print_syscalls(void);

int do_tracer(pid_t pid, int pause_on_syscall_nr, bool follow_fork);
int do_tracee(int argc, char **argv);

bool wait_for_syscall_or_exit(pid_t pid);

void wait_for_user_input(void);

void print_syscall(pid_t pid, long syscall_nr);


/* -- Functions -- */
int main(int argc, char **argv) {
/* 0. Parse CLI args */
    cli_args parsed_cli_args;
    parse_cli_args(argc, argv, &parsed_cli_args);

    if (parsed_cli_args.list_syscalls) {
        print_syscalls();
        return 0;
    }

/* 1. Fork child (gets args passed) */
    int child_args_offset = 1 + parsed_cli_args.exec_arg_offset;    /* executable itself @ `argv[0]` + e.g., "--pause-snr", "<int>" */
    if (!strcmp("--", argv[child_args_offset])) {                   /* `--` for stop parsing cli args (otherwise args of to be traced program will be parsed) */
        child_args_offset++;
    }
    pid_t pid = DIE_WHEN_ERRNO(fork());
    return (!pid) ?
         (do_tracee(argc - child_args_offset, argv + child_args_offset)) :
         (do_tracer(pid, parsed_cli_args.pause_on_scall_nr, parsed_cli_args.follow_fork));
}


/* ----------------------------------------- ----------------------------------------- ----------------------------------------- */
int do_tracee(int argc, char **argv) {
/* exec setup: Create new array for argv of to be exec'd command */
    char *child_exec_argv[argc + 1 /* NULL terminator */];
    memcpy(child_exec_argv, argv, (argc * sizeof(argv[0])));
    child_exec_argv[argc] = NULL;
    const char* child_exec = child_exec_argv[0];

/* `PTRACE_TRACEME` starts tracing + causes next signal (sent to this process) to stop it & notify the parent (via `wait`), so that the parent knows to start tracing */
    ptrace(PTRACE_TRACEME);
/* Stop oneself so parent can set tracing option + Parent will see exec syscall */
    kill(getpid(), SIGSTOP);
/* Execute actual program */
    return execvp(child_exec, child_exec_argv);

/* Error handling (in case exec failed) */
    LOG_ERROR_AND_EXIT("Couldn't exec \"%s\"", child_exec);
}


/* -- Tracing -- */
int do_tracer(const pid_t pid, const int pause_on_syscall_nr, const bool follow_fork) {

/* (0) Set ptrace options */
    int status;
    do {
        DIE_WHEN_ERRNO(waitpid(pid, &status, 0));
    } while(!WIFSTOPPED(status));

    /*
     * ELUCIDATION:
     *  - `WIFSTOPPED`: Returns nonzero value if child process is stopped
     */
    if (!WIFSTOPPED(status)) {
        LOG_ERROR_AND_EXIT("Couldn't stop child process");
    }

    /*
     * ELUCIDATION:
     *  - `PTRACE_O_TRACESYSGOOD`: When delivering syscall traps, set bit 7 in the signal number (i.e., deliver SIGTRAP|0x80) (see `PTRACE_TRAP_INDICATOR_BIT`)
     *    -> Makes it easier (for tracer) to distinguish b/w normal- & from syscalls caused traps
     *  - `PTRACE_O_TRACECLONE`: Stop the tracee at next `clone(2)` and automatically starts tracing the newly cloned process, which will start w/ a SIGSTOP; `waitpid(2)` by the tracer will
     *                           return a status value such that status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))
     */
    unsigned int ptrace_setoptions = PTRACE_O_TRACESYSGOOD;
    if (follow_fork) {
		ptrace_setoptions |= PTRACE_O_TRACECLONE
				          | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

        // tmap_create(DEFAULT_TMAP_MAX_SIZE);          // TODO: CLI arg
    }
    ptrace(PTRACE_SETOPTIONS, pid, 0, ptrace_setoptions);


/* (1) Trace */
    while(1) {

    /* CHECK PID ... */




    /* Syscall ENTER: Print syscall (based on retrieved syscall nr) */
        if (wait_for_syscall_or_exit(pid)) break;
        const long syscall_nr = get_reg_content(pid, REG_SYSCALL_NR);

        print_syscall(pid, syscall_nr);


    /* Stop (i.e., single step) if requested */
        if (syscall_nr == pause_on_syscall_nr) {
            wait_for_user_input();
        }


    /* Syscall EXIT (syscall return value) */
        if (wait_for_syscall_or_exit(pid)) break;
        const long syscall_rtn_val = get_reg_content(pid, REG_SYSCALL_RTN_VAL);
        fprintf(stderr, "%ld\n", syscall_rtn_val);
    }

    return 0;
}

void print_syscall(pid_t pid, long syscall_nr) {
    fprintf(stderr, "%s(", get_syscall_name(syscall_nr));
    print_syscall_args(pid, syscall_nr);
    fprintf(stderr, ") = ");
}

void wait_for_user_input(void) {
    int c;
    while ( '\n' != (c = getchar()) && EOF != c ) {} // wait until user presses enter to continue
}

bool wait_for_syscall_or_exit(pid_t pid) {
    int sig = 0;
    siginfo_t si;

    while (1) {
    /* (0) Restart stopped tracee but set next breakpoint (on next syscall)   (AND "forward" received signal to tracee)
     *   ELUCIDATION:
     *     - `PTRACE_SYSCALL`: Restarts stopped tracee (similar to `PTRACE_CONT`),
     *                         but sets breakpoint at next syscall entry/exit
     *                         (Tracee will, as usual, be stopped upon receipt of a signal)
     *                         From the tracer's perspective, the tracee will appear to have
     *                         been stopped by receipt of a `SIGTRAP`
     *
     *     - Signal delivery:  Normally, when a (possibly multithreaded) process receives any signal (except
     *                         `SIGKILL`), the kernel selects an arbitrary thread which handles the signal.
     *                         (If the signal is generated w/ `tgkill`(2), the target thread can be
     *                         explicitly selected by the caller.)
     *
     *                         However, if the selected thread is traced, it enters signal-delivery-stop.
     *                         At this point, the signal is NOT YET delivered to the process, and can be
     *                         suppressed by the tracer. If the tracer doesn't suppress the signal, it
     *                         passes the signal to the tracee in the next ptrace restart request.
     */
        DIE_WHEN_ERRNO(ptrace(PTRACE_SYSCALL, pid, 0, sig));

        /* Reset restart signal & pid */
        sig = 0;
        pid = -1;


    /* (1) Wait (i.e., block) for ANY tracee to change state (stops or terminates) */
        int status;
        pid_t tracee_waited = DIE_WHEN_ERRNO(waitpid(-1, &status, __WALL));


    /* (2) Check tracee's process status */
        /* (2.1) Possibility 1: Tracee was stopped
         *   - Possible reasons:
         *     (I)   Syscall-enter-/-exit-stop      => `stopsig == (SIGTRAP | PTRACE_TRAP_INDICATOR_BIT)`
         *     (II)  `PTRACE_EVENT_xxx` stops       => `stopsig == SIGTRAP`
         *     (III) Group-stops
         *     (IV)  Signal-delivery stops
         *   - Which are all reported by `waitpid`(2) w/ `WIFSTOPPED(status)` being true
         *   - They may be differentiated by examining the value status>>8, and if
         *     there's ambiguity in that value, by querying PTRACE_GETSIGINFO
         *     (Note: `WSTOPSIG(status)` can't be used to perform this
         *      examination, b/c it returns the value (status>>8) & 0xff)
         *
         * ELUCIDATION:
         *   - `int WIFSTOPPED (int status)`: Returns nonzero value if child is stopped
         *     - `int WSTOPSIG (int status)`: Returns signal number of signal that caused child to stop if `WIFSTOPPED` (passed in as `status` arg) is true
         */
        if (WIFSTOPPED(status)) {
            pid = tracee_waited;
            const int stopsig = WSTOPSIG(status);

            /* (I) Syscall-enter-/-exit-stop
             *     Condition: `waitpid`(2) returns w/ `WIFSTOPPED(status)` true, and
             *                `WSTOPSIG(status)` gives the value `(SIGTRAP | 0x80)`)
             *                (due to by tracer set `PTRACE_O_TRACESYSGOOD` option))
             */
            if ((SIGTRAP | PTRACE_TRAP_INDICATOR_BIT) == stopsig) {
                // XXX TODO: return child_waited; XXX
                return false;       /* Child was stopped (due to syscall breakpoint) -> extract syscall info */

            /* (II) `PTRACE_EVENT_xxx` stops
             *      Condition: `waitpid`(2) returns w/ `WIFSTOPPED(status)` true, and
             *                 `WSTOPSIG(status)` returns `SIGTRAP`)
             */
            } else if (SIGTRAP == stopsig) {
                // ... Check for ptrace-events here ...

            /* (III) Group-stops
             *    ELUCIDATION:
             *      - `PTRACE_GETSIGINFO`: Retrieve information about the signal that
             *                             caused the stop; copies a `siginfo_t` structure
             *                             from the tracee to the address data in the tracer
             */
            } else if (ptrace(PTRACE_GETSIGINFO, tracee_waited, 0, &si) < 0) {
                // ...

            /*
             * (IV) Signal-delivery stops
             */
            } else {
                sig = stopsig;
            }


        /* (2.2) Possibility 2: Child terminated
         *   - Possible reasons:
         *     (I)   Child exited w/ `exit`     (check via `WIFEXITED(status)`)
         *     (II)  Child exited due to signal (check via `WIFSIGNALED(status)`)
         */
        } else {
            return true;
        }
    }
}
