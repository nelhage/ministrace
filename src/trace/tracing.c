#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "internal/ptrace_utils.h"
#include "internal/syscalls.h"

#include "tracing.h"

#ifdef WITH_STACK_UNWINDING
#  include "internal/unwind.h"
#endif

#include "../common/error.h"


/* -- Global consts -- */
#define PTRACE_TRAP_INDICATOR_BIT (1 << 7)


/* -- Function prototypes -- */
int _wait_for_syscall_or_exit(pid_t tid, int *exit_status);

void _wait_for_user_input(void);



/* ----------------------------------------- ----------------------------------------- ----------------------------------------- */
int do_tracee(int argc, char **argv) {
/* exec setup: Create new array for argv of to be exec'd command */
    char *child_exec_argv[argc + 1 /* NULL terminator */];
    memcpy(child_exec_argv, argv, (argc * sizeof(argv[0])));
    child_exec_argv[argc] = NULL;
    const char* child_exec = child_exec_argv[0];

/* ELUCIDATION:
 *   - `PTRACE_TRACEME`: Starts tracing + causes next signal (sent to this
 *                       process) to stop it & notify the parent(via `wait`),
 *                       so that the parent knows to start tracing
 */
    ptrace(PTRACE_TRACEME);
/* Stop oneself so parent can set tracing option + Parent will see exec syscall */
    kill(getpid(), SIGSTOP);
/* Execute actual program */
    return execvp(child_exec, child_exec_argv);

/* Error handling (in case `execvp` failed) */
    LOG_ERROR_AND_EXIT("Couldn't exec \"%s\"", child_exec);
}


/* -- Tracing -- */
int do_tracer(const pid_t tracee_pid,
              const bool attach_to_tracee,
              const long pause_on_syscall_nr, const bool follow_fork
#ifdef WITH_STACK_UNWINDING
            , const bool print_stacktrace
#endif /* WITH_STACK_UNWINDING */
) {
    /* Disable IO buffering for accurate output */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);


/* 0a. Setup: Wait until child stops */
    if (attach_to_tracee) {
        /*
         * ELUCIDATION:
         *  - `PTRACE_ATTACH`: Attach to process specified by `pid`
         *                     (making it a tracee of the calling process)
         *                     The tracee is sent a `SIGSTOP`, but
         *                     will not necessarily have stopped by the
         *                     completion of this call => hence, use `waitpid`(2)
         */
        DIE_WHEN_ERRNO(ptrace(PTRACE_ATTACH, tracee_pid));          /* For required permissions, see https://www.kernel.org/doc/Documentation/security/Yama.txt */
    }

    int status;
    do {
        DIE_WHEN_ERRNO(waitpid(tracee_pid, &status, 0));
    } while(!WIFSTOPPED(status));

    /*
     * ELUCIDATION:
     *  - `WIFSTOPPED`: Returns nonzero value if child process is stopped
     */
    if (!WIFSTOPPED(status)) {
        LOG_ERROR_AND_EXIT("Couldn't stop child process");
    }


/* 0b. Setup: Set ptrace options */
    /*
     * ELUCIDATION:
     *   - `PTRACE_O_TRACESYSGOOD`: Sets bit 7 in the signal number when delivering syscall traps
     *                              (i.e., deliver `SIGTRAP|0x80`) (see `PTRACE_TRAP_INDICATOR_BIT`)
     *                              Makes it easier (for tracer) to distinguish b/w normal- & from syscalls caused traps
     *
     *   - `PTRACE_O_TRACECLONE`:   Stop the tracee at next `clone(2)` and automatically start tracing
     *                              the newly cloned process, which will start w/ a SIGSTOP;
     *                              `waitpid(2)` by the tracer will return a status value such that
     *                              `status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))`
     */
    unsigned int ptrace_setoptions = PTRACE_O_TRACESYSGOOD;
    if (follow_fork) {
        ptrace_setoptions |= PTRACE_O_TRACECLONE
                             | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    }
    ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, ptrace_setoptions);


#ifdef WITH_STACK_UNWINDING
    if (print_stacktrace) {
        unwind_init();
    }
#endif /* WITH_STACK_UNWINDING */


/* 1. Trace */
    int tracee_exit_status = -1;
    pid_t cur_tid = tracee_pid;
    while(1) {
        /* Wait for a child to change state (stop or terminate) */
        const pid_t status_tid = _wait_for_syscall_or_exit(cur_tid, &tracee_exit_status);

        /* Check status */
        /*   -> Thread terminated (indicated via negative int) */
        if (0 > status_tid) {
            if (-(tracee_pid) == status_tid) {
                fprintf(stderr, "\n+++ [%d] (parent) terminated +++\n", -(status_tid));
                break;
            } else {
                fprintf(stderr, "\n+++ [%d] (child) terminated +++\n", -(status_tid));

                cur_tid = -1;
                continue;
            }

        /*   -> Thread stopped (i.e., hit breakpoint; indicated via positive int) */
        } else {
            cur_tid = status_tid;

            struct user_regs_struct_full regs;
            ptrace_get_regs_content(cur_tid, &regs);

            const long syscall_nr = SYSCALL_REG_CALLNO(regs);

            const char* scall_name = NULL;
            if (!(scall_name = syscalls_get_name(syscall_nr))) {
                LOG_DEBUG("Unknown syscall w/ nr %ld", syscall_nr);
                static char fallback_generic_syscall_name[128];
                snprintf(fallback_generic_syscall_name, sizeof(fallback_generic_syscall_name), "sys_%ld", syscall_nr);
                scall_name = fallback_generic_syscall_name;
            }

            /* >> Syscall ENTER: Print syscall-nr + -args << */
            if (!SYSCALL_RETED(regs)) {
                // LOG_DEBUG("%d:: SYSCALL_ENTER ...", status_tid);

                if (follow_fork) {
                    fprintf(stderr, "\n[%d] ", cur_tid);
                }
                fprintf(stderr, "%s(", scall_name);
                syscalls_print_args(cur_tid, &regs);
                fprintf(stderr, ")");

                /* OPTIONAL: Stop (i.e., single step) if requested */
                if (syscall_nr == pause_on_syscall_nr) {
                    _wait_for_user_input();
                }

            /* >> Syscall EXIT: Print syscall return value (+ optionally stacktrace) << */
            } else {
                // LOG_DEBUG("%d:: SYSCALL_EXIT ...", status_tid);

                if (follow_fork) {      /* For task identification (in log) when following `clone`s */
                    fprintf(stderr, "\n... [%d - %s (%d)]",
                            cur_tid, scall_name, cur_tid);
                }
                const long syscall_rtn_val = SYSCALL_REG_RETURN(regs);
                fprintf(stderr, " = %ld\n", syscall_rtn_val);

#ifdef WITH_STACK_UNWINDING
                if (print_stacktrace) {
                    unwind_print_backtrace_of_pid(cur_tid);
                }
#endif /* WITH_STACK_UNWINDING */
            }
        }
    }


#ifdef WITH_STACK_UNWINDING
    if (print_stacktrace) {
        unwind_fin();
    }
#endif /* WITH_STACK_UNWINDING */


    return tracee_exit_status;
}

void _wait_for_user_input(void) {
    int c;
    while ( '\n' != (c = getchar()) && EOF != c ) {} // wait until user presses enter to continue
}

int _wait_for_syscall_or_exit(pid_t tid, int *exit_status) {
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
        if (-1 != tid) {        /* Allow function to ONLY WAIT (e.g., when prior child terminated) */
            DIE_WHEN_ERRNO(ptrace(PTRACE_SYSCALL, tid, 0, sig));
        }

        /* Reset restart signal */
        sig = 0;


        /* (1) Wait (i.e., block) for ANY tracee to change state (stops or terminates) */
        /* ELUCIDATION:
         *   - `__WALL`: Wait for all children, regardless of type (`clone` or non-`clone`)
         *               See also https://kernelnewbies.kernelnewbies.narkive.com/9Zd9eWeb/waitpid-2-and-clone-thread
         */
        int status;
        pid_t wait_tid = DIE_WHEN_ERRNO(waitpid(-1, &status, __WALL));


        /* (2) Check tracee's process status */
        /* (2.1) Possibility 1: Tracee was stopped
         *   - Possible reasons:
         *     (I)   Syscall-enter-/-exit-stop      => `stopsig == (SIGTRAP | PTRACE_TRAP_INDICATOR_BIT)`
         *     (II)  `PTRACE_EVENT_xxx` stops       => `stopsig == SIGTRAP`
         *     (III) Group-stops
         *     (IV)  Signal-delivery stops
         *   - Which are all reported by `waitpid`(2) w/ `WIFSTOPPED(status)` being true
         *   - They may be differentiated by examining the value `status>>8`, and if
         *     there's ambiguity in that value, by querying `PTRACE_GETSIGINFO`
         *     (Note: `WSTOPSIG(status)` can't be used to perform this
         *      examination, b/c it returns the value `(status>>8) & 0xff`)
         *
         * ELUCIDATION:
         *   - `int WIFSTOPPED (int status)`: Returns nonzero value if child is stopped
         *     - `int WSTOPSIG (int status)`: Returns signal number of signal that caused child to stop if `WIFSTOPPED` (passed in as `status` arg) is true
         */
        if (WIFSTOPPED(status)) {
            tid = wait_tid;
            const int stopsig = WSTOPSIG(status);

            /* (I) Syscall-enter-/-exit-stop
             *     Condition: `waitpid`(2) returns w/ `WIFSTOPPED(status)` true, and
             *                `WSTOPSIG(status)` gives the value `(SIGTRAP | 0x80)`)
             *                (due to by tracer set `PTRACE_O_TRACESYSGOOD` option))
             */
            if ((SIGTRAP | PTRACE_TRAP_INDICATOR_BIT) == stopsig) {
                return wait_tid;       /* Child was stopped (due to syscall breakpoint) -> get syscall info */

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
            } else if (ptrace(PTRACE_GETSIGINFO, wait_tid, 0, &si) < 0) {
                // ...

            /*
             * (IV) Signal-delivery stops
             */
            } else {
                fprintf(stderr, "\n+++ [%d] received (not delivered yet) signal \"%s\" +++\n", tid, strsignal(stopsig));
                sig = stopsig;
            }


        /* (2.2) Possibility 2: Child terminated
         *   - Possible reasons:
         *     (I)   Child exited w/ `exit`     (check via `WIFEXITED(status)`)
         *     (II)  Child exited due to signal (check via `WIFSIGNALED(status)`)
         */
        } else {
            if (WIFEXITED(status)) {
                *exit_status = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                *exit_status = WTERMSIG(status);
            }

            return -(wait_tid);
        }
    }
}
