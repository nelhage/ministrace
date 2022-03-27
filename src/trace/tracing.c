#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
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
static int wait_for_syscall_or_exit(pid_t tid, int *exit_status);
static void wait_for_user_input(void);


/* -- Functions -- */
int do_tracee(int argc, char** argv,
              tracer_options_t* tracer_options) {
/* exec setup: Create new array for argv of to be exec'd command */
    char *tracee_exec_argv[argc + 1 /* NULL terminator */];     /* Use VLA (instead of `malloc`(3)) */
    memcpy(tracee_exec_argv, argv, (argc * sizeof(argv[0])));
    tracee_exec_argv[argc] = NULL;

    if (!tracer_options->daemonize) {
        /* ELUCIDATION:
         *   - `PTRACE_TRACEME`: Starts tracing + causes next signal (sent to this
         *                       process) to stop it & notify the parent(via `wait`),
         *                       so that the parent knows to start tracing
         */
        DIE_WHEN_ERRNO( ptrace(PTRACE_TRACEME) );

        /* Stop oneself so tracer can set ptrace options (+ tracer will see the `exec` syscall)
         *    -> Tracer will resume execution w/ `PTRACE_SYSCALL`
         */
        DIE_WHEN_ERRNO( kill(getpid(), SIGSTOP) );
    }

    else {
    /* Allow non-root child (= tracer) to trace parent (= tracee)   (ONLY PERTINENT when Yama ptrace_scope = 1 AND `PTRACE_ATTACH` is used) */
        DIE_WHEN_ERRNO( prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) );

    /* `kill`(2) sent from grandchild (= tracer) to child will wake us up   -> `wait`(2) & reap child  */
        /* we depend on SIGCHLD set to SIG_DFL by init code */
        /* if it happens to be SIG_IGN'ed, wait won't block */
        while (wait(NULL) < 0 && EINTR == errno);
    }

/* Execute actual program */
    return execvp(tracee_exec_argv[0], tracee_exec_argv);
    LOG_ERROR_AND_EXIT("Exec'ing \"%s\" failed (errno=%d)", tracee_exec_argv[0], errno);
}


/* - Tracing - */
int do_tracer(tracer_options_t* options) {
    if (options->daemonize) {
		const pid_t pid = DIE_WHEN_ERRNO( fork() );
    /* parent */
		if (pid) {
			/*
			 * Wait for grandchild to attach to straced process
			 * (grandparent). Grandchild SIGKILLs us after it attached.
			 * Grandparent's wait() is unblocked by our death,
			 * it proceeds to exec the straced program.
			 */
			pause();
			_exit(0); /* paranoia */
		}

    /* grandchild   (will be tracer) */
        /*
		 * Make parent go away.
		 * Also makes grandparent's wait() unblock.
		 */
		kill(getppid(), SIGKILL);
    }

    const pid_t tracee_pid = options->tracee_pid;

    /* Disable IO buffering for accurate output */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);


    if (options->attach_to_tracee || options->daemonize) {
        /* ELUCIDATION:
         *  - `PTRACE_ATTACH`: Attach to process specified by `pid`
         *                     (making it a tracee of the calling process)
         *                     The tracee is sent a `SIGSTOP`, but
         *                     will not necessarily have stopped by the
         *                     completion of this call => hence, use `waitpid`(2)
         */
        DIE_WHEN_ERRNO( ptrace(PTRACE_ATTACH, tracee_pid) );
    }
    /* ELSE: tracee (= child) did `PTRACE_TRACEME`, hence, nothing to do in tracer (= parent)  */

/* 0a. Setup: Wait until child stops
 *     Either already stopped by previous `PTRACE_ATTACH` or by itself
 */
    /* ELUCIDATION:
     *  - `WIFSTOPPED`: Returns nonzero value if child process is stopped
     */
    int tracee_status;
    do {
        DIE_WHEN_ERRNO( waitpid(tracee_pid, &tracee_status, 0) );
    } while (!WIFSTOPPED(tracee_status));

/* 0b. Setup: Set ptrace options */
    /* ELUCIDATION:
     *   - `PTRACE_O_TRACESYSGOOD`: Sets bit 7 in the signal number when delivering syscall traps
     *                              (i.e., deliver `SIGTRAP|0x80`) (see `PTRACE_TRAP_INDICATOR_BIT`)
     *                              Makes it easier (for tracer) to distinguish b/w normal- & from syscalls caused traps
     *
     *   - `PTRACE_O_TRACECLONE`:   Stop the tracee at next `clone(2)` and automatically start tracing
     *                              the newly cloned process, which will start w/ a SIGSTOP;
     *                              `waitpid(2)` by the tracer will return a status value such that
     *                              `status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))`
     */
    DIE_WHEN_ERRNO( ptrace(PTRACE_SETOPTIONS,
                           tracee_pid,
                           0,
                           PTRACE_O_TRACESYSGOOD | ((options->follow_fork) ?
                                (PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) :
                                (0))) );

#ifdef WITH_STACK_UNWINDING
    if (options->print_stacktrace) {
        unwind_init();
    }
#endif /* WITH_STACK_UNWINDING */


/* 1. Trace */
    int tracee_exit_status = -1;
    pid_t cur_tid = tracee_pid;
    while (1) {
        /* Wait for a child to change state (stop or terminate) */
        const pid_t status_tid = wait_for_syscall_or_exit(cur_tid, &tracee_exit_status);

        /* Check status */
        /*   -> Thread terminated (indicated via negative int) */
        if (0 > status_tid) {
            fprintf(stderr, "\n+++ [%d] terminated w/ %d +++\n", -(status_tid), tracee_exit_status);

            if (-(tracee_pid) == status_tid) {
                break;
            } else {
                cur_tid = -1;
                continue;
            }

        /*   -> Thread stopped (i.e., hit breakpoint; indicated via positive int) */
        } else {
            cur_tid = status_tid;

            struct user_regs_struct_full regs;
            ptrace_get_regs_content(cur_tid, &regs);

            const long syscall_nr = USER_REGS_STRUCT_SC_NO(regs);
            if (NO_SYSCALL == syscall_nr ||                                /* "Trap" was, e.g., a signal */
                (options->syscall_subset_to_be_traced &&
                 !(options->syscall_subset_to_be_traced[syscall_nr]))) {   /* Current "trapped" syscall shall not be traced */
                continue;
            }

            const char* scall_name = NULL;
            if (!(scall_name = syscalls_get_name(syscall_nr))) {
                LOG_WARN("Unknown syscall w/ nr=%ld", syscall_nr);
                static char fallback_generic_syscall_name[128];
                snprintf(fallback_generic_syscall_name, sizeof(fallback_generic_syscall_name), "sys_%ld", syscall_nr);
                scall_name = fallback_generic_syscall_name;
            }

            /* >> Syscall ENTER: Print syscall-nr + -args << */
            if (!USER_REGS_STRUCT_SC_HAS_RTNED(regs)) {
                // LOG_DEBUG("%d:: SYSCALL_ENTER ...", status_tid);

                if (options->follow_fork) {
                    fprintf(stderr, "\n[%d] ", cur_tid);
                }
                fprintf(stderr, "%s(", scall_name);
                syscalls_print_args(cur_tid, &regs);
                fprintf(stderr, ")");

                /* OPTIONAL: Stop (i.e., single step) if requested */
                if (syscall_nr == options->pause_on_syscall_nr) {
                    wait_for_user_input();
                }

            /* >> Syscall EXIT: Print syscall return value (+ optionally stacktrace) << */
            } else {
                // LOG_DEBUG("%d:: SYSCALL_EXIT ...", status_tid);

                if (options->follow_fork) {      /* For task identification (in log) when following `clone`s */
                    fprintf(stderr, "\n... [%d - %s (%d)]",
                            cur_tid, scall_name, cur_tid);
                }
                const long syscall_rtn_val = USER_REGS_STRUCT_SC_RTNVAL(regs);
                fprintf(stderr, " = %ld\n", syscall_rtn_val);

#ifdef WITH_STACK_UNWINDING
                if (options->print_stacktrace) {
                    unwind_print_backtrace_of_tid(cur_tid);
                }
#endif /* WITH_STACK_UNWINDING */
            }
        }
    }

#ifdef WITH_STACK_UNWINDING
    if (options->print_stacktrace) {
        unwind_fin();
    }
#endif /* WITH_STACK_UNWINDING */

    fprintf(stderr, "+++ exited w/ %d +++\n", tracee_exit_status);
    return tracee_exit_status;
}


static void wait_for_user_input(void) {
    int c;
    while ('\n' != (c = getchar()) && EOF != c) { }     /* Wait until user presses enter to continue */
}

static int wait_for_syscall_or_exit(pid_t tid, int *exit_status) {
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
            DIE_WHEN_ERRNO( ptrace(PTRACE_SYSCALL, tid, 0, sig) );
        }

        /* Reset restart signal */
        sig = 0;


        /* (1) Wait (i.e., block) for ANY tracee to change state (stops or terminates) */
        /* ELUCIDATION:
         *   - `__WALL`: Wait for all children, regardless of type (`clone` or non-`clone`)
         *               See also https://kernelnewbies.kernelnewbies.narkive.com/9Zd9eWeb/waitpid-2-and-clone-thread
         */
        int tracee_status;
        pid_t wait_tid = DIE_WHEN_ERRNO( waitpid(-1, &tracee_status, __WALL) );


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
        if (WIFSTOPPED(tracee_status)) {
            tid = wait_tid;
            const int stopsig = WSTOPSIG(tracee_status);

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
            if (WIFEXITED(tracee_status)) {
                *exit_status = WEXITSTATUS(tracee_status);
            } else if (WIFSIGNALED(tracee_status)) {
                *exit_status = WTERMSIG(tracee_status);
            }

            return -(wait_tid);
        }
    }
}
