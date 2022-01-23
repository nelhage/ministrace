/* How to trace using a "thread-like" relationship (shared VM (except stack)) b/w tracer & tracee
 *   Scenario:     Tracer interrupts tracee every sec to check the current IP + stackframe
 *   OG code:      https://stackoverflow.com/a/30092189
 *
 *   Infos (regarding thread tracing thread): https://yarchive.net/comp/linux/ptrace_self_attach.html
 *      Prior patch (< 2.6.14): Tracing child threads from the parent thread as well as tracing
 *                   siblings and parent threads from a child was still feasible
 *      Reason:      Local DoS attack, where you could either force an oops or a unkillable process
 *      Since patch: Can't ptrace your own thread group
 *                   (ptrace parent is forced to behave more like a "real parent" - who also cannot be
 *                   in the same thread group)
 *      Workaround:  The debugging thread can do a "vfork()" or a direct "clone(CLONE_VFORK|CLONE_MM)"
 *                   to have a new thread that is in a _different_ thread group, but is able to ptrace
 *                   and also is "synchronized" with the VM, simply b/c it shares it with all the other
 *                   threads it might want to debug
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>


/* ------------------ ------------------  ptrace stuff ------------------ ------------------ */
/* ----------- amd64 ----------- */
#if defined(__x86_64__)

/* - Types - */
#  define user_regs_struct_full user_regs_struct

/* - Macros for accessing registers (and other information) in `user_regs_struct` - */
#  define USER_REGS_STRUCT_IP(user_struct) (user_struct.rip)
#  define USER_REGS_STRUCT_SP(user_struct) (user_struct.rsp)


/* ----------- arm64 ----------- */
#elif defined(__aarch64__)

/* - Types - */
struct user_regs_struct_full {
  __extension__ union {                  /* `__extension__` to disable anonymous struct/union warning */
    struct user_regs_struct user_regs;   /* Required to ensure correct alignment ?? */
    struct {                             /* Use anonymous union + -struct to access elements as if they were direct members of `user_regs_struct_full` struct */
      unsigned long long regs[31];       /* x0 - x30 */
      unsigned long long sp;
      unsigned long long pc;
      unsigned long long pstate;         /* cpsr */
    };
  };
};

/* - Macros for accessing registers (and other information) in `user_regs_struct` - */
#  define USER_REGS_STRUCT_IP(user_struct) (user_struct.pc)
#  define USER_REGS_STRUCT_SP(user_struct) (user_struct.sp)


#else

#  error "Unsupported CPU arch"

#endif


int ptrace_get_regs_content(pid_t tid, struct user_regs_struct_full *regs) {
  struct iovec iov = {
    .iov_base = regs,
    .iov_len = sizeof (struct user_regs_struct_full),
  };
  errno = 0;
  ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov);
  return errno ? -1 : 0;
}
/* ------------------ ------------------  ptrace stuff ------------------ ------------------ */


/* -- Globals -- */
static int _shared_mem_test_bytes_writen;   // Global for testing shared memory (only feasible when `CLONE_VM` was set)     (no volatile keyword necesssary (even w/ -O3) ??)


static void inline _print_task_info(FILE* stream, char* tname) {
	const int pid = getpid();
	fprintf(stream, "\n[%s] >>>  tid = %d, pid (aka. thread group) = %d" /* ", ppid = %d, pgid = %d, sid = %d" */ "  <<<\n\n",
              tname, gettid(), pid /*, getppid(), getpgrp(), getsid(pid) */ );
}


void run_tracee_busy_loop(void) {
    _print_task_info(stdout, "tracee");

    FILE* voiiid = fopen("/dev/null", "w");
    if (!voiiid) {
      perror("Error opening /dev/null");
      exit(1);
    }
  /* Busy loop for tracee -> must consist of function calls of same call duration   (otherwise IP won't seem to change for tracer) */
    while (1) {
        _shared_mem_test_bytes_writen = 0;
        _shared_mem_test_bytes_writen += fprintf(voiiid, "Hello");
        _shared_mem_test_bytes_writen += fprintf(voiiid, " from");
        _shared_mem_test_bytes_writen += fprintf(voiiid, " tracee!");
        _shared_mem_test_bytes_writen += fprintf(voiiid, "      \n");
    }
}



static void _perform_clone(int (*fn)(void *), void* fn_arg) {
    #define CHILD_STACK_SIZE (1024 * 1024)            // this number is arbitrary - find a better one.

/* -- 0. Setup: Child's stack -- */
    void* child_stack = malloc(CHILD_STACK_SIZE);
    if (!child_stack) {
      perror("malloc for child's stack");
      exit(1);
    }

    int clone_flags = CLONE_VM |   /* $$$ TODO: Following flags necessary $$$ ?? */   CLONE_FILES | CLONE_FS | CLONE_IO;

    /*
     * `clone`(2): Create a new ("child") process, in a manner similar to fork(2)
     *             (but provides more precise control over what pieces of execution
     *             context are shared b/w the calling process & the child process)
     *    Args:
     *      - `int (*fn)(void *)`: New task's routine (or simply function to be executed by new task)
     *      - `void *stack`:       Topmost address of the memory space set up for the child stack (since stack grows downwards on Linux)
     *      - `int flags`:
     *        - `CLONE_PARENT_SETTID`: Store the child thread ID at the location pointed
     *                                to by `parent_tid` (here `tracee_tid`)
     *        - `CLONE_FILES`:         Calling process & child process share the same
     *                                 fildes table
     *        - `CLONE_FS`:            Caller & child process share the same filesystem
     *                                 information (includes the root of the fs, the cwd,
     *                                 and the umask)
     *        - `CLONE_IO`:            New process shares an I/O context w/ calling process
     *        - `CLONE_VM`:            Calling process & child process run in same memory space
     *      - `void *arg`:         Args to be passed into new task's routine
     *      - `pid_t *parent_tid`: ???
     */
    if (-1 == clone(fn, child_stack + CHILD_STACK_SIZE, clone_flags, fn_arg)) {
        perror("failed to spawn child task");
        exit(1);
    }
}



/**
 * @brief Tracer: "Inspects" tracee every 1s, printing the current IP-address + current stackframe
 *
 * @param arg_tracee_tid Pointer to tracee's tid
 * @return int Exit status
 */
int grandchild_routine(void* arg_tracee_tid) {
    /*
		 * Make parent go away.
		 * Also makes grandparent's wait() unblock.
		 */
		kill(getppid(), SIGKILL);


    const pid_t tracee_tid = *((pid_t*)arg_tracee_tid);

    _print_task_info(stderr, "tracer");
    fprintf(stderr, "[tracer] >>>  Target (= tracee): %d  <<<\n\n", tracee_tid);


/* -- Attach to tracee -- */
    /* `PTRACE_SEIZE`: Attach to the process specified in pid, making
     *                 it a tracee of the calling process
     *                 Doesn't stop the process (unlike `PTRACE_ATTACH`)
     */
    if (-1 == ptrace(PTRACE_SEIZE, tracee_tid, NULL, NULL)) {
        perror("failed monitor seize");
        exit(1);
    }
/* -- Attach to tracee -- */


    fputs("[tracer] >>>  Beginning monitoring ...  <<<\n\n", stderr);

    while (1) {
        sleep(1);

        if (-1 == ptrace(PTRACE_INTERRUPT, tracee_tid, NULL, NULL)) {
            perror("[tracer] failed to interrupt main thread");
            break;
        }
        int status;
        if (-1 == waitpid(tracee_tid, &status, __WCLONE)) {
            perror("[tracer] target wait failed");
            break;
        }
        if (!WIFSTOPPED(status)) { // this section is messy. do it better.
            fputs("[tracer] target wait went wrong", stderr);
            break;
        }
        if ((status >> 8) != (SIGTRAP | PTRACE_EVENT_STOP << 8)) {
            fputs("[tracer] target wait went wrong (2)", stderr);
            break;
        }

    /* - Print tracee status - */
        struct user_regs_struct_full user_regs_struct;
        if (-1 == ptrace_get_regs_content(tracee_tid, &user_regs_struct)) {
          fputs("[tracer] failed to read registers", stderr);
          break;
        }
        fprintf(stderr, "[tracer] %ld    IP=0x%llx SP=0x%llx\n",
                time(NULL), USER_REGS_STRUCT_IP(user_regs_struct), USER_REGS_STRUCT_SP(user_regs_struct));
        fprintf(stderr, "[tracer]  > Tracee wrote currently %d bytes to a stream\n", _shared_mem_test_bytes_writen);      // Testing shared memory
        fputs("\n", stderr);
    /* - Print tracee status - */

        if (-1 == ptrace(PTRACE_CONT, tracee_tid, NULL, NULL)) {
            perror("[tracer] failed to resume main thread");
            break;
        }
    }

    return 1;
}


int child_routine(void* arg_tracee_tid) {
    _perform_clone(grandchild_routine, arg_tracee_tid);

    /*
     * Wait for grandchild to attach to straced process
	   * (grandparent). Grandchild SIGKILLs us after it attached.
	   * Grandparent's wait() is unblocked by our death,
	   * it proceeds to exec the straced program.
	   */
	  pause();
	  _exit(0); /* paranoia */

    return 0;
}



int main(void) {
  /* Allow non-root child (= tracer) to trace parent (= tracee)   (ONLY PERTINENT when Yama ptrace_scope = 1 AND `PTRACE_ATTACH` is used) */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);


    pid_t tracee_tid = gettid();
/* -- Tracer  (grandchild) -- */
    _perform_clone(child_routine, &tracee_tid);


/* -- Tracee  (parent) -- */
  /* `kill`(2) sent from grandchild (= tracer) to child will wake us up   -> `wait`(2) & reap child  */
    /* we depend on SIGCHLD set to SIG_DFL by init code */
    /* if it happens to be SIG_IGN'ed, wait won't block */
    while (wait(NULL) < 0 && EINTR == errno);

    run_tracee_busy_loop();


    return 0;
}
