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
#include <stdatomic.h>


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
static atomic_int _shared_mem_test_bytes_writen;   // Global for testing shared memory (only feasible when `CLONE_VM` was set)     (no volatile keyword necesssary (even w/ -O3) ??)


static void inline _print_task_info(FILE* stream, char* tname) {
	const int pid = getpid();
	fprintf(stream, "\n[%s] >>>  tid = %d, pid (aka. thread group) = %d" /* ", ppid = %d, pgid = %d, sid = %d" */ "  <<<\n\n",
              tname, gettid(), pid /*, getppid(), getpgrp(), getsid(pid) */ );
}


/**
 * @brief Tracee's routine (may either be "parent" or "child" (in the ptrace context))
 *
 * @param arg N/A
 * @return int N/A (never returns)
 */
int tracee_routine(void *arg) {
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

    return 0;
}


/**
 * @brief "Inspects" tracee every 1s, printing the current IP-address + current stackframe
 *
 * @param arg Pointer to tracee's tid
 * @return int Exit status
 */
int do_tracer(void* arg) {
    const pid_t tracee_tid = *((pid_t*)arg);

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



static void inline _perform_clone(int (*fn)(void *), void* stack, int flags, void* arg, pid_t* parent_tid) {
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
    if (-1 == clone(fn, stack, flags, arg, parent_tid)) {
        perror("failed to spawn child task");
        exit(1);
    }
}

int main(int argc, char** argv) {
    const bool switch_roles = (2 == argc && !strcmp("--switch-roles", argv[1]));


    #define CHILD_STACK_SIZE (1024 * 1024)            // this number is arbitrary - find a better one.

/* -- 0. Setup: Child's stack -- */
    void *child_stack = malloc(CHILD_STACK_SIZE);
    if (!child_stack) {
      perror("malloc for child's stack");
      return 1;
    }


/* - 1. Launch tracer & tracee (!! IMPORANT: Order matters !!) - */
    int clone_flags = CLONE_VM |   /* $$$ TODO: Following flags necessary $$$ ?? */   CLONE_FILES | CLONE_FS | CLONE_IO;        // TESTING (AS THREAD; CHECK via `sysctl kernel.yama.ptrace_scope` (`echo "0" | sudo tee /proc/sys/kernel/yama/ptrace_scope`)):  CLONE_SIGHAND | CLONE_VM | CLONE_THREAD


    if (!switch_roles) {
    /* >>  Default: "Child" (task reulting from `clone`(2)) = tracee, "Parent" = tracer  << */
      fputs(">>> Tracing roles: \"Parent\" = tracer, \"Child\" = tracee <<<\n\n\n", stdout);


      int (*clone_fn)(void*) = tracee_routine;

      pid_t tracee_tid;
      void* clone_arg = NULL;
      pid_t* clone_parent_tid = &tracee_tid;
      clone_flags |= CLONE_PARENT_SETTID;


      _perform_clone(clone_fn, child_stack + CHILD_STACK_SIZE, clone_flags, clone_arg, clone_parent_tid);
      do_tracer(&tracee_tid);
    } else {
    /* >>  Switched roles: "Child" (task reulting from `clone`(2)) = tracer, "Parent" = tracee   !!!  REQUIRES CURRENTLY kernel.yama.ptrace_scope=0 !!!  << */
      fputs(">>> Tracing roles: \"Parent\" = tracee, \"Child\" = tracer <<<\n\n\n", stdout);

    /* Allow non-root child (= tracer) to trace parent (= tracee)   (ONLY PERTINENT when Yama ptrace_scope = 1 AND `PTRACE_ATTACH` is used) */
      prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);

      int (*clone_fn)(void*) = do_tracer;

      pid_t tracee_tid = gettid();
      void* clone_arg = &tracee_tid;
      pid_t* clone_parent_tid = NULL;


      _perform_clone(clone_fn, child_stack + CHILD_STACK_SIZE, clone_flags, clone_arg, clone_parent_tid);
      tracee_routine(NULL);
    }


    return 0;
}
