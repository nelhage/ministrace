// Compile: g++ ptrace_multi_threaded_demo.cpp -o test -lpthread
// Source: https://github.com/aleden/ptrace-multi-threaded-demo
#include <unordered_map>
#include <asm/unistd.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <array>
#include <thread>
#include <mutex>
#include <sys/syscall.h>
#include <string.h>

using namespace std;


static int do_child(int argc, char **argv);

static const char* name_of_syscall_number(int);
static const char* name_of_signal_number(int);

enum SYSCALL_STATE { SYSCALL_ENTERED, SYSCALL_EXITED };
struct child_syscall_state_t {
  SYSCALL_STATE st;
  int no;
};

static void toggle_syscall_state(child_syscall_state_t& st) {
  st.st = (st.st == SYSCALL_ENTERED ? SYSCALL_EXITED : SYSCALL_ENTERED);
}

static std::unordered_map<pid_t, child_syscall_state_t> chld_sysc_map;



int main(int argc, char **argv) {
  fprintf(stderr, "parent: forking...\n");

  const pid_t child = fork();
  if (!child)
    return do_child(argc, argv);

  //
  // parent
  //

  //
  // Normally when a (possibly multithreaded) process receives any signal except
  // SIGKILL, the kernel selects an arbitrary thread which handles the signal.
  // (If the signal is generated with tgkill(2), the target thread can be
  // explicitly selected by the caller.)
  //
  // However, if the selected thread is traced, it enters signal-delivery-stop.
  //
  // At this point, the signal is not yet delivered to the process, and can be
  // suppressed by the tracer. If the tracer doesn't suppress the signal, it
  // passes the signal to the tracee in the next ptrace restart request.
  //

  //
  // observe the (initial) signal-delivery-stop
  //
  fprintf(stderr, "parent: waiting for initial stop of child %d...\n", child);
  int status;
  do
    waitpid(child, &status, 0);
  while (!WIFSTOPPED(status));
  fprintf(stderr, "parent: initial stop observed\n");

  //
  // select ptrace options
  //
  int ptrace_options = 0;

  // When delivering system call traps, set bit 7 in the signal number (i.e.,
  // deliver SIGTRAP|0x80). This makes it easy for the tracer to distinguish
  // normal traps from those caused by a system call. Note:
  // PTRACE_O_TRACESYSGOOD may not work on all architectures.
  ptrace_options |= PTRACE_O_TRACESYSGOOD;

  // Send a SIGKILL signal to the tracee if the tracer exits. This option is
  // useful for ptrace jailers that want to ensure that tracees can never escape
  // the tracer's control.
  ptrace_options |= PTRACE_O_EXITKILL;

  // Stop the tracee at the next clone(2) and automatically start tracing the
  // newly cloned process, which will start with a SIGSTOP, or PTRACE_EVENT_STOP
  // if PTRACE_SEIZE was used.  A waitpid(2) by the tracer will return a status
  // value such that
  //
  //  status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))
  //
  // The PID of the new process can be retrieved with PTRACE_GETEVENTMSG. This
  // option may not catch clone(2) calls in all cases.  If the tracee calls
  // clone(2) with the CLONE_VFORK flag, PTRACE_EVENT_VFORK will be delivered
  // instead if PTRACE_O_TRACEVFORK is set; otherwise if the tracee calls
  // clone(2) with the exit signal set to SIGCHLD, PTRACE_EVENT_FORK will be
  // delivered if PTRACE_O_TRACEFORK is set.
  ptrace_options |= PTRACE_O_TRACECLONE;

  //
  // set those options
  //
  fprintf(stderr, "parent: setting ptrace options...\n");
  ptrace(PTRACE_SETOPTIONS, child, 0, ptrace_options);
  fprintf(stderr, "ptrace options set!\n");







  auto wait_for_syscall_entry_or_exit = [](pid_t pid) -> pid_t {
    siginfo_t si;
    uintptr_t sig = 0;

    for (;;) {
      if (pid != -1) {
        // Restart the stopped tracee as for PTRACE_CONT, but arrange for the
        // tracee to be stopped at the next entry to or exit from a system call.
        // (The tracee will also, as usual, be stopped upon receipt of a
        // signal.) From the tracer's perspective, the tracee will appear to
        // have been stopped by receipt of a SIGTRAP. So, for PTRACE_SYSCALL,
        // the idea is to inspect the arguments to the system call at the first
        // stop, then do another PTRACE_SYSCALL and inspect the return value of
        // the system call at the second stop.
        //
        // The data argument is treated as for PTRACE_CONT; i.e. If data is
        // nonzero, it is interpreted as the number of a signal to be delivered
        // to the tracee; otherwise, no signal is delivered.  Thus, for example,
        // the tracer can control whether a signal sent to the tracee is
        // delivered or not.
        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)sig) == -1) {
          fprintf(stderr,
                  "parent: failed to ptrace(PTRACE_SYSCALL): %s\n",
                  strerror(errno));
          return -1;
        }
      }

      //
      // reset restart signal and pid
      //
      sig = 0;
      pid = -1;

      //
      // wait for a child process to stop or terminate
      //
      int status;
      pid_t child_waited = waitpid(-1, &status, __WALL);
      if (child_waited == -1) {
        fprintf(stderr, "parent: waitpid(1) failed : %s\n",
                strerror(errno));
        return -1;


      } else {
        if (WIFSTOPPED(status)) {
          //
          // the following kinds of ptrace-stops exist:
          //
          //   (1) syscall-stops
          //   (2) PTRACE_EVENT stops
          //   (3) group-stops
          //   (4) signal-delivery-stops
          //
          // they all are reported by waitpid(2) with WIFSTOPPED(status) true.
          // They may be differentiated by examining the value status>>8, and if
          // there is ambiguity in that value, by querying PTRACE_GETSIGINFO.
          // (Note: the WSTOPSIG(status) macro can't be used to perform this
          // examination, because it returns the value (status>>8) & 0xff.)
          //
          pid = child_waited;

          const int stopsig = WSTOPSIG(status);
          if (stopsig == (SIGTRAP | 0x80)) {
            //
            // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
            // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
            // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
            // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
            //
            return child_waited;

          } else if (stopsig == SIGTRAP) {
            //
            // PTRACE_EVENT stops (2) are observed by the tracer as waitpid(2)
            // returning with WIFSTOPPED(status) true, and WSTOPSIG(status)
            // returns SIGTRAP.
            //
            const unsigned int event = (unsigned int)status >> 16;
            switch (event) {
              case PTRACE_EVENT_VFORK:
                fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_VFORK)\n");
                break;

              case PTRACE_EVENT_FORK:
                fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_FORK)\n");
                break;

              case PTRACE_EVENT_CLONE: {
                pid_t new_child;
                ptrace(PTRACE_GETEVENTMSG, child_waited, 0, &new_child);
                fprintf(stderr,
                        "parent: ptrace event (PTRACE_EVENT_CLONE) [%d]\n",
                        new_child);
                break;
              }

              case PTRACE_EVENT_VFORK_DONE:
                fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_VFORK_DONE)\n");
                break;

              case PTRACE_EVENT_EXEC:
                fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_EXEC)\n");
                break;

              case PTRACE_EVENT_EXIT:
                fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_EXIT)\n");
                break;

              case PTRACE_EVENT_STOP:
                fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_STOP)\n");
                break;

              case PTRACE_EVENT_SECCOMP:
                fprintf(stderr, "parent: ptrace event (PTRACE_EVENT_SECCOMP)\n");
                break;

              default:
                fprintf(stderr, "parent: unknown ptrace event %u\n", event);
                break;
              }

          } else if (ptrace(PTRACE_GETSIGINFO, child_waited, 0, &si) < 0) {
            //
            // (3) group-stop
            //
            fprintf(stderr, "parent: group-stop [%s]\n",
                    name_of_signal_number(stopsig));

            // When restarting a tracee from a ptrace-stop other than
            // signal-delivery-stop, recommended practice is to always pass 0 in
            // sig.

          } else {
            //
            // (4) signal-delivery-stop
            //
            fprintf(stderr, "parent: signal-delivery-stop [%s]\n",
                    name_of_signal_number(stopsig));

            // deliver it
            sig = stopsig;
          }


        } else {
          //
          // the child process terminated
          //
          fprintf(stderr, "parent: child terminated\n");
        }
      }
    }
  };







  //
  // Main loop of the parent
  //
  pid_t pid = child; /* handle initial signal-delivery-stop */
  for (;;) {
    pid = wait_for_syscall_entry_or_exit(pid);
    if (pid == -1)
      break;

    child_syscall_state_t &st = chld_sysc_map[pid];
    switch (st.st) {
      case SYSCALL_ENTERED: {
        //
        // getting the syscall number
        //
        int no;

#if defined(__i386__)
        no = ptrace(PTRACE_PEEKUSER, pid,
                  __builtin_offsetof(struct user, regs.orig_eax));
#elif defined(__x86_64__)
        no = ptrace(PTRACE_PEEKUSER, pid,
                  __builtin_offsetof(struct user, regs.orig_rax));
#elif defined(__arm__)
        no = ptrace(PTRACE_PEEKUSER, pid,
                  __builtin_offsetof(struct user, regs.uregs[7]));
#else
#error "unknown architecture"
#endif

        st.no = no;
        break;
      }

      case SYSCALL_EXITED: {
        //
        // getting the syscall return value
        //
        int res;

#if defined(__i386__)
        res = ptrace(PTRACE_PEEKUSER, pid,
                   __builtin_offsetof(struct user, regs.eax));
#elif defined(__x86_64__)
        res = ptrace(PTRACE_PEEKUSER, pid,
                   __builtin_offsetof(struct user, regs.rax));
#elif defined(__arm__)
        res = ptrace(PTRACE_PEEKUSER, pid,
                   __builtin_offsetof(struct user, regs.uregs[0]));
#else
#error "unknown architecture"
#endif

        fprintf(stderr, "parent: [%d] SYSCALL [%s] = %d\n", pid,
              name_of_syscall_number(st.no), res);
        break;
      }

      default:
        __builtin_unreachable();
    }

    toggle_syscall_state(st);
  }



  return 0;
}

static mutex mtx;
static void do_thread(int n) {
  for (int i = 1;; ++i) {
    {
      lock_guard<mutex> lck(mtx);
      fprintf(stdout, "child: %d [%d]\n", i,
              static_cast<int>(syscall(SYS_gettid)));
    }

    struct timespec tm;
    clock_gettime(CLOCK_MONOTONIC, &tm);
    tm.tv_sec += 3;
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &tm, NULL);
  }
}

int do_child(int argc, char **argv) {
  //
  // child
  //

  //
  // the request
  //
  ptrace(PTRACE_TRACEME);
  //
  // turns the calling thread into a tracee.  The thread continues to run
  // (doesn't enter ptrace-stop).  A common practice is to follow the
  // PTRACE_TRACEME with
  //
  raise(SIGSTOP);
  //
  // and allow the parent (which is our tracer now) to observe our
  // signal-delivery-stop.
  //

  constexpr unsigned NUM_THREADS = 3;

  array<thread, NUM_THREADS> thds;
  for (unsigned i = 0; i < NUM_THREADS; i++)
    thds[i] = thread(do_thread, i+1);

  for (thread& thd : thds)
    thd.join();

  return 0;
}

const char *name_of_signal_number(int num) {
  switch (num) {
#define _CHECK_SIGNAL(NM)                                                      \
  case NM:                                                                     \
    return #NM;

#ifdef SIGHUP
  _CHECK_SIGNAL(SIGHUP)
#endif
#ifdef SIGINT
  _CHECK_SIGNAL(SIGINT)
#endif
#ifdef SIGQUIT
  _CHECK_SIGNAL(SIGQUIT)
#endif
#ifdef SIGILL
  _CHECK_SIGNAL(SIGILL)
#endif
#ifdef SIGTRAP
  _CHECK_SIGNAL(SIGTRAP)
#endif
#ifdef SIGABRT
  _CHECK_SIGNAL(SIGABRT)
#endif
#ifdef SIGBUS
  _CHECK_SIGNAL(SIGBUS)
#endif
#ifdef SIGFPE
  _CHECK_SIGNAL(SIGFPE)
#endif
#ifdef SIGKILL
  _CHECK_SIGNAL(SIGKILL)
#endif
#ifdef SIGUSR1
  _CHECK_SIGNAL(SIGUSR1)
#endif
#ifdef SIGSEGV
  _CHECK_SIGNAL(SIGSEGV)
#endif
#ifdef SIGUSR2
  _CHECK_SIGNAL(SIGUSR2)
#endif
#ifdef SIGPIPE
  _CHECK_SIGNAL(SIGPIPE)
#endif
#ifdef SIGALRM
  _CHECK_SIGNAL(SIGALRM)
#endif
#ifdef SIGTERM
  _CHECK_SIGNAL(SIGTERM)
#endif
#ifdef SIGSTKFLT
  _CHECK_SIGNAL(SIGSTKFLT)
#endif
#ifdef SIGCHLD
  _CHECK_SIGNAL(SIGCHLD)
#endif
#ifdef SIGCONT
  _CHECK_SIGNAL(SIGCONT)
#endif
#ifdef SIGSTOP
  _CHECK_SIGNAL(SIGSTOP)
#endif
#ifdef SIGTSTP
  _CHECK_SIGNAL(SIGTSTP)
#endif
#ifdef SIGTTIN
  _CHECK_SIGNAL(SIGTTIN)
#endif
#ifdef SIGTTOU
  _CHECK_SIGNAL(SIGTTOU)
#endif
#ifdef SIGURG
  _CHECK_SIGNAL(SIGURG)
#endif
#ifdef SIGXCPU
  _CHECK_SIGNAL(SIGXCPU)
#endif
#ifdef SIGXFSZ
  _CHECK_SIGNAL(SIGXFSZ)
#endif
#ifdef SIGVTALRM
  _CHECK_SIGNAL(SIGVTALRM)
#endif
#ifdef SIGPROF
  _CHECK_SIGNAL(SIGPROF)
#endif
#ifdef SIGWINCH
  _CHECK_SIGNAL(SIGWINCH)
#endif
#ifdef SIGPOLL
  _CHECK_SIGNAL(SIGPOLL)
#endif
#ifdef SIGSYS
  _CHECK_SIGNAL(SIGSYS)
#endif
  }

  return "UNKNOWN";
}

const char* name_of_syscall_number(int num) {
#define _CHECK_SYSCALL(NM)                                                     \
  case __NR_##NM:                                                              \
    return #NM;

  switch (num) {
#ifdef __NR_exit
  _CHECK_SYSCALL(exit)
#endif
#ifdef __NR_fork
  _CHECK_SYSCALL(fork)
#endif
#ifdef __NR_read
  _CHECK_SYSCALL(read)
#endif
#ifdef __NR_write
  _CHECK_SYSCALL(write)
#endif
#ifdef __NR_open
  _CHECK_SYSCALL(open)
#endif
#ifdef __NR_close
  _CHECK_SYSCALL(close)
#endif
#ifdef __NR_creat
  _CHECK_SYSCALL(creat)
#endif
#ifdef __NR_link
  _CHECK_SYSCALL(link)
#endif
#ifdef __NR_unlink
  _CHECK_SYSCALL(unlink)
#endif
#ifdef __NR_execve
  _CHECK_SYSCALL(execve)
#endif
#ifdef __NR_chdir
  _CHECK_SYSCALL(chdir)
#endif
#ifdef __NR_mknod
  _CHECK_SYSCALL(mknod)
#endif
#ifdef __NR_chmod
  _CHECK_SYSCALL(chmod)
#endif
#ifdef __NR_lchown
  _CHECK_SYSCALL(lchown)
#endif
#ifdef __NR_lseek
  _CHECK_SYSCALL(lseek)
#endif
#ifdef __NR_getpid
  _CHECK_SYSCALL(getpid)
#endif
#ifdef __NR_mount
  _CHECK_SYSCALL(mount)
#endif
#ifdef __NR_setuid
  _CHECK_SYSCALL(setuid)
#endif
#ifdef __NR_getuid
  _CHECK_SYSCALL(getuid)
#endif
#ifdef __NR_ptrace
  _CHECK_SYSCALL(ptrace)
#endif
#ifdef __NR_pause
  _CHECK_SYSCALL(pause)
#endif
#ifdef __NR_access
  _CHECK_SYSCALL(access)
#endif
#ifdef __NR_nice
  _CHECK_SYSCALL(nice)
#endif
#ifdef __NR_sync
  _CHECK_SYSCALL(sync)
#endif
#ifdef __NR_kill
  _CHECK_SYSCALL(kill)
#endif
#ifdef __NR_rename
  _CHECK_SYSCALL(rename)
#endif
#ifdef __NR_mkdir
  _CHECK_SYSCALL(mkdir)
#endif
#ifdef __NR_rmdir
  _CHECK_SYSCALL(rmdir)
#endif
#ifdef __NR_dup
  _CHECK_SYSCALL(dup)
#endif
#ifdef __NR_pipe
  _CHECK_SYSCALL(pipe)
#endif
#ifdef __NR_times
  _CHECK_SYSCALL(times)
#endif
#ifdef __NR_brk
  _CHECK_SYSCALL(brk)
#endif
#ifdef __NR_setgid
  _CHECK_SYSCALL(setgid)
#endif
#ifdef __NR_getgid
  _CHECK_SYSCALL(getgid)
#endif
#ifdef __NR_geteuid
  _CHECK_SYSCALL(geteuid)
#endif
#ifdef __NR_getegid
  _CHECK_SYSCALL(getegid)
#endif
#ifdef __NR_acct
  _CHECK_SYSCALL(acct)
#endif
#ifdef __NR_umount2
  _CHECK_SYSCALL(umount2)
#endif
#ifdef __NR_ioctl
  _CHECK_SYSCALL(ioctl)
#endif
#ifdef __NR_fcntl
  _CHECK_SYSCALL(fcntl)
#endif
#ifdef __NR_setpgid
  _CHECK_SYSCALL(setpgid)
#endif
#ifdef __NR_umask
  _CHECK_SYSCALL(umask)
#endif
#ifdef __NR_chroot
  _CHECK_SYSCALL(chroot)
#endif
#ifdef __NR_ustat
  _CHECK_SYSCALL(ustat)
#endif
#ifdef __NR_dup2
  _CHECK_SYSCALL(dup2)
#endif
#ifdef __NR_getppid
  _CHECK_SYSCALL(getppid)
#endif
#ifdef __NR_getpgrp
  _CHECK_SYSCALL(getpgrp)
#endif
#ifdef __NR_setsid
  _CHECK_SYSCALL(setsid)
#endif
#ifdef __NR_sigaction
  _CHECK_SYSCALL(sigaction)
#endif
#ifdef __NR_setreuid
  _CHECK_SYSCALL(setreuid)
#endif
#ifdef __NR_setregid
  _CHECK_SYSCALL(setregid)
#endif
#ifdef __NR_sigsuspend
  _CHECK_SYSCALL(sigsuspend)
#endif
#ifdef __NR_sigpending
  _CHECK_SYSCALL(sigpending)
#endif
#ifdef __NR_sethostname
  _CHECK_SYSCALL(sethostname)
#endif
#ifdef __NR_setrlimit
  _CHECK_SYSCALL(setrlimit)
#endif
#ifdef __NR_getrusage
  _CHECK_SYSCALL(getrusage)
#endif
#ifdef __NR_gettimeofday
  _CHECK_SYSCALL(gettimeofday)
#endif
#ifdef __NR_settimeofday
  _CHECK_SYSCALL(settimeofday)
#endif
#ifdef __NR_getgroups
  _CHECK_SYSCALL(getgroups)
#endif
#ifdef __NR_setgroups
  _CHECK_SYSCALL(setgroups)
#endif
#ifdef __NR_symlink
  _CHECK_SYSCALL(symlink)
#endif
#ifdef __NR_readlink
  _CHECK_SYSCALL(readlink)
#endif
#ifdef __NR_uselib
  _CHECK_SYSCALL(uselib)
#endif
#ifdef __NR_swapon
  _CHECK_SYSCALL(swapon)
#endif
#ifdef __NR_reboot
  _CHECK_SYSCALL(reboot)
#endif
#ifdef __NR_munmap
  _CHECK_SYSCALL(munmap)
#endif
#ifdef __NR_truncate
  _CHECK_SYSCALL(truncate)
#endif
#ifdef __NR_ftruncate
  _CHECK_SYSCALL(ftruncate)
#endif
#ifdef __NR_fchmod
  _CHECK_SYSCALL(fchmod)
#endif
#ifdef __NR_fchown
  _CHECK_SYSCALL(fchown)
#endif
#ifdef __NR_getpriority
  _CHECK_SYSCALL(getpriority)
#endif
#ifdef __NR_setpriority
  _CHECK_SYSCALL(setpriority)
#endif
#ifdef __NR_statfs
  _CHECK_SYSCALL(statfs)
#endif
#ifdef __NR_fstatfs
  _CHECK_SYSCALL(fstatfs)
#endif
#ifdef __NR_syslog
  _CHECK_SYSCALL(syslog)
#endif
#ifdef __NR_setitimer
  _CHECK_SYSCALL(setitimer)
#endif
#ifdef __NR_getitimer
  _CHECK_SYSCALL(getitimer)
#endif
#ifdef __NR_stat
  _CHECK_SYSCALL(stat)
#endif
#ifdef __NR_lstat
  _CHECK_SYSCALL(lstat)
#endif
#ifdef __NR_fstat
  _CHECK_SYSCALL(fstat)
#endif
#ifdef __NR_vhangup
  _CHECK_SYSCALL(vhangup)
#endif
#ifdef __NR_wait4
  _CHECK_SYSCALL(wait4)
#endif
#ifdef __NR_swapoff
  _CHECK_SYSCALL(swapoff)
#endif
#ifdef __NR_sysinfo
  _CHECK_SYSCALL(sysinfo)
#endif
#ifdef __NR_fsync
  _CHECK_SYSCALL(fsync)
#endif
#ifdef __NR_sigreturn
  _CHECK_SYSCALL(sigreturn)
#endif
#ifdef __NR_clone
  _CHECK_SYSCALL(clone)
#endif
#ifdef __NR_setdomainname
  _CHECK_SYSCALL(setdomainname)
#endif
#ifdef __NR_uname
  _CHECK_SYSCALL(uname)
#endif
#ifdef __NR_adjtimex
  _CHECK_SYSCALL(adjtimex)
#endif
#ifdef __NR_mprotect
  _CHECK_SYSCALL(mprotect)
#endif
#ifdef __NR_sigprocmask
  _CHECK_SYSCALL(sigprocmask)
#endif
#ifdef __NR_init_module
  _CHECK_SYSCALL(init_module)
#endif
#ifdef __NR_delete_module
  _CHECK_SYSCALL(delete_module)
#endif
#ifdef __NR_quotactl
  _CHECK_SYSCALL(quotactl)
#endif
#ifdef __NR_getpgid
  _CHECK_SYSCALL(getpgid)
#endif
#ifdef __NR_fchdir
  _CHECK_SYSCALL(fchdir)
#endif
#ifdef __NR_bdflush
  _CHECK_SYSCALL(bdflush)
#endif
#ifdef __NR_sysfs
  _CHECK_SYSCALL(sysfs)
#endif
#ifdef __NR_personality
  _CHECK_SYSCALL(personality)
#endif
#ifdef __NR_setfsuid
  _CHECK_SYSCALL(setfsuid)
#endif
#ifdef __NR_setfsgid
  _CHECK_SYSCALL(setfsgid)
#endif
#ifdef __NR__llseek
  _CHECK_SYSCALL(_llseek)
#endif
#ifdef __NR_getdents
  _CHECK_SYSCALL(getdents)
#endif
#ifdef __NR__newselect
  _CHECK_SYSCALL(_newselect)
#endif
#ifdef __NR_flock
  _CHECK_SYSCALL(flock)
#endif
#ifdef __NR_msync
  _CHECK_SYSCALL(msync)
#endif
#ifdef __NR_readv
  _CHECK_SYSCALL(readv)
#endif
#ifdef __NR_writev
  _CHECK_SYSCALL(writev)
#endif
#ifdef __NR_getsid
  _CHECK_SYSCALL(getsid)
#endif
#ifdef __NR_fdatasync
  _CHECK_SYSCALL(fdatasync)
#endif
#ifdef __NR__sysctl
  _CHECK_SYSCALL(_sysctl)
#endif
#ifdef __NR_mlock
  _CHECK_SYSCALL(mlock)
#endif
#ifdef __NR_munlock
  _CHECK_SYSCALL(munlock)
#endif
#ifdef __NR_mlockall
  _CHECK_SYSCALL(mlockall)
#endif
#ifdef __NR_munlockall
  _CHECK_SYSCALL(munlockall)
#endif
#ifdef __NR_sched_setparam
  _CHECK_SYSCALL(sched_setparam)
#endif
#ifdef __NR_sched_getparam
  _CHECK_SYSCALL(sched_getparam)
#endif
#ifdef __NR_sched_setscheduler
  _CHECK_SYSCALL(sched_setscheduler)
#endif
#ifdef __NR_sched_getscheduler
  _CHECK_SYSCALL(sched_getscheduler)
#endif
#ifdef __NR_sched_yield
  _CHECK_SYSCALL(sched_yield)
#endif
#ifdef __NR_sched_get_priority_max
  _CHECK_SYSCALL(sched_get_priority_max)
#endif
#ifdef __NR_sched_get_priority_min
  _CHECK_SYSCALL(sched_get_priority_min)
#endif
#ifdef __NR_sched_rr_get_interval
  _CHECK_SYSCALL(sched_rr_get_interval)
#endif
#ifdef __NR_nanosleep
  _CHECK_SYSCALL(nanosleep)
#endif
#ifdef __NR_mremap
  _CHECK_SYSCALL(mremap)
#endif
#ifdef __NR_setresuid
  _CHECK_SYSCALL(setresuid)
#endif
#ifdef __NR_getresuid
  _CHECK_SYSCALL(getresuid)
#endif
#ifdef __NR_poll
  _CHECK_SYSCALL(poll)
#endif
#ifdef __NR_nfsservctl
  _CHECK_SYSCALL(nfsservctl)
#endif
#ifdef __NR_setresgid
  _CHECK_SYSCALL(setresgid)
#endif
#ifdef __NR_getresgid
  _CHECK_SYSCALL(getresgid)
#endif
#ifdef __NR_prctl
  _CHECK_SYSCALL(prctl)
#endif
#ifdef __NR_rt_sigreturn
  _CHECK_SYSCALL(rt_sigreturn)
#endif
#ifdef __NR_rt_sigaction
  _CHECK_SYSCALL(rt_sigaction)
#endif
#ifdef __NR_rt_sigprocmask
  _CHECK_SYSCALL(rt_sigprocmask)
#endif
#ifdef __NR_rt_sigpending
  _CHECK_SYSCALL(rt_sigpending)
#endif
#ifdef __NR_rt_sigtimedwait
  _CHECK_SYSCALL(rt_sigtimedwait)
#endif
#ifdef __NR_rt_sigqueueinfo
  _CHECK_SYSCALL(rt_sigqueueinfo)
#endif
#ifdef __NR_rt_sigsuspend
  _CHECK_SYSCALL(rt_sigsuspend)
#endif
#ifdef __NR_pread64
  _CHECK_SYSCALL(pread64)
#endif
#ifdef __NR_pwrite64
  _CHECK_SYSCALL(pwrite64)
#endif
#ifdef __NR_chown
  _CHECK_SYSCALL(chown)
#endif
#ifdef __NR_getcwd
  _CHECK_SYSCALL(getcwd)
#endif
#ifdef __NR_capget
  _CHECK_SYSCALL(capget)
#endif
#ifdef __NR_capset
  _CHECK_SYSCALL(capset)
#endif
#ifdef __NR_sigaltstack
  _CHECK_SYSCALL(sigaltstack)
#endif
#ifdef __NR_sendfile
  _CHECK_SYSCALL(sendfile)
#endif
#ifdef __NR_vfork
  _CHECK_SYSCALL(vfork)
#endif
#ifdef __NR_ugetrlimit
  _CHECK_SYSCALL(ugetrlimit)
#endif
#ifdef __NR_mmap
  _CHECK_SYSCALL(mmap)
#endif
#ifdef __NR_mmap2
  _CHECK_SYSCALL(mmap2)
#endif
#ifdef __NR_truncate64
  _CHECK_SYSCALL(truncate64)
#endif
#ifdef __NR_ftruncate64
  _CHECK_SYSCALL(ftruncate64)
#endif
#ifdef __NR_stat64
  _CHECK_SYSCALL(stat64)
#endif
#ifdef __NR_lstat64
  _CHECK_SYSCALL(lstat64)
#endif
#ifdef __NR_fstat64
  _CHECK_SYSCALL(fstat64)
#endif
#ifdef __NR_lchown32
  _CHECK_SYSCALL(lchown32)
#endif
#ifdef __NR_getuid32
  _CHECK_SYSCALL(getuid32)
#endif
#ifdef __NR_getgid32
  _CHECK_SYSCALL(getgid32)
#endif
#ifdef __NR_geteuid32
  _CHECK_SYSCALL(geteuid32)
#endif
#ifdef __NR_getegid32
  _CHECK_SYSCALL(getegid32)
#endif
#ifdef __NR_setreuid32
  _CHECK_SYSCALL(setreuid32)
#endif
#ifdef __NR_setregid32
  _CHECK_SYSCALL(setregid32)
#endif
#ifdef __NR_getgroups32
  _CHECK_SYSCALL(getgroups32)
#endif
#ifdef __NR_setgroups32
  _CHECK_SYSCALL(setgroups32)
#endif
#ifdef __NR_fchown32
  _CHECK_SYSCALL(fchown32)
#endif
#ifdef __NR_setresuid32
  _CHECK_SYSCALL(setresuid32)
#endif
#ifdef __NR_getresuid32
  _CHECK_SYSCALL(getresuid32)
#endif
#ifdef __NR_setresgid32
  _CHECK_SYSCALL(setresgid32)
#endif
#ifdef __NR_getresgid32
  _CHECK_SYSCALL(getresgid32)
#endif
#ifdef __NR_chown32
  _CHECK_SYSCALL(chown32)
#endif
#ifdef __NR_setuid32
  _CHECK_SYSCALL(setuid32)
#endif
#ifdef __NR_setgid32
  _CHECK_SYSCALL(setgid32)
#endif
#ifdef __NR_setfsuid32
  _CHECK_SYSCALL(setfsuid32)
#endif
#ifdef __NR_setfsgid32
  _CHECK_SYSCALL(setfsgid32)
#endif
#ifdef __NR_getdents64
  _CHECK_SYSCALL(getdents64)
#endif
#ifdef __NR_pivot_root
  _CHECK_SYSCALL(pivot_root)
#endif
#ifdef __NR_mincore
  _CHECK_SYSCALL(mincore)
#endif
#ifdef __NR_madvise
  _CHECK_SYSCALL(madvise)
#endif
#ifdef __NR_fcntl64
  _CHECK_SYSCALL(fcntl64)
#endif
#ifdef __NR_gettid
  _CHECK_SYSCALL(gettid)
#endif
#ifdef __NR_readahead
  _CHECK_SYSCALL(readahead)
#endif
#ifdef __NR_setxattr
  _CHECK_SYSCALL(setxattr)
#endif
#ifdef __NR_lsetxattr
  _CHECK_SYSCALL(lsetxattr)
#endif
#ifdef __NR_fsetxattr
  _CHECK_SYSCALL(fsetxattr)
#endif
#ifdef __NR_getxattr
  _CHECK_SYSCALL(getxattr)
#endif
#ifdef __NR_lgetxattr
  _CHECK_SYSCALL(lgetxattr)
#endif
#ifdef __NR_fgetxattr
  _CHECK_SYSCALL(fgetxattr)
#endif
#ifdef __NR_listxattr
  _CHECK_SYSCALL(listxattr)
#endif
#ifdef __NR_llistxattr
  _CHECK_SYSCALL(llistxattr)
#endif
#ifdef __NR_flistxattr
  _CHECK_SYSCALL(flistxattr)
#endif
#ifdef __NR_removexattr
  _CHECK_SYSCALL(removexattr)
#endif
#ifdef __NR_lremovexattr
  _CHECK_SYSCALL(lremovexattr)
#endif
#ifdef __NR_fremovexattr
  _CHECK_SYSCALL(fremovexattr)
#endif
#ifdef __NR_tkill
  _CHECK_SYSCALL(tkill)
#endif
#ifdef __NR_sendfile64
  _CHECK_SYSCALL(sendfile64)
#endif
#ifdef __NR_futex
  _CHECK_SYSCALL(futex)
#endif
#ifdef __NR_sched_setaffinity
  _CHECK_SYSCALL(sched_setaffinity)
#endif
#ifdef __NR_sched_getaffinity
  _CHECK_SYSCALL(sched_getaffinity)
#endif
#ifdef __NR_io_setup
  _CHECK_SYSCALL(io_setup)
#endif
#ifdef __NR_io_destroy
  _CHECK_SYSCALL(io_destroy)
#endif
#ifdef __NR_io_getevents
  _CHECK_SYSCALL(io_getevents)
#endif
#ifdef __NR_io_submit
  _CHECK_SYSCALL(io_submit)
#endif
#ifdef __NR_io_cancel
  _CHECK_SYSCALL(io_cancel)
#endif
#ifdef __NR_exit_group
  _CHECK_SYSCALL(exit_group)
#endif
#ifdef __NR_lookup_dcookie
  _CHECK_SYSCALL(lookup_dcookie)
#endif
#ifdef __NR_epoll_create
  _CHECK_SYSCALL(epoll_create)
#endif
#ifdef __NR_epoll_ctl
  _CHECK_SYSCALL(epoll_ctl)
#endif
#ifdef __NR_epoll_wait
  _CHECK_SYSCALL(epoll_wait)
#endif
#ifdef __NR_remap_file_pages
  _CHECK_SYSCALL(remap_file_pages)
#endif
#ifdef __NR_set_tid_address
  _CHECK_SYSCALL(set_tid_address)
#endif
#ifdef __NR_timer_create
  _CHECK_SYSCALL(timer_create)
#endif
#ifdef __NR_timer_settime
  _CHECK_SYSCALL(timer_settime)
#endif
#ifdef __NR_timer_gettime
  _CHECK_SYSCALL(timer_gettime)
#endif
#ifdef __NR_timer_getoverrun
  _CHECK_SYSCALL(timer_getoverrun)
#endif
#ifdef __NR_timer_delete
  _CHECK_SYSCALL(timer_delete)
#endif
#ifdef __NR_clock_settime
  _CHECK_SYSCALL(clock_settime)
#endif
#ifdef __NR_clock_gettime
  _CHECK_SYSCALL(clock_gettime)
#endif
#ifdef __NR_clock_getres
  _CHECK_SYSCALL(clock_getres)
#endif
#ifdef __NR_clock_nanosleep
  _CHECK_SYSCALL(clock_nanosleep)
#endif
#ifdef __NR_statfs64
  _CHECK_SYSCALL(statfs64)
#endif
#ifdef __NR_fstatfs64
  _CHECK_SYSCALL(fstatfs64)
#endif
#ifdef __NR_tgkill
  _CHECK_SYSCALL(tgkill)
#endif
#ifdef __NR_utimes
  _CHECK_SYSCALL(utimes)
#endif
#ifdef __NR_arm_fadvise64_64
  _CHECK_SYSCALL(arm_fadvise64_64)
#endif
#ifdef __NR_pciconfig_iobase
  _CHECK_SYSCALL(pciconfig_iobase)
#endif
#ifdef __NR_pciconfig_read
  _CHECK_SYSCALL(pciconfig_read)
#endif
#ifdef __NR_pciconfig_write
  _CHECK_SYSCALL(pciconfig_write)
#endif
#ifdef __NR_mq_open
  _CHECK_SYSCALL(mq_open)
#endif
#ifdef __NR_mq_unlink
  _CHECK_SYSCALL(mq_unlink)
#endif
#ifdef __NR_mq_timedsend
  _CHECK_SYSCALL(mq_timedsend)
#endif
#ifdef __NR_mq_timedreceive
  _CHECK_SYSCALL(mq_timedreceive)
#endif
#ifdef __NR_mq_notify
  _CHECK_SYSCALL(mq_notify)
#endif
#ifdef __NR_mq_getsetattr
  _CHECK_SYSCALL(mq_getsetattr)
#endif
#ifdef __NR_waitid
  _CHECK_SYSCALL(waitid)
#endif
#ifdef __NR_socket
  _CHECK_SYSCALL(socket)
#endif
#ifdef __NR_bind
  _CHECK_SYSCALL(bind)
#endif
#ifdef __NR_connect
  _CHECK_SYSCALL(connect)
#endif
#ifdef __NR_listen
  _CHECK_SYSCALL(listen)
#endif
#ifdef __NR_accept
  _CHECK_SYSCALL(accept)
#endif
#ifdef __NR_getsockname
  _CHECK_SYSCALL(getsockname)
#endif
#ifdef __NR_getpeername
  _CHECK_SYSCALL(getpeername)
#endif
#ifdef __NR_socketpair
  _CHECK_SYSCALL(socketpair)
#endif
#ifdef __NR_send
  _CHECK_SYSCALL(send)
#endif
#ifdef __NR_sendto
  _CHECK_SYSCALL(sendto)
#endif
#ifdef __NR_recv
  _CHECK_SYSCALL(recv)
#endif
#ifdef __NR_recvfrom
  _CHECK_SYSCALL(recvfrom)
#endif
#ifdef __NR_shutdown
  _CHECK_SYSCALL(shutdown)
#endif
#ifdef __NR_setsockopt
  _CHECK_SYSCALL(setsockopt)
#endif
#ifdef __NR_getsockopt
  _CHECK_SYSCALL(getsockopt)
#endif
#ifdef __NR_sendmsg
  _CHECK_SYSCALL(sendmsg)
#endif
#ifdef __NR_recvmsg
  _CHECK_SYSCALL(recvmsg)
#endif
#ifdef __NR_semop
  _CHECK_SYSCALL(semop)
#endif
#ifdef __NR_semget
  _CHECK_SYSCALL(semget)
#endif
#ifdef __NR_semctl
  _CHECK_SYSCALL(semctl)
#endif
#ifdef __NR_msgsnd
  _CHECK_SYSCALL(msgsnd)
#endif
#ifdef __NR_msgrcv
  _CHECK_SYSCALL(msgrcv)
#endif
#ifdef __NR_msgget
  _CHECK_SYSCALL(msgget)
#endif
#ifdef __NR_msgctl
  _CHECK_SYSCALL(msgctl)
#endif
#ifdef __NR_shmat
  _CHECK_SYSCALL(shmat)
#endif
#ifdef __NR_shmdt
  _CHECK_SYSCALL(shmdt)
#endif
#ifdef __NR_shmget
  _CHECK_SYSCALL(shmget)
#endif
#ifdef __NR_shmctl
  _CHECK_SYSCALL(shmctl)
#endif
#ifdef __NR_add_key
  _CHECK_SYSCALL(add_key)
#endif
#ifdef __NR_request_key
  _CHECK_SYSCALL(request_key)
#endif
#ifdef __NR_keyctl
  _CHECK_SYSCALL(keyctl)
#endif
#ifdef __NR_semtimedop
  _CHECK_SYSCALL(semtimedop)
#endif
#ifdef __NR_vserver
  _CHECK_SYSCALL(vserver)
#endif
#ifdef __NR_ioprio_set
  _CHECK_SYSCALL(ioprio_set)
#endif
#ifdef __NR_ioprio_get
  _CHECK_SYSCALL(ioprio_get)
#endif
#ifdef __NR_inotify_init
  _CHECK_SYSCALL(inotify_init)
#endif
#ifdef __NR_inotify_add_watch
  _CHECK_SYSCALL(inotify_add_watch)
#endif
#ifdef __NR_inotify_rm_watch
  _CHECK_SYSCALL(inotify_rm_watch)
#endif
#ifdef __NR_mbind
  _CHECK_SYSCALL(mbind)
#endif
#ifdef __NR_get_mempolicy
  _CHECK_SYSCALL(get_mempolicy)
#endif
#ifdef __NR_set_mempolicy
  _CHECK_SYSCALL(set_mempolicy)
#endif
#ifdef __NR_openat
  _CHECK_SYSCALL(openat)
#endif
#ifdef __NR_mkdirat
  _CHECK_SYSCALL(mkdirat)
#endif
#ifdef __NR_mknodat
  _CHECK_SYSCALL(mknodat)
#endif
#ifdef __NR_fchownat
  _CHECK_SYSCALL(fchownat)
#endif
#ifdef __NR_futimesat
  _CHECK_SYSCALL(futimesat)
#endif
#ifdef __NR_fstatat64
  _CHECK_SYSCALL(fstatat64)
#endif
#ifdef __NR_unlinkat
  _CHECK_SYSCALL(unlinkat)
#endif
#ifdef __NR_renameat
  _CHECK_SYSCALL(renameat)
#endif
#ifdef __NR_linkat
  _CHECK_SYSCALL(linkat)
#endif
#ifdef __NR_symlinkat
  _CHECK_SYSCALL(symlinkat)
#endif
#ifdef __NR_readlinkat
  _CHECK_SYSCALL(readlinkat)
#endif
#ifdef __NR_fchmodat
  _CHECK_SYSCALL(fchmodat)
#endif
#ifdef __NR_faccessat
  _CHECK_SYSCALL(faccessat)
#endif
#ifdef __NR_pselect6
  _CHECK_SYSCALL(pselect6)
#endif
#ifdef __NR_ppoll
  _CHECK_SYSCALL(ppoll)
#endif
#ifdef __NR_unshare
  _CHECK_SYSCALL(unshare)
#endif
#ifdef __NR_set_robust_list
  _CHECK_SYSCALL(set_robust_list)
#endif
#ifdef __NR_get_robust_list
  _CHECK_SYSCALL(get_robust_list)
#endif
#ifdef __NR_splice
  _CHECK_SYSCALL(splice)
#endif
#ifdef __NR_arm_sync_file_range
  _CHECK_SYSCALL(arm_sync_file_range)
#endif
#ifdef __NR_tee
  _CHECK_SYSCALL(tee)
#endif
#ifdef __NR_vmsplice
  _CHECK_SYSCALL(vmsplice)
#endif
#ifdef __NR_move_pages
  _CHECK_SYSCALL(move_pages)
#endif
#ifdef __NR_getcpu
  _CHECK_SYSCALL(getcpu)
#endif
#ifdef __NR_epoll_pwait
  _CHECK_SYSCALL(epoll_pwait)
#endif
#ifdef __NR_kexec_load
  _CHECK_SYSCALL(kexec_load)
#endif
#ifdef __NR_utimensat
  _CHECK_SYSCALL(utimensat)
#endif
#ifdef __NR_signalfd
  _CHECK_SYSCALL(signalfd)
#endif
#ifdef __NR_timerfd_create
  _CHECK_SYSCALL(timerfd_create)
#endif
#ifdef __NR_eventfd
  _CHECK_SYSCALL(eventfd)
#endif
#ifdef __NR_fallocate
  _CHECK_SYSCALL(fallocate)
#endif
#ifdef __NR_timerfd_settime
  _CHECK_SYSCALL(timerfd_settime)
#endif
#ifdef __NR_timerfd_gettime
  _CHECK_SYSCALL(timerfd_gettime)
#endif
#ifdef __NR_signalfd4
  _CHECK_SYSCALL(signalfd4)
#endif
#ifdef __NR_eventfd2
  _CHECK_SYSCALL(eventfd2)
#endif
#ifdef __NR_epoll_create1
  _CHECK_SYSCALL(epoll_create1)
#endif
#ifdef __NR_dup3
  _CHECK_SYSCALL(dup3)
#endif
#ifdef __NR_pipe2
  _CHECK_SYSCALL(pipe2)
#endif
#ifdef __NR_inotify_init1
  _CHECK_SYSCALL(inotify_init1)
#endif
#ifdef __NR_preadv
  _CHECK_SYSCALL(preadv)
#endif
#ifdef __NR_pwritev
  _CHECK_SYSCALL(pwritev)
#endif
#ifdef __NR_rt_tgsigqueueinfo
  _CHECK_SYSCALL(rt_tgsigqueueinfo)
#endif
#ifdef __NR_perf_event_open
  _CHECK_SYSCALL(perf_event_open)
#endif
#ifdef __NR_recvmmsg
  _CHECK_SYSCALL(recvmmsg)
#endif
#ifdef __NR_accept4
  _CHECK_SYSCALL(accept4)
#endif
#ifdef __NR_fanotify_init
  _CHECK_SYSCALL(fanotify_init)
#endif
#ifdef __NR_fanotify_mark
  _CHECK_SYSCALL(fanotify_mark)
#endif
#ifdef __NR_prlimit64
  _CHECK_SYSCALL(prlimit64)
#endif
#ifdef __NR_name_to_handle_at
  _CHECK_SYSCALL(name_to_handle_at)
#endif
#ifdef __NR_open_by_handle_at
  _CHECK_SYSCALL(open_by_handle_at)
#endif
#ifdef __NR_clock_adjtime
  _CHECK_SYSCALL(clock_adjtime)
#endif
#ifdef __NR_syncfs
  _CHECK_SYSCALL(syncfs)
#endif
#ifdef __NR_sendmmsg
  _CHECK_SYSCALL(sendmmsg)
#endif
#ifdef __NR_setns
  _CHECK_SYSCALL(setns)
#endif
#ifdef __NR_process_vm_readv
  _CHECK_SYSCALL(process_vm_readv)
#endif
#ifdef __NR_process_vm_writev
  _CHECK_SYSCALL(process_vm_writev)
#endif
#ifdef __NR_kcmp
  _CHECK_SYSCALL(kcmp)
#endif
#ifdef __NR_finit_module
  _CHECK_SYSCALL(finit_module)
#endif
#ifdef __NR_sched_setattr
  _CHECK_SYSCALL(sched_setattr)
#endif
#ifdef __NR_sched_getattr
  _CHECK_SYSCALL(sched_getattr)
#endif
#ifdef __NR_renameat2
  _CHECK_SYSCALL(renameat2)
#endif
#ifdef __NR_seccomp
  _CHECK_SYSCALL(seccomp)
#endif
#ifdef __NR_getrandom
  _CHECK_SYSCALL(getrandom)
#endif
#ifdef __NR_memfd_create
  _CHECK_SYSCALL(memfd_create)
#endif
#ifdef __NR_bpf
  _CHECK_SYSCALL(bpf)
#endif
#ifdef __NR_execveat
  _CHECK_SYSCALL(execveat)
#endif
#ifdef __NR_userfaultfd
  _CHECK_SYSCALL(userfaultfd)
#endif
#ifdef __NR_membarrier
  _CHECK_SYSCALL(membarrier)
#endif
#ifdef __NR_mlock2
  _CHECK_SYSCALL(mlock2)
#endif
#ifdef __NR_copy_file_range
  _CHECK_SYSCALL(copy_file_range)
#endif
#ifdef __NR_preadv2
  _CHECK_SYSCALL(preadv2)
#endif
#ifdef __NR_pwritev2
  _CHECK_SYSCALL(pwritev2)
#endif
#ifdef __NR_pkey_mprotect
  _CHECK_SYSCALL(pkey_mprotect)
#endif
#ifdef __NR_pkey_alloc
  _CHECK_SYSCALL(pkey_alloc)
#endif
#ifdef __NR_pkey_free
  _CHECK_SYSCALL(pkey_free)
#endif
  }

  return "UNKNOWN";
}
