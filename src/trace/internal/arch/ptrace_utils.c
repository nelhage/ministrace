#include <elf.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include "../../../common/error.h"
#include "../ptrace_utils.h"
#include "ptrace_utils.h"



/* ----------------------- ----------------------- amd64 / i386 ----------------------- ----------------------- */
#if defined(__x86_64__) || defined(__i386__)

void ptrace_get_regs_content(pid_t tid, struct user_regs_struct_full *regs) {
  struct iovec iov = {
    .iov_base = regs,
    .iov_len = sizeof (struct user_regs_struct_full),
  };

  errno = 0;
  ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov);
  if (errno) {
    LOG_ERROR_AND_EXIT("Reading registers failed (errno=%d)", errno);
  }
}


// /* ----------------------- -----------------------   arm64    ----------------------- ----------------------- */
// #elif defined(__aarch64__)
//
// void ptrace_get_regs_content(pid_t tid, struct user_regs_struct_full *regs) {
//   struct iovec iov = {
//     .iov_base = &(regs->user_regs),
//     .iov_len = sizeof(regs->user_regs),
//   };
//
//   errno = 0;
//   /* 1. Get reg contents */
//   ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov);
//   if (errno) {
//     LOG_ERROR_AND_EXIT("Reading registers failed (errno=%d)", errno);
//   }
//
//   /* 2. Get syscall-nr */
//   iov.iov_base = &(regs->syscallno);
//   iov.iov_len = sizeof(regs->syscallno);
//   ptrace(PTRACE_GETREGSET, tid, NT_ARM_SYSTEM_CALL, &iov);        // !!! TODO: Returns wrong syscall nr ?? !!!
//   if (errno) {
//     LOG_ERROR_AND_EXIT("Reading registers failed (errno=%d)", errno);
//   }
// }


#else

#  error "Unsupported CPU arch"

#endif
