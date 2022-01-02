#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include "ptrace_utils.h"


/* ----------------------- -----------------------   arm64    ----------------------- ----------------------- */
#ifdef __aarch64__

long __ptrace_get_reg_content(pid_t pid, struct user_regs_struct_full *regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (struct user_regs_struct_full),
	};
	register long err;
	if ((err = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))) {      // 1. Get reg contents
		return err;
	} else {
		iov.iov_base = ((struct user_regs_struct*)iov.iov_base) + 1  /* += sizeof (struct user_regs_struct) */;	 	   // $$ TODO: ASK CORRECT $$
		iov.iov_len = sizeof (int);
		return ptrace(PTRACE_GETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);    // 2. Get syscall-nr
	}

  // $$$ TODO: CHECK `errno` ??! $$$
}


/* ----------------------- ----------------------- amd64 / i386 ----------------------- ----------------------- */
#elif defined(__x86_64__) || defined(__i386__)

long __ptrace_get_reg_content(pid_t pid, struct user_regs_struct_full *regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (struct user_regs_struct_full),
	};
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);

  // $$$ TODO: CHECK `errno` ??! $$$
}


#else

#  error "Unsupported CPU arch"

#endif
