// Source: https://gist.github.com/SBell6hf/77393dac37939a467caf8b241dc1676b
// License: The Unlicense

#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>



// ------------------------------------------- Arch specific stuff -------------------------------------------
#ifdef __aarch64__

struct user_regs_struct_full {
	union {
		struct user_regs_struct user_regs;
		struct {
			unsigned long regs[31];
			unsigned long sp;
			unsigned long pc;
			unsigned long pstate;
		};
	};
	int syscallno;
};


#else /* __x86_64__ / __i386__ */

#  define user_regs_struct_full user_regs_struct

#endif



#define NO_SYSCALL (-1)

#ifdef __aarch64__

#  define SYSCALL_REG_CALLNO(regss) ((const int)(regss.syscallno))
#  define SYSCALL_REG_RETURN(regss) (regss.regs[0])
#  define SYSCALL_REG_ARG0(regss) (regss.regs[0])
#  define SYSCALL_REG_ARG1(regss) (regss.regs[1])
#  define SYSCALL_REG_ARG2(regss) (regss.regs[2])
#  define SYSCALL_REG_ARG3(regss) (regss.regs[3])
#  define SYSCALL_REG_ARG4(regss) (regss.regs[4])
#  define SYSCALL_REG_ARG5(regss) (regss.regs[5])

#  define SYSCALL_RETED(regss) (regss.regs[7] == 1 && SYSCALL_REG_CALLNO(regss) != NO_SYSCALL)
#  define SYSCALL_SETCALLNO(regss, call_no) (regss.regs[8] = regss.syscallno = call_no)

static inline long ptrace_get_reg_content(pid_t pid, struct user_regs_struct_full *regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (struct user_regs_struct_full),
	};
	register long err;
	if (err = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov)) {
		return err;
	} else {
		iov.iov_base += sizeof (struct user_regs_struct);
		iov.iov_len = sizeof (int);
		return ptrace(PTRACE_GETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);
	}
}

static inline long ptrace_set_reg_content(pid_t pid, struct user_regs_struct_full *regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (struct user_regs_struct_full),
	};
	register long err;
	if (err = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov)) {
		return err;
	} else {
		iov.iov_base += sizeof (struct user_regs_struct);
		iov.iov_len = sizeof (int);
		return ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);
	}
}

#elif defined(__x86_64__) || defined(__i386__)

#  ifdef __x86_64__
#    define SYSCALL_REG_CALLNO(regss) ((const int)(regss.orig_rax))
#    define SYSCALL_REG_RETURN(regss) (regss.rax)
#    define SYSCALL_REG_ARG0(regss) (regss.rdi)
#    define SYSCALL_REG_ARG1(regss) (regss.rsi)
#    define SYSCALL_REG_ARG2(regss) (regss.rdx)
#    define SYSCALL_REG_ARG3(regss) (regss.r10)
#    define SYSCALL_REG_ARG4(regss) (regss.r8)
#    define SYSCALL_REG_ARG5(regss) (regss.r9)
#    define SYSCALL_RETED(regss) (regss.rax != -38)
#    define SYSCALL_SETCALLNO(regss, call_no) (regss.orig_rax = call_no)
#  else
#    define SYSCALL_REG_CALLNO(regss) ((const int)(regss.orig_eax))
#    define SYSCALL_REG_RETURN(regss) (regss.eax)
#    define SYSCALL_REG_ARG0(regss) (regss.ebx)
#    define SYSCALL_REG_ARG1(regss) (regss.ecx)
#    define SYSCALL_REG_ARG2(regss) (regss.edx)
#    define SYSCALL_REG_ARG3(regss) (regss.esi)
#    define SYSCALL_REG_ARG4(regss) (regss.edi)
#    define SYSCALL_REG_ARG5(regss) (regss.ebp)
#    define SYSCALL_RETED(regss) (regss.eax != -38)
#    define SYSCALL_SETCALLNO(regss, call_no) (regss.orig_eax = call_no)
# endif

static inline long ptrace_get_reg_content(pid_t pid, struct user_regs_struct_full *regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (struct user_regs_struct_full),
	};
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

static inline long ptrace_set_reg_content(pid_t pid, struct user_regs_struct_full *regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (struct user_regs_struct_full),
	};
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

#else

#  error "Unsupported CPU arch"

#endif
// ------------------------------------------- Arch specific stuff -------------------------------------------







#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#ifndef MAP_ANON
#  define MAP_ANON 0x20
#endif /* MAP_ANON */
#endif /* MAP_ANONYMOUS */

int main(void) {
	pid_t childPid;
	int *pChildError;
	int childStatus, lenChildError, ignoredSyscallRet[1024], lastSkippedCall;
	bool ignoredSyscall[1024];
	struct user_regs_struct_full gPRegs;
	long origSyscallArg0;

	lenChildError = 2;
	lastSkippedCall = -1;
	pChildError = (int *) mmap(NULL, sizeof (*pChildError) * lenChildError, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pChildError[0] = pChildError[1] = 0;
	memset(ignoredSyscall, 0, sizeof (ignoredSyscall));
	memset(ignoredSyscallRet, 0, sizeof (ignoredSyscallRet));

	  ignoredSyscall[SYS_nanosleep]
	= ignoredSyscall[SYS_getpid]
	= ignoredSyscall[SYS_clock_nanosleep]
	= true;

	  ignoredSyscallRet[SYS_nanosleep]
	= ignoredSyscallRet[SYS_clock_nanosleep]
	= 0;

	  ignoredSyscallRet[SYS_getpid]
	= 10;

	childPid = fork();
	if (childPid == -1) {
		printf("error: fork() failed\n");
		munmap(pChildError, sizeof (*pChildError) * lenChildError);
		return -1;
	}

	if (childPid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
			pChildError[0] = 1;
			pChildError[1] = errno;
			munmap(pChildError, sizeof (*pChildError) * lenChildError);
			return -1;
		}

		execle("./test", "", NULL, NULL);
		pChildError[0] = 2;
		pChildError[1] = errno;
		munmap(pChildError, sizeof (*pChildError) * lenChildError);
		return -1;
	}

	ptrace(PTRACE_SETOPTIONS, childPid, NULL, PTRACE_O_EXITKILL);
	waitpid(childPid, &childStatus, 0);
	ptrace(PTRACE_SETOPTIONS, childPid, NULL, PTRACE_O_EXITKILL);
	ptrace(PTRACE_SETOPTIONS, childPid, NULL, PTRACE_O_TRACESYSGOOD);

	while (true) {
		ptrace(PTRACE_SYSCALL, childPid, NULL, NULL);
		do {
			waitpid(childPid, &childStatus, 0);

			if (WIFSIGNALED(childStatus)) {
				printf("error: child killed by signal\n");
				munmap(pChildError, sizeof (*pChildError));
				return -1;
			}
			if (WIFEXITED(childStatus)) {
				break;
			}

			if (!WIFSTOPPED(childStatus) || !(WSTOPSIG(childStatus) & 0x80)) {
				ptrace(PTRACE_SYSCALL, childPid, NULL, NULL);
			} else {
				break;
			}
		} while (true);

		if (WIFEXITED(childStatus)) {
			break;
		}

		ptrace_get_reg_content(childPid, &gPRegs);
		printf("callno: %d\treted: %d  ", SYSCALL_REG_CALLNO(gPRegs), SYSCALL_RETED(gPRegs));
		origSyscallArg0 = SYSCALL_REG_ARG0(gPRegs);

		if (lastSkippedCall != -1) {
			SYSCALL_SETCALLNO(gPRegs, lastSkippedCall);
			SYSCALL_REG_RETURN(gPRegs) = ignoredSyscallRet[lastSkippedCall];
			lastSkippedCall = -1;
			ptrace_set_reg_content(childPid, &gPRegs);
		}
		if (!SYSCALL_RETED(gPRegs) && lastSkippedCall == -1 && ignoredSyscall[SYSCALL_REG_CALLNO(gPRegs)]) {
			lastSkippedCall = SYSCALL_REG_CALLNO(gPRegs);
			SYSCALL_SETCALLNO(gPRegs, NO_SYSCALL);
			printf("ign");
			ptrace_set_reg_content(childPid, &gPRegs);
		} else {
			printf("   ");
		}

		printf("  retval: %llu\n", SYSCALL_REG_RETURN(gPRegs));
	}

	switch (pChildError[0]) {
		case 0: {
			munmap(pChildError, sizeof (*pChildError));
			return 0;
		}
		case 1: {
			printf("error: child ptrace(PTRACE_TRACEME) failed\n");
			break;
		}
		case 2: {
			printf("error: child execle(\"./test\") failed\n");
			break;
		}
		default: {
			printf("error: child exited with unknown error\n");
			break;
		}
	}
	munmap(pChildError, sizeof (*pChildError));
	return -1;
}
