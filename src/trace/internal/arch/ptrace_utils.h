/**
 * CPU architecture specific stuff relevant for `ptrace(2)`
 *
 * Elucidation:
 *  - The ABI specifies the calling convention used for syscalls
 *    -> Those  conventions are described for every architecture
 *       in the `syscall(2)` man page
 *  - `orig_` prefix: Refers to initial value in register (on
 *      syscall enter)
 *    Used when register is used to hold the ...
 *      - syscall nr (on syscall enter) AND
 *      - return value (on syscall exit)
 */
#ifndef PTRACE_ARCH_H
#define PTRACE_ARCH_H

#include <sys/user.h>


#define NO_SYSCALL (-1)


/* ----------------------- -----------------------   arm64    ----------------------- ----------------------- */
#ifdef __aarch64__

/* - Types - */
struct user_regs_struct_full {
	__extension__ union {									 /* `__extension__` to disable anonymous struct/union warning */
		struct user_regs_struct user_regs;   /* Required to make sure alignment is correct */
		struct {  													 /* Use anonymous union + struct to access elements as if they were direct members of full struct */
			unsigned long long regs[31];
			unsigned long long sp;
			unsigned long long pc;
			unsigned long long pstate;
		};
	};
	int syscallno;
};

/* - Registers - */
#  define SYSCALL_REG_CALLNO(regss) ((const int)(regss.syscallno))
#  define SYSCALL_REG_RETURN(regss) (regss.regs[0])
#  define SYSCALL_REG_ARG0(regss) (regss.regs[0])
#  define SYSCALL_REG_ARG1(regss) (regss.regs[1])
#  define SYSCALL_REG_ARG2(regss) (regss.regs[2])
#  define SYSCALL_REG_ARG3(regss) (regss.regs[3])
#  define SYSCALL_REG_ARG4(regss) (regss.regs[4])
#  define SYSCALL_REG_ARG5(regss) (regss.regs[5])
#  define SYSCALL_RETED(regss) (regss.regs[7] == 1 && SYSCALL_REG_CALLNO(regss) != NO_SYSCALL)     // $$$ $$$ $$$ $$$ $$$  TODO: TEST $$$ $$$ $$$ $$$ $$$


/* ----------------------- ----------------------- amd64 / i386 ----------------------- ----------------------- */
#elif defined(__x86_64__) || defined(__i386__)

/* - Types - */
#  define user_regs_struct_full user_regs_struct

/* - Registers - */
#  ifdef __x86_64__
#    define SYSCALL_REG_CALLNO(regss) ((const int)(regss.orig_rax))
#    define SYSCALL_REG_RETURN(regss) (regss.rax)
#    define SYSCALL_REG_ARG0(regss) (regss.rdi)
#    define SYSCALL_REG_ARG1(regss) (regss.rsi)
#    define SYSCALL_REG_ARG2(regss) (regss.rdx)
#    define SYSCALL_REG_ARG3(regss) (regss.r10)
#    define SYSCALL_REG_ARG4(regss) (regss.r8)
#    define SYSCALL_REG_ARG5(regss) (regss.r9)
#    define SYSCALL_RETED(regss) (regss.rax != -38)     // $$$  TODO: TEST $$$
#  else /* __i386__ */
#    define SYSCALL_REG_CALLNO(regss) ((const int)(regss.orig_eax))
#    define SYSCALL_REG_RETURN(regss) (regss.eax)
#    define SYSCALL_REG_ARG0(regss) (regss.ebx)
#    define SYSCALL_REG_ARG1(regss) (regss.ecx)
#    define SYSCALL_REG_ARG2(regss) (regss.edx)
#    define SYSCALL_REG_ARG3(regss) (regss.esi)
#    define SYSCALL_REG_ARG4(regss) (regss.edi)
#    define SYSCALL_REG_ARG5(regss) (regss.ebp)
#    define SYSCALL_RETED(regss) (regss.eax != -38)     // $$$  TODO: TEST $$$
# endif


#else

#  error "Unsupported CPU arch"

#endif


/* - Function prototypes - */
long __ptrace_get_reg_content(pid_t pid, struct user_regs_struct_full *regs);


#endif /* PTRACE_ARCH_H */
