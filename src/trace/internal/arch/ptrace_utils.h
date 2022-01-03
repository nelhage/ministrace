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


/* ----------------------- ----------------------- amd64 / i386 ----------------------- ----------------------- */
#if defined(__x86_64__) || defined(__i386__)

/* - Types - */
#  define user_regs_struct_full user_regs_struct

/* - Registers - */
#  ifdef __x86_64__
#    define SYSCALL_REG_CALLNO(regss) ((const int)(regss.orig_rax))
#    define SYSCALL_REG_RETURN(regss) (regss.rax)
#    define SYSCALL_REG_ARG0(regss)   (regss.rdi)
#    define SYSCALL_REG_ARG1(regss)   (regss.rsi)
#    define SYSCALL_REG_ARG2(regss)   (regss.rdx)
#    define SYSCALL_REG_ARG3(regss)   (regss.r10)
#    define SYSCALL_REG_ARG4(regss)   (regss.r8)
#    define SYSCALL_REG_ARG5(regss)   (regss.r9)
#    define SYSCALL_RETED(regss)      (regss.rax != ((unsigned long long)-38))     /* -38 is ENOSYS which is put into RAX as a default return value by the kernel's syscall entry code */
#  else /* __i386__ */
#    define SYSCALL_REG_CALLNO(regss) ((const int)(regss.orig_eax))
#    define SYSCALL_REG_RETURN(regss) (regss.eax)
#    define SYSCALL_REG_ARG0(regss)   (regss.ebx)
#    define SYSCALL_REG_ARG1(regss)   (regss.ecx)
#    define SYSCALL_REG_ARG2(regss)   (regss.edx)
#    define SYSCALL_REG_ARG3(regss)   (regss.esi)
#    define SYSCALL_REG_ARG4(regss)   (regss.edi)
#    define SYSCALL_REG_ARG5(regss)   (regss.ebp)
#    define SYSCALL_RETED(regss)      (regss.eax != ((unsigned long)-38))		// $$ TODO: CHECK WHETHER CORRECT $$
# endif


// /* ----------------------- -----------------------   arm64    ----------------------- ----------------------- */
// #elif defined(__aarch64__)
//
// /* - Types - */
// struct user_regs_struct_full {
// 	__extension__ union {                  /* `__extension__` to disable anonymous struct/union warning */
// 		struct user_regs_struct user_regs;   /* Required to ensure correct alignment ?? */
// 		struct {                             /* Use anonymous union + -struct to access elements as if they were direct members of `user_regs_struct_full` struct */
//   		unsigned long long regs[31];       /* x0 - x30 */
//   		unsigned long long sp;
//   		unsigned long long pc;
//   		unsigned long long pstate;         /* cpsr */
// 		};
// 	};
// 	int syscallno;
// };
//
// #define NO_SYSCALL (-1)
//
// /* - Registers (sno = x8, args = x0 to x5, rtn value = x0) - */
// #  define SYSCALL_REG_CALLNO(regss) ((const int)(regss.syscallno))
// #  define SYSCALL_REG_RETURN(regss) (regss.regs[0])
// #  define SYSCALL_REG_ARG0(regss)   (regss.regs[0])
// #  define SYSCALL_REG_ARG1(regss)   (regss.regs[1])
// #  define SYSCALL_REG_ARG2(regss)   (regss.regs[2])
// #  define SYSCALL_REG_ARG3(regss)   (regss.regs[3])
// #  define SYSCALL_REG_ARG4(regss)   (regss.regs[4])
// #  define SYSCALL_REG_ARG5(regss)   (regss.regs[5])
// #  define SYSCALL_RETED(regss)      (regss.regs[7] == 1 && SYSCALL_REG_CALLNO(regss) != NO_SYSCALL)    // reg[7] is 0 before syscall and 1 after


#else

#  error "Unsupported CPU arch"

#endif


#endif /* PTRACE_ARCH_H */
