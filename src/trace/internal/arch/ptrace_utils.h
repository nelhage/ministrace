/**
 * CPU architecture specific stuff relevant for `ptrace`(2)
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
#ifndef PTRACE_UTILS_ARCH_H
#define PTRACE_UTILS_ARCH_H

#include <sys/user.h>


/* ----------------------- ----------------------- amd64 / i386 ----------------------- ----------------------- */
#if defined(__x86_64__) || defined(__i386__)

/* -- Macros -- */
#  define user_regs_struct_full user_regs_struct

#  define NO_SYSCALL (-1)

/* - Macros for accessing registers (and other information) in `user_regs_struct` - */
#  ifdef __x86_64__
#    define USER_REGS_STRUCT_IP(regss)           (regss.rip)
#    define USER_REGS_STRUCT_SP(regss)           (regss.rsp)
#    define USER_REGS_STRUCT_SC_NO(regss)        ((const int)(regss.orig_rax))
#    define USER_REGS_STRUCT_SC_RTNVAL(regss)    (regss.rax)
#    define USER_REGS_STRUCT_SC_ARG0(regss)      (regss.rdi)
#    define USER_REGS_STRUCT_SC_ARG1(regss)      (regss.rsi)
#    define USER_REGS_STRUCT_SC_ARG2(regss)      (regss.rdx)
#    define USER_REGS_STRUCT_SC_ARG3(regss)      (regss.r10)
#    define USER_REGS_STRUCT_SC_ARG4(regss)      (regss.r8)
#    define USER_REGS_STRUCT_SC_ARG5(regss)      (regss.r9)
#    define USER_REGS_STRUCT_SC_HAS_RTNED(regss) (regss.rax != ((unsigned long long)-38))     /* -38 (ENOSYS) is put into RAX as a default return value by the kernel's syscall entry code */
#  else /* __i386__ */
#    define USER_REGS_STRUCT_IP(regss)           (regss.eip)
#    define USER_REGS_STRUCT_SP(regss)           (regss.esp)
#    define USER_REGS_STRUCT_SC_NO(regss)        ((const int)(regss.orig_eax))
#    define USER_REGS_STRUCT_SC_RTNVAL(regss)    (regss.eax)
#    define USER_REGS_STRUCT_SC_ARG0(regss)      (regss.ebx)
#    define USER_REGS_STRUCT_SC_ARG1(regss)      (regss.ecx)
#    define USER_REGS_STRUCT_SC_ARG2(regss)      (regss.edx)
#    define USER_REGS_STRUCT_SC_ARG3(regss)      (regss.esi)
#    define USER_REGS_STRUCT_SC_ARG4(regss)      (regss.edi)
#    define USER_REGS_STRUCT_SC_ARG5(regss)      (regss.ebp)
#    define USER_REGS_STRUCT_SC_HAS_RTNED(regss) (regss.eax != ((unsigned long)-38))    // $$ TODO: CHECK WHETHER CORRECT $$
# endif


// /* ----------------------- -----------------------   arm64    ----------------------- ----------------------- */
// #elif defined(__aarch64__)
//
// /* -- Macros / Types -- */
// struct user_regs_struct_full {
//   __extension__ union {                  /* `__extension__` to disable anonymous struct/union warning */
//     struct user_regs_struct user_regs;   /* Required to ensure correct alignment ?? */
//     struct {                             /* Use anonymous union + -struct to access elements as if they were direct members of `user_regs_struct_full` struct */
//       unsigned long long regs[31];       /* x0 - x30 */
//       unsigned long long sp;
//       unsigned long long pc;
//       unsigned long long pstate;         /* cpsr */
//     };
//   };
//   int syscallno;
// };
//
// #  define NO_SYSCALL (-1)
//
// /* - Macros for accessing registers (and other information) in `user_regs_struct` - */
// // (sno = x8, args = x0 to x5, rtn value = x0)
// #  define USER_REGS_STRUCT_IP(regss)           (regss.pc)
// #  define USER_REGS_STRUCT_SP(regss)           (regss.sp)
// #  define USER_REGS_STRUCT_SC_NO(regss)        ((const int)(regss.syscallno))
// #  define USER_REGS_STRUCT_SC_RTNVAL(regss)    (regss.regs[0])
// #  define USER_REGS_STRUCT_SC_ARG0(regss)      (regss.regs[0])
// #  define USER_REGS_STRUCT_SC_ARG1(regss)      (regss.regs[1])
// #  define USER_REGS_STRUCT_SC_ARG2(regss)      (regss.regs[2])
// #  define USER_REGS_STRUCT_SC_ARG3(regss)      (regss.regs[3])
// #  define USER_REGS_STRUCT_SC_ARG4(regss)      (regss.regs[4])
// #  define USER_REGS_STRUCT_SC_ARG5(regss)      (regss.regs[5])
// #  define USER_REGS_STRUCT_SC_HAS_RTNED(regss) (regss.regs[7] == 1 && USER_REGS_STRUCT_SC_NO(regss) != NO_SYSCALL)    // reg[7] is 0 before syscall and 1 after


#else

#  error "Unsupported CPU arch"

#endif

#endif /* PTRACE_UTILS_ARCH_H */
