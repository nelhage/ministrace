#ifndef TRACE_PTRACE_H
#define TRACE_PTRACE_H

#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>

#include <unistd.h>


/* -- Macros / Function prototypes -- */
/*
 * ELUCIDATION:
 *  - The ABI specifies the calling convention used for syscalls
 *    -> Calling conventions for every architecture are described
 *       in the `syscall(2)` man page
 *  - `orig_` prefix: Refers to initial value in register (on
 *      syscall enter)
 *    Used when register is used to hold the ...
 *      - syscall nr (on syscall enter) AND
 *      - return value (on syscall exit)
 */
#if defined(__amd64__)
#  define REG_SYSCALL_NR orig_rax
#  define REG_SYSCALL_RTN_VAL rax
#  define REG_SYSCALL_ARG0 rdi
#  define REG_SYSCALL_ARG1 rsi
#  define REG_SYSCALL_ARG2 rdx
#  define REG_SYSCALL_ARG3 r10
#  define REG_SYSCALL_ARG4 r8
#  define REG_SYSCALL_ARG5 r9

#elif defined(__i386__)
#  define REG_SYSCALL_NR orig_eax
#  define REG_SYSCALL_RTN_VAL eax
#  define REG_SYSCALL_ARG0 ebx
#  define REG_SYSCALL_ARG1 ecx
#  define REG_SYSCALL_ARG2 edx
#  define REG_SYSCALL_ARG3 esi
#  define REG_SYSCALL_ARG4 edi
#  define REG_SYSCALL_ARG5 ebp

#else
#  error "Unsupported CPU arch"
#endif

#define PTRACE_TRAP_INDICATOR_BIT (1 << 7)


long __get_reg_content(pid_t pid, size_t off_user_struct);
#define offsetof(a, b) __builtin_offsetof(a, b)
#define get_reg_content(pid, reg_name) __get_reg_content(pid, offsetof(struct user, regs.reg_name))

long get_syscall_arg(pid_t pid, int which);
char *read_string(pid_t pid, unsigned long addr);


#endif /* TRACE_PTRACE_H */
