#ifndef TRACE_PTRACE_H
#define TRACE_PTHRACE_H

#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>

#include <unistd.h>


/* -- Macros / Function prototypes -- */
/*
 * ELUCIDATION:
 *  - `ORIG_RAX` = Value of RAX BEFORE syscall (syscall nr)
 *  - `RAX`      = Return value of syscall
 */
#ifdef __amd64__
#  define REG_SYSCALL_NR orig_rax
#  define REG_SYSCALL_RTN_VAL rax
#else
#  define REG_SYSCALL_NR orig_eax
#  define REG_SYSCALL_RTN_VAL eax
#endif

#define PTRACE_TRAP_INDICATOR_BIT (1 << 7)


long __get_reg_content(pid_t pid, size_t off_user_struct);
#define offsetof(a, b) __builtin_offsetof(a, b)
#define get_reg_content(pid, reg_name) __get_reg_content(pid, offsetof(struct user, regs.reg_name))

long get_syscall_arg(pid_t pid, int which);
char *read_string(pid_t pid, unsigned long addr);


#endif /* TRACE_PTRACE_H */
