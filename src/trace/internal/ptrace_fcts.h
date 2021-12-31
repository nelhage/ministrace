/**
 * Functions utilizing `ptrace(2)` which make tracing easier
 */
#ifndef PTRACE_FCTS_H
#define PTRACE_FCTS_H

#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>

#include <unistd.h>


/* -- Macros / Function prototypes -- */
/*
 * ELUCIDATION:
 *  - The ABI specifies the calling convention used for syscalls
 *    -> Those  conventions are described for every architecture
 *       in the `syscall(2)` man page
 *  - `orig_` prefix: Refers to initial value in register (on
 *      syscall enter)
 *    Used when register is used to hold the ...
 *      - syscall nr (on syscall enter) AND
 *      - return value (on syscall exit)
 */


long __get_reg_content(pid_t pid, size_t off_user_struct);
#define offsetof(a, b) __builtin_offsetof(a, b)
#define get_reg_content(pid, reg_name) __get_reg_content(pid, offsetof(struct user, regs.reg_name))

long get_syscall_arg(pid_t pid, int which);


char *read_string(pid_t pid, unsigned long addr);


#endif /* PTRACE_FCTS_H */
