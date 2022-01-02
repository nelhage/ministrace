/**
 * Functions which make use of `syscallents` type
 *   May also make use of "ptrace_utils"
 */
#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

#include <unistd.h>


/* -- Function prototypes -- */
const char *get_syscall_name(long syscall_nr);
long get_syscall_nr(char* syscall_name);

void print_syscall_args(pid_t pid, long syscall_nr);

void print_all_supported_syscalls(void);

#endif /* TRACE_SYSCALLS_H */
