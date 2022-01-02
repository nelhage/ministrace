/**
 * Functions utilizing `ptrace(2)` which make tracing easier
 */
#ifndef PTRACE_FCTS_H
#define PTRACE_FCTS_H

#include <unistd.h>


/* -- Macros / Function prototypes -- */
long ptrace_get_syscall_nr(pid_t pid);
long ptrace_get_syscall_arg(pid_t pid, int which);
long ptrace_get_syscall_rtn_value(pid_t pid);

/* WARNING: MUST BE `free(3)`'ED */
char *ptrace_read_string(pid_t pid, unsigned long addr);


#endif /* PTRACE_FCTS_H */
