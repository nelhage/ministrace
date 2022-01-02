/**
 * Functions utilizing `ptrace(2)` which make tracing easier
 */
#ifndef PTRACE_FCTS_H
#define PTRACE_FCTS_H

#include <stdbool.h>
#include <unistd.h>


/* -- Macros / Function prototypes -- */
long ptrace_get_syscall_nr(pid_t tid);
long ptrace_get_syscall_arg(pid_t tid, int which);
long ptrace_get_syscall_rtn_value(pid_t tid);
bool ptrace_syscall_has_returned(pid_t tid);

/* WARNING: MUST BE `free(3)`'ED */
char *ptrace_read_string(pid_t tid, unsigned long addr);


#endif /* PTRACE_FCTS_H */
