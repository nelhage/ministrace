#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

#include <unistd.h>


/* -- Function prototypes -- */
const char *get_syscall_name(int syscall_nr);
void print_syscall_args(pid_t pid, int syscall_nr);


#endif /* TRACE_SYSCALLS_H */
