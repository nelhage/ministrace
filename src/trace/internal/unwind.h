#ifndef UNWIND_H
#define UNWIND_H

#include <unistd.h>

void print_backtrace_of_tracee(pid_t pid);

#endif /* UNWIND_H */
