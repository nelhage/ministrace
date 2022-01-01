#ifndef TRACING_H
#define TRACING_H

#include <stdbool.h>
#include <stdlib.h>


int do_tracer(pid_t pid, bool attach_to_tracee, int pause_on_syscall_nr, bool follow_fork
#ifdef WITH_STACK_UNWINDING
            , bool print_stacktrace
#endif /* WITH_STACK_UNWINDING */
);
int do_tracee(int argc, char **argv);

#endif /* TRACING_H */
