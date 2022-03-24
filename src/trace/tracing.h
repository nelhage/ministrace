#ifndef TRACING_H
#define TRACING_H

#include <stdbool.h>
#include <stdlib.h>


/* -- Types -- */
typedef struct {
  pid_t tracee_pid;
  bool attach_to_tracee;
  long pause_on_syscall_nr;
  const bool* syscall_subset_to_be_traced;
  bool follow_fork;
  bool daemonize;
#ifdef WITH_STACK_UNWINDING
  bool print_stacktrace;
#endif /* WITH_STACK_UNWINDING */
} tracer_options_t;


/* -- Function prototypes -- */
int do_tracee(int argc, char** argv,
              tracer_options_t* options);
int do_tracer(tracer_options_t* options);


#endif /* TRACING_H */
