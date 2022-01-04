/**
 * Used for unwinding stack
 */
#ifndef UNWIND_H
#define UNWIND_H

#include <unistd.h>


/* -- Function prototypes -- */
void unwind_init(void);
void unwind_fin(void);
void unwind_print_backtrace_of_pid(pid_t pid);


#endif /* UNWIND_H */
