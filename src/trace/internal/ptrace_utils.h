/**
 * Functions utilizing `ptrace`(2)
 */
#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

#include <unistd.h>
#include "arch/ptrace_utils.h"


/* -- Function prototypes -- */
int ptrace_get_regs_content(pid_t tid, struct user_regs_struct_full *regs);
size_t ptrace_read_string(pid_t tid, unsigned long addr,
                          ssize_t bytes_to_read,
                          char** read_str_ptr_ptr);        /* WARNING: MUST BE `free`(3)'ed */

#endif /* PTRACE_UTILS_H */
