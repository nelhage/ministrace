#ifndef SYSCALLS_H
#define SYSCALLS_H


#define SYSCALL_MAX_ARGS 6


/* -- Types -- */
typedef enum argtype {
    ARG_INT,
    ARG_PTR,
    ARG_STR
} argtype;

typedef struct syscall_entry {
    const char* const name;
    const int nargs;
    const argtype args[SYSCALL_MAX_ARGS];
} syscall_entry;


#endif /* SYSCALLS_H */
