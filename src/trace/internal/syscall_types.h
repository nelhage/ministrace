#ifndef SYSCALL_TYPES_H
#define SYSCALL_TYPES_H

#define SYSCALL_MAX_ARGS 6

/* -- Types -- */
typedef enum {
    ARG_INT,
    ARG_PTR,
    ARG_STR
} arg_type;

typedef struct {
    const char* const name;
    const int nargs;
    const arg_type args[SYSCALL_MAX_ARGS];
} syscall_entry;


#endif /* SYSCALL_TYPES_H */
