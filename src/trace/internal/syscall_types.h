#ifndef SYSCALL_TYPES_H
#define SYSCALL_TYPES_H


/* -- Consts -- */
#define SYSCALL_MAX_ARGS 6


/* -- Types -- */
typedef enum {
    ARG_INT,
    ARG_PTR,
    ARG_STR
} arg_type_t;

typedef struct {
    const char* const name;
    const int nargs;
    const arg_type_t args[SYSCALL_MAX_ARGS];
} syscall_entry_t;


/* -- Function prototypes -- */
const char* arg_type_enum_to_str(arg_type_t arg);

#endif /* SYSCALL_TYPES_H */
