#ifndef SYSCALL_TYPES_H
#define SYSCALL_TYPES_H

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


/* -- Functions -- */
static inline const char* arg_type_enum_to_str(arg_type_t arg) {
    if (((unsigned int)-1) == arg) {
        return "N/A";
    }

    static const char *strings[] = {
            [ARG_INT] = "ARG_INT",
            [ARG_PTR] = "ARG_PTR",
            [ARG_STR] = "ARG_STR"
    };
    return strings[arg];
}


#endif /* SYSCALL_TYPES_H */
