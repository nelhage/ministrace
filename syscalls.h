#define SYSCALL_MAX_ARGS 6


enum argtype {
    ARG_INT,
    ARG_PTR,
    ARG_STR
};

struct syscall_entry {
    const char* const name;
    const int nargs;
    const enum argtype args[SYSCALL_MAX_ARGS];
};
