#define MAXARGS 6
enum argtype {
    ARG_INT,
    ARG_PTR,
    ARG_STR
};

struct syscall_entry {
    const char *name;
    int nargs;
    enum argtype args[MAXARGS];
};
