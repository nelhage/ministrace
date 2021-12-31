#include "syscalls.h"

#include "syscall_types.h"
#include "generated/syscallents.h"

#include "ptrace_fcts.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <locale.h>


/* -- Function prototypes -- */
static void _fprint_str_esc(FILE* restrict stream, char* str);


/* -- Functions -- */
const char *get_syscall_name(long syscall_nr) {
    if (syscall_nr <= MAX_SYSCALL_NUM) {
        const syscall_entry* const scall = &syscalls[syscall_nr];
        if (scall->name) {
            return scall->name;
        }
    }

    static char fallback_generic_syscall_name[128];     // Warning: Not thread-safe
    snprintf(fallback_generic_syscall_name, sizeof(fallback_generic_syscall_name), "sys_%ld", syscall_nr);
    return fallback_generic_syscall_name;
}


void print_syscall_args(pid_t pid, long syscall_nr) {
    const syscall_entry* ent = NULL;
    int nargs = SYSCALL_MAX_ARGS;

    if (syscall_nr <= MAX_SYSCALL_NUM && syscalls[syscall_nr].name) {
        ent = &syscalls[syscall_nr];
        nargs = ent->nargs;
    }
    for (int arg_nr = 0; arg_nr < nargs; arg_nr++) {
        long arg = get_syscall_arg(pid, arg_nr);
        long type = ent ? ent->args[arg_nr] : ARG_PTR;      /* Default to `ARG_PTR` */
        switch (type) {
            case ARG_INT:
                fprintf(stderr, "%ld", arg);
                break;
            case ARG_STR: {
                char* strval = read_string(pid, arg);

                // fprintf(stderr, "\"%s\"", strval);
                fprintf(stderr, "\""); _fprint_str_esc(stderr, strval); fprintf(stderr, "\"");

                free(strval);
                break;
            }
            default:    /* e.g., ARG_PTR */
                fprintf(stderr, "0x%lx", (unsigned long)arg);
                break;
        }
        if (arg_nr != nargs -1)
            fprintf(stderr, ", ");
    }
}


/* - Misc. - */
void print_syscalls(void) {
    for (int i = 0; i < SYSCALLS_ARR_SIZE; i++) {
        const syscall_entry* const scall = &syscalls[i];
        if (NULL != scall->name) {
            printf("\t%d: %s\n", i, scall->name);
        }
    }
}


/* - Helper functions - */
/*
 * Prints ASCII control chars in `str` using a hex representation
 */
static void _fprint_str_esc(FILE *stream, char *str) {
    setlocale(LC_ALL, "C");

    for (int i = 0; '\0' != str[i]; i++) {
        const char c = str[i];
        if (isprint(c) && c != '\\') {
            fputc(c, stream);
        } else {
            fprintf(stream, "\\x%02x", (unsigned char)c);
        }
    }
}
