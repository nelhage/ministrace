#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../common/error.h"
#include "generated/syscallents.h"
#include "ptrace_utils.h"
#include "syscall_types.h"
#include "syscalls.h"


/* -- Function prototypes -- */
static void _fprint_str_esc(FILE* restrict stream, char *str);
static inline long _from_regs_struct_get_syscall_arg(struct user_regs_struct_full *regs, int which);


/* -- Functions -- */
const char *syscalls_get_name(long syscall_nr) {
    if (syscall_nr >= 0 && syscall_nr <= MAX_SYSCALL_NUM) {
        const syscall_entry* const scall = &syscalls[syscall_nr];
        if (scall->name) {  /* NOTE: Syscall-nrs may be non-consecutive (i.e., array has empty slots) */
            return scall->name;
        }
    }
    return NULL;
}

long syscalls_get_nr(char* syscall_name) {
    for (int i = 0; i < SYSCALLS_ARR_SIZE; i++) {
        const syscall_entry* const scall = &syscalls[i];
        if (scall->name && !strcmp(syscall_name, scall->name)) {  /* NOTE: Syscall-nrs may be non-consecutive (i.e., array has empty slots) */
            return i;
        }
    }
    return -1L;
}


void syscalls_print_args(__attribute__((unused)) pid_t tid, struct user_regs_struct_full *regs) {   // `user_regs_struct_full *regs` only for efficiency sake (not necessary, could be fetched again ...)
    const long syscall_nr = SYSCALL_REG_CALLNO((*regs));

    const syscall_entry* ent = NULL;
    int nargs = SYSCALL_MAX_ARGS;

    if ((syscall_nr >= 0 && syscall_nr <= MAX_SYSCALL_NUM) && syscalls[syscall_nr].name) {
        ent = &syscalls[syscall_nr];
        nargs = ent->nargs;
    } else {
        LOG_DEBUG("Unknown syscall w/ nr %ld", syscall_nr);
    }

    for (int arg_nr = 0; arg_nr < nargs; arg_nr++) {
        long arg = _from_regs_struct_get_syscall_arg(regs, arg_nr);
        long type = ent ? ent->args[arg_nr] : ARG_PTR;      /* Default to `ARG_PTR` */
        switch (type) {
            case ARG_INT:
                fprintf(stderr, "%ld", arg);
                break;
            case ARG_STR: {
                char* strval = ptrace_read_string(tid, arg);

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

static inline long _from_regs_struct_get_syscall_arg(struct user_regs_struct_full *regs, int which) {
    switch (which) {
        case 0: return SYSCALL_REG_ARG0((*regs));
        case 1: return SYSCALL_REG_ARG1((*regs));
        case 2: return SYSCALL_REG_ARG2((*regs));
        case 3: return SYSCALL_REG_ARG3((*regs));
        case 4: return SYSCALL_REG_ARG4((*regs));
        case 5: return SYSCALL_REG_ARG5((*regs));

        default: return -1L;        /* Invalid */
    }
}

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


/* - Misc. - */
void syscalls_print_all(void) {
    for (int i = 0; i < SYSCALLS_ARR_SIZE; i++) {
        const syscall_entry* const scall = &syscalls[i];
        if (NULL != scall->name) {
            printf("\t%d: %s\n", i, scall->name);
        }
    }
}
