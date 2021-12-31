#include "ptrace.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "../../common/error.h"


long __get_reg_content(pid_t pid, size_t off_user_struct) {
    /*
     * ELUCIDATION:
     *   - `PTRACE_PEEKUSER`: Read & return a word at offset `addr` (must be word-aligned) in the
     *      tracee's USER area (see <sys/user.h>), which holds the registers & other process information
     */
    long reg_val = ptrace(PTRACE_PEEKUSER, pid, off_user_struct);
    if (errno) {
        LOG_ERROR_AND_EXIT("%s", strerror(errno));
    }
    return reg_val;
}


/* - Helpers - */
long get_syscall_arg(pid_t pid, int which) {
    switch (which) {
        case 0: return get_reg_content(pid, REG_SYSCALL_ARG0);
        case 1: return get_reg_content(pid, REG_SYSCALL_ARG1);
        case 2: return get_reg_content(pid, REG_SYSCALL_ARG2);
        case 3: return get_reg_content(pid, REG_SYSCALL_ARG3);
        case 4: return get_reg_content(pid, REG_SYSCALL_ARG4);
        case 5: return get_reg_content(pid, REG_SYSCALL_ARG5);

        default: return -1L;        /* Invalid */
    }
}

char *read_string(pid_t pid, unsigned long addr) {
    char *read_str;
    size_t read_str_size_bytes = 2048;
/* Allocate memory as buffer for string to be read */
    if (!(read_str = malloc(read_str_size_bytes))) {
        LOG_ERROR_AND_EXIT("`malloc`: Failed to allocate memory");
    }

    size_t read_bytes = 0;
    unsigned long ptrace_read_word;
    while (1) {
    /* Increase buffer size of too small */
        if (read_bytes + sizeof(ptrace_read_word) > read_str_size_bytes) {
            read_str_size_bytes *= 2;
            if (!(read_str = realloc(read_str, read_str_size_bytes))) {
                LOG_ERROR_AND_EXIT("`realloc`: Failed to allocate memory");
            }
        }
    /* Read from tracee (each time one word) */
        ptrace_read_word = ptrace(PTRACE_PEEKDATA, pid, addr + read_bytes);
        if (errno) {
            read_str[read_bytes] = '\0';
            break;
        }
    /* Append read word to buffer */
        memcpy(read_str + read_bytes, &ptrace_read_word, sizeof(ptrace_read_word));
    /* Read end of string ? */
        if (memchr(&ptrace_read_word, 0, sizeof(ptrace_read_word)) != NULL)
            break;
    /* Update read_bytes counter */
        read_bytes += sizeof(ptrace_read_word);
    }
    return read_str;
}
