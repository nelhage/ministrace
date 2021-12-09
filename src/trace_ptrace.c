#include "trace_ptrace.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "error.h"


long __get_reg_content(pid_t pid, size_t off_user_struct) {
    /*
     * ELUCIDATION:
     *   - `PTRACE_PEEKUSER`: Read & return a word at offset `addr` (must be word-aligned) in the
     *      tracee's USER area (see <sys/user.h>), which holds the registers & other process information
     */
    long reg_val = ptrace(PTRACE_PEEKUSER, pid, off_user_struct);
    if (errno) {
        PRINT_ERR(strerror(errno));
        exit(1);
    }
    return reg_val;
}


/*
 * ELUCIDATION:
 *   Syscall args (up to 6) are passed on
 *      amd64 in rdi, rsi, rdx, r10, r8, and r9
 */
long get_syscall_arg(pid_t pid, int which) {
    switch (which) {
#ifdef __amd64__
        case 0: return get_reg_content(pid, rdi);
        case 1: return get_reg_content(pid, rsi);
        case 2: return get_reg_content(pid, rdx);
        case 3: return get_reg_content(pid, r10);
        case 4: return get_reg_content(pid, r8);
        case 5: return get_reg_content(pid, r9);
#else
        case 0: return get_reg_content(pid, ebx);
        case 1: return get_reg_content(pid, ecx);
        case 2: return get_reg_content(pid, edx);
        case 3: return get_reg_content(pid, esi);
        case 4: return get_reg_content(pid, edi);
        case 5: return get_reg_content(pid, ebp);
#endif
        default: return -1L;
    }
}


char *read_string(pid_t pid, unsigned long addr) {
    char *read_str;
    size_t read_str_size_bytes = 2048;
/* Allocate memory as buffer for string to be read */
    if (!(read_str = malloc(read_str_size_bytes))) {
        PRINT_ERR("malloc: Failed to allocate memory");
        exit(1);
    }

    size_t read_bytes = 0;
    unsigned long ptrace_read_word;
    while (1) {
    /* Increase buffer size of too small */
        if (read_bytes + sizeof(ptrace_read_word) > read_str_size_bytes) {
            read_str_size_bytes *= 2;
            if (!(read_str = realloc(read_str, read_str_size_bytes))) {
                PRINT_ERR("realloc: Failed to allocate memory");
                exit(1);
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
