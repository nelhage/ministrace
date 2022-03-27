#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>

#include "ptrace_utils.h"

#include "../../common/error.h"

/* -- Consts -- */
#ifndef PRINT_COMPLETE_STRING_ARGS
#  define STRING_MAX_WORDS_TO_BE_READ 25
#endif /* PRINT_COMPLETE_STRING_ARGS */


/* -- Functions -- */
char *ptrace_read_string(pid_t tid, unsigned long addr) {
    size_t read_bytes = 0;
    unsigned long ptrace_read_word;

/* Allocate memory as buffer for string to be read */
    char *read_str;
#ifdef PRINT_COMPLETE_STRING_ARGS
    size_t read_str_size_bytes = 2048;
#else
    size_t read_str_size_bytes = STRING_MAX_WORDS_TO_BE_READ * sizeof(ptrace_read_word);
#endif /* PRINT_COMPLETE_STRING_ARGS */

    if (!(read_str = malloc(read_str_size_bytes))) {
        LOG_ERROR_AND_EXIT("`malloc`: Failed to allocate memory");
    }

/* Read string using ptrace */
    while (1) {
    /* Increase buffer size if too small */
        if (read_bytes + sizeof(ptrace_read_word) > read_str_size_bytes) {
#ifdef PRINT_COMPLETE_STRING_ARGS
            read_str_size_bytes *= 2;
            if (!(read_str = realloc(read_str, read_str_size_bytes))) {
                LOG_ERROR_AND_EXIT("`realloc`: Failed to allocate memory");
            }
#else
            /* If limit has been reached, add shortened suffix + NUL-terminate string */
            const char* const shortened_str_suf = "[...]";
            const size_t shortened_str_suf_len = strlen(shortened_str_suf) + 1;
            strncpy(&(read_str[read_bytes - shortened_str_suf_len]), shortened_str_suf, shortened_str_suf_len);
            break;
#endif /* PRINT_COMPLETE_STRING_ARGS */
        }

    /* Read from tracee (each time one word) */
        errno = 0;
        ptrace_read_word = ptrace(PTRACE_PEEKDATA, tid, addr + read_bytes);
        if (errno) {
            read_str[read_bytes] = '\0';
            break;
        }
    /* Append read word to buffer */
        memcpy(read_str + read_bytes, &ptrace_read_word, sizeof(ptrace_read_word));
    /* Read end of string ? */
        if (memchr(&ptrace_read_word, 0, sizeof(ptrace_read_word)) != NULL) {
            break;
        }
    /* Update read_bytes counter */
        read_bytes += sizeof(ptrace_read_word);
    }
    return read_str;
}
