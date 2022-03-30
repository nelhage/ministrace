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
size_t ptrace_read_string(pid_t tid, unsigned long addr,
                         ssize_t bytes_to_read,
                         char** read_str_ptr_ptr) {

    unsigned long ptrace_read_word;
/* 0. Allocate memory as buffer for string to be read */
#ifdef PRINT_COMPLETE_STRING_ARGS
    size_t read_str_size_bytes = 2048;
#else
    size_t read_str_size_bytes = STRING_MAX_WORDS_TO_BE_READ * sizeof(ptrace_read_word);
#endif /* PRINT_COMPLETE_STRING_ARGS */

    char *read_str_ptr = NULL;
    if (! (read_str_ptr = malloc(read_str_size_bytes)) ) {
        LOG_ERROR_AND_EXIT("`malloc`: Failed to allocate memory");
    }
    *read_str_ptr_ptr = read_str_ptr;

/* 1. Read string using ptrace */
    for (size_t read_bytes = 0; ; ) {

    /* 1.1. Increase buffer size if too small */
        if (read_bytes + sizeof(ptrace_read_word) > read_str_size_bytes) {
#ifdef PRINT_COMPLETE_STRING_ARGS
            read_str_size_bytes *= 2;
            if (! (read_str_ptr = realloc(read_str_ptr, read_str_size_bytes)) ) {
                LOG_ERROR_AND_EXIT("`realloc`: Failed to allocate memory");
            }
            *read_str_ptr_ptr = read_str_ptr;
#else
            /* If limit has been reached, add shortened suffix + NUL-terminate string */
            const char* const shortened_str_suf = "[...]";
            const size_t shortened_str_suf_len = strlen(shortened_str_suf) + 1;
            strncpy(&(read_str_ptr[read_bytes - shortened_str_suf_len]), shortened_str_suf, shortened_str_suf_len);

            return read_bytes -1;     /* Length excl. NUL byte */
#endif /* PRINT_COMPLETE_STRING_ARGS */
        }

    /* 1.2. Read from tracee (each time one word) */
        errno = 0;
        ptrace_read_word = ptrace(PTRACE_PEEKDATA, tid, addr + read_bytes);
    /* 1.2.1. Check for errors */
        if (errno) {
            read_str_ptr[read_bytes] = '\0';
            return read_bytes -1;            /* Length excl. NUL byte */
        }

    /* 1.3. Append read word to buffer */
        memcpy(read_str_ptr + read_bytes, &ptrace_read_word, sizeof(ptrace_read_word));

    /* 1.4. Update `read_bytes` counter */
        read_bytes += sizeof(ptrace_read_word);

    /* 1.5. Read end of string ? */
    // WE KNOW HOW # OF BYTES (e.g., due to `read`(2) or `write`(2) syscall -- which may take in arbitrary binary data (i.e., doesn't have to be NUL terminated) + a size)
        if (bytes_to_read >= 0) {
            if (read_bytes >= (size_t)bytes_to_read) {
                read_str_ptr[bytes_to_read] = '\0'; /* Must be after ALL bytes (hence no -1) */
                return bytes_to_read - 1;    /* Length excl. NUL byte */
            }
        }

    // WE DON'T KNOW # OF BYTES -> Look out for NUL-byte
        else {
            if (memchr(&ptrace_read_word, '\0', sizeof(ptrace_read_word))) {
                return strlen(read_str_ptr);
            }
        }
    }
}
