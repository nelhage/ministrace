// Example of static lookup table

#ifndef IOTRACE_H
#define IOTRACE_H

#include "syscallents.h"          /* SYSCALLS_ARR_SIZE, __SNR_xxxxxxx */

/* ---
/* -- Functions -- */
bool syscall_is_io_pertinent(long syscall_nr) {
    const static bool io_fct_lookup_table[SYSCALLS_ARR_SIZE] = {
        [__SNR_read] = true,
        [__SNR_write] = true,
        [__SNR_open] = true,
        [__SNR_close] = true,
        [__SNR_stat] = true,
        [__SNR_fstat] = true,
        [__SNR_lstat] = true,
        [__SNR_poll] = true,
        [__SNR_lseek] = true,
        [__SNR_ioctl] = true,
        [__SNR_pread64] = true,
        [__SNR_pwrite64] = true,
        [__SNR_readv] = true,
        [__SNR_writev] = true,
        [__SNR_access] = true,
        [__SNR_pipe] = true,
        [__SNR_select] = true,
        [__SNR_dup] = true,
        [__SNR_dup2] = true,
        [__SNR_socket] = true,
        [__SNR_connect] = true,
        [__SNR_sendmsg] = true,
        [__SNR_recvmsg] = true,
        [__SNR_bind] = true,
        [__SNR_listen] = true,
        [__SNR_fcntl] = true,
        [__SNR_rename] = true,
        [__SNR_mkdir] = true,
        [__SNR_rmdir] = true,
        [__SNR_creat] = true,
        [__SNR_link] = true,
        [__SNR_unlink] = true,
        [__SNR_symlink] = true,
        [__SNR_readlink] = true,
        [__SNR_chmod] = true,
        [__SNR_fchmod] = true,
        [__SNR_chown] = true,
        [__SNR_fchown] = true,
        [__SNR_lchown] = true,
        [__SNR_accept4] = true,
        [__SNR_dup3] = true,
        [__SNR_pipe2] = true,
        [__SNR_preadv] = true,
        [__SNR_pwritev] = true
    };

    return io_fct_lookup_table[syscall_nr];
}


#endif /* IOTRACE_H */
