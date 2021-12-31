/**
 * CPU architecture specific stuff relevant for `ptrace(2)`
 */
#ifndef PTRACE_ARCH_H
#define PTRACE_ARCH_H

/*
 * ELUCIDATION:
 *  - The ABI specifies the calling convention used for syscalls
 *    -> Those  conventions are described for every architecture
 *       in the `syscall(2)` man page
 *  - `orig_` prefix: Refers to initial value in register (on
 *      syscall enter)
 *    Used when register is used to hold the ...
 *      - syscall nr (on syscall enter) AND
 *      - return value (on syscall exit)
 */
#if defined(__amd64__)
#  define REG_SYSCALL_NR orig_rax
#  define REG_SYSCALL_RTN_VAL rax
#  define REG_SYSCALL_ARG0 rdi
#  define REG_SYSCALL_ARG1 rsi
#  define REG_SYSCALL_ARG2 rdx
#  define REG_SYSCALL_ARG3 r10
#  define REG_SYSCALL_ARG4 r8
#  define REG_SYSCALL_ARG5 r9

#elif defined(__i386__)
#  define REG_SYSCALL_NR orig_eax
#  define REG_SYSCALL_RTN_VAL eax
#  define REG_SYSCALL_ARG0 ebx
#  define REG_SYSCALL_ARG1 ecx
#  define REG_SYSCALL_ARG2 edx
#  define REG_SYSCALL_ARG3 esi
#  define REG_SYSCALL_ARG4 edi
#  define REG_SYSCALL_ARG5 ebp

#else
#  error "Unsupported CPU arch"
#endif


#endif /* PTRACE_ARCH_H */
