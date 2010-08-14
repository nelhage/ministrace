#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#define offsetof(a, b) __builtin_offsetof(a,b)

int do_child(int argc, char **argv) {
    char *args [argc+1];
    int i;
    for (i=0;i<argc;i++)
        args[i] = argv[i];
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
        fprintf(stderr, "[stopped %d (%x)]\n", status, WSTOPSIG(status));
    }
}

int do_trace(pid_t child) {
    int status;
    int syscall, retval;
    waitpid(child, &status, 0);
    assert(WIFSTOPPED(status));
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while(1) {
        if (wait_for_syscall(child) != 0)
            break;

        syscall = ptrace(PTRACE_PEEKUSER, child, offsetof(struct user, regs.orig_eax));
        assert(errno == 0);

        fprintf(stderr, "syscall(%d) = ", syscall);

        if (wait_for_syscall(child) != 0)
            break;

        retval = ptrace(PTRACE_PEEKUSER, child, offsetof(struct user, regs.eax));
        assert(errno == 0);

        fprintf(stderr, "%d\n", retval);
    }
    return 0;
}


int main(int argc, char **argv) {
    pid_t child;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s prog args\n", argv[0]);
        exit(1);
    }

    child = fork();
    if (child == 0) {
        return do_child(argc-1, argv+1);
    } else {
        return do_trace(child);
    }
}
