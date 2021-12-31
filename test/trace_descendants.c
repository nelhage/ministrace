//
// Test tracing grandchildren
//
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include "../src/common/error.h"

#include <stdlib.h>

#define MAX_CHILDREN 10


void create_children(const int max_children) {
    static int child_count = 0;

    if ((child_count)++ >= max_children) {
        puts("");
        return;
    }

    pid_t child;
/* Child */
    if (! (child = DIE_WHEN_ERRNO(fork())) ) {
        nanosleep((const struct timespec[]){{0, 300000000L}}, NULL);
        printf("Descendant #%2d: pid=%d, ppid=%d\n", child_count, getpid(), getppid());

        create_children(max_children);


/* Parent */
    } else {
        const int descendent_nr = child_count -1;
        const pid_t own_pid = getpid();

        if (0 == descendent_nr) {
            printf("--- MAIN ---  : pid=%d, ppid=%d\n", own_pid, getppid());
        }

        int status;
        DIE_WHEN_ERRNO(waitpid(child, &status, 0));

        if (0 == descendent_nr) {
            printf("--- MAIN ---  : ");
        } else {
            printf("Descendant #%2d: ", descendent_nr);
        }
        printf("pid=%d, child(pid=%d) exitstatus=", own_pid, child);


        if (WIFEXITED(status)) {
            printf("%d", WEXITSTATUS(status));
        } else {
            printf("unknown");
        }

        srand(time(NULL) ^ (own_pid << 16));
        const int own_exit_code = rand() % 2;
        printf(" (exit status for this process=%d)\n", own_exit_code);

        exit(own_exit_code);               // Varying exit codes for validating
    }
}


int main(void) {
    /* Disable IO buffering for stdout */
    setvbuf(stdout, NULL, _IONBF, 0);

    create_children(MAX_CHILDREN);

    return 0;
}
