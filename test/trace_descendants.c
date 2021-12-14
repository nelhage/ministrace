//
// Test tracing grandchildren
//
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include "../src/error.h"

#define MAX_CHILDREN 10


void create_children(int *count, int max) {
    if (! DIE_WHEN_ERRNO(fork()) ) {
        printf("My pid %d, my ppid %d\n", getpid(), getppid());
        nanosleep((const struct timespec[]){{0, 300000000L}}, NULL);

        if (((*count)++) <= MAX_CHILDREN) {
            create_children(count, max);
        }
    } else {
        DIE_WHEN_ERRNO(wait(NULL));
    }
}


int main(void) {
    /* Disable IO buffering for stdout */
    setvbuf(stdout, NULL, _IONBF, 0);

    int child_count = 0;
    create_children(&child_count, MAX_CHILDREN);

    return 0;
}
