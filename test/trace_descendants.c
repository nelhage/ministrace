//
// Test tracing grandchildren
//
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include "../src/error.h"

#define MAX_CHILDREN 10


void create_children(int max_children) {
    if (! DIE_WHEN_ERRNO(fork()) ) {
        static int child_count = 0;
        printf("Descendant #%2d: My pid %d, my ppid %d\n", child_count +1, getpid(), getppid());
        nanosleep((const struct timespec[]){{0, 300000000L}}, NULL);

        if (((child_count)++) < MAX_CHILDREN) {
            create_children(max_children);
        }
    } else {
        DIE_WHEN_ERRNO(wait(NULL));
    }
}


int main(void) {
    /* Disable IO buffering for stdout */
    setvbuf(stdout, NULL, _IONBF, 0);

    create_children(MAX_CHILDREN);

    return 0;
}
