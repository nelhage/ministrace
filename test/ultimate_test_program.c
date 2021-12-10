// gcc ultimate_test_program.c -o ultimate_test_program -lpthread

#define _GNU_SOURCE         /* Necessary for gettid */
#include <stdio.h>          /* fprintf, printf, setvbuf, stdout, _IONBF */
#include <unistd.h>         /* write, getpid, getppid, gettid, getpgid, getsid, _exit */

#include <stdlib.h>         /* exit */

#include <pthread.h>        /* pthread_t, pthread_create, pthread_join */
#include <sys/wait.h>       /* wait */

#include <string.h>         /* strcmp */

#include <errno.h>          /* errno */
#include <signal.h>         /* sigaction, sigemptyset, SA_RESTART, SIGSTOP, SIGCONT, SIGINT, SIGUSR1, SIGUSR2, SIGCHLD, SIGHUP */

#include <time.h>           /* nanosleep, timespec */

#include <stdbool.h>        /* bool */


/* -- Signal handlers -- */
void child_signal_handler(int sig) {
    int old_errno = errno;

    switch (sig) {
        case SIGSTOP:
            write(STDOUT_FILENO, ">> CHILD: Received SIGSTOP\n", 27);
            break;

        case SIGCONT:
            write(STDOUT_FILENO, ">> CHILD: Received SIGCONT\n", 27);
            break;

        case SIGINT:
            write(STDOUT_FILENO, ">> CHILD: Received SIGINT\n", 26);
            _exit(1);

        case SIGTERM:
            write(STDOUT_FILENO, ">> CHILD: Received SIGTERM\n", 27);
            _exit(1);

        case SIGQUIT:
            write(STDOUT_FILENO, ">> CHILD: Received SIGQUIT\n", 27);
            _exit(1);

        case SIGKILL:
            write(STDOUT_FILENO, ">> CHILD: Received SIGKILL\n", 27);
            _exit(1);

        case SIGUSR1:
            write(STDOUT_FILENO, ">> CHILD: Received SIGUSR1\n", 27);
            break;

        case SIGUSR2:
            write(STDOUT_FILENO, ">> CHILD: Received SIGUSR2\n", 27);
            break;

        case SIGCHLD:
            write(STDOUT_FILENO, ">> CHILD: Received SIGCHLD\n", 27);
            break;

        case SIGHUP:
            write(STDOUT_FILENO, ">> CHILD: Received SIGHUP\n", 26);
            break;

        default:
            write(STDOUT_FILENO, ">> ERR: Unhandled SIG\n", 22);
            break;
    }

    errno = old_errno;
}

void parent_signal_handler(int sig) {
    int old_errno = errno;

    switch (sig) {
        case SIGSTOP:
            write(STDOUT_FILENO, ">> PARENT: Received SIGSTOP\n", 28);
            break;

        case SIGCONT:
            write(STDOUT_FILENO, ">> PARENT: Received SIGCONT\n", 28);
            break;

        case SIGINT:
            write(STDOUT_FILENO, ">> PARENT: Received SIGINT\n", 27);
            _exit(1);

        case SIGTERM:
            write(STDOUT_FILENO, ">> PARENT: Received SIGTERM\n", 28);
            _exit(1);

        case SIGQUIT:
            write(STDOUT_FILENO, ">> PARENT: Received SIGQUIT\n", 28);
            _exit(1);

        case SIGKILL:
            write(STDOUT_FILENO, ">> PARENT: Received SIGKILL\n", 28);
            _exit(1);

        case SIGUSR1:
            write(STDOUT_FILENO, ">> PARENT: Received SIGUSR1\n", 28);
            break;

        case SIGUSR2:
            write(STDOUT_FILENO, ">> PARENT: Received SIGUSR2\n", 28);
            break;

        case SIGCHLD:
            write(STDOUT_FILENO, ">> PARENT: Received SIGCHLD\n", 28);
            break;

        case SIGHUP:
            write(STDOUT_FILENO, ">> PARENT: Received SIGHUP\n", 27);
            break;

        default:
            write(STDOUT_FILENO, ">> ERR: Unhandled SIG\n", 22);
            break;
    }

    errno = old_errno;
}


void register_sig_handlers(void(*sig_handler_func_ptr)(int)) {
    struct sigaction action;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);   /* Mask no signals during execution of handler */
    action.sa_handler = sig_handler_func_ptr;

    sigaction(SIGSTOP, &action, NULL);        /* cannot be handled */
    sigaction(SIGCONT, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGKILL, &action, NULL);        /* cannot be handled */
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
}



typedef struct routine_arg {
    char* pname;
    bool loop;
    void(*sig_handler_func_ptr)(int);
} routine_arg;

void* routine(void* arg) {
    const char* const pname = ((routine_arg*)arg)->pname;
    const bool loop = ((routine_arg*)arg)->loop;
    const void(*sig_handler_func_ptr)(int) = ((routine_arg*)arg)->sig_handler_func_ptr;

    register_sig_handlers(sig_handler_func_ptr);

loop:
    printf("tid = %5d, pid = %5d, ppid = %5d, pgid = %5d, sid = %5d [%s]\n",
            gettid(), getpid(), getppid(), getpgid(0), getsid(0), pname);
    nanosleep((const struct timespec[]){{3, 500000000L}}, NULL);
    if (loop) { goto loop; }

    return NULL;
}


typedef struct cli_args {
    bool loop;
    bool fork;
    bool pthread;
} cli_args;

int parse_cli_args(int argc, char** argv, cli_args* args) {
  /* - Defaults - */
    args->loop = false;
    args->fork = false;
    args->pthread = false;

    for (int i=1; i<argc; i++) {
        if (!strcmp("--loop", argv[i])) {
            args->loop = true;
            continue;
        }

        if (!strcmp("--fork", argv[i])) {
            args->fork = true;
            continue;
        }

        if (!strcmp("--pthread", argv[i])) {
            args->pthread = true;
            continue;
        }

        return -1;              /* Unrecognized option */
    }

    return (args->fork && args->pthread) ? (-1) : (0);        /* `fork` & `pthread` are mutually eXclusive */
}


int main(int argc, char** argv) {

    cli_args args;
    if (-1 == parse_cli_args(argc, argv, &args)) {
        fprintf(stderr, "Err: Invalid CLI args\n");
        return(1);
    }

    // Disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);


    if (args.fork) {
        puts("Forking child ...");
        pid_t child_pid = fork();
        if (-1 == child_pid) {
            fprintf(stderr, "Failed forking\n");
            exit(1);
        }

        routine((routine_arg[]){{ .pname = (!child_pid) ? "Child" : "Parent", .loop=args.loop, .sig_handler_func_ptr=(!child_pid) ? &child_signal_handler : &parent_signal_handler }});

        if (child_pid) {
            wait(NULL);         /* Wait for child process to exit */
        }

    } else if (args.pthread) {
        puts("Creating additional thread ...");
        pthread_t t1;
        pthread_create(&t1, NULL, routine, (routine_arg[]){{ .pname = "Thread-1", .loop=args.loop, .sig_handler_func_ptr = &child_signal_handler }});      // NOTE: Child-thread will overwrite parent's signal handler ??
        routine((routine_arg[]){{ .pname = "Thread-0", .loop=args.loop, .sig_handler_func_ptr = &parent_signal_handler }});
        pthread_join(t1, NULL);

    } else {
        puts("Running single threaded ...");
        routine((routine_arg[]){{ .loop=args.loop, .sig_handler_func_ptr = &parent_signal_handler }});
    }

    return 0;
}