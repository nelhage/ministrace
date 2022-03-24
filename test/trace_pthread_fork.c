/**
 * Small test program which allows creating processes (using `fork`) or threads (using pthread lib)
 * which in turn print info about themselves (tid, pid, ppid, etc.)
 */
#define _GNU_SOURCE         /* Necessary for gettid */
#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>

#include <pthread.h>
#include <sys/wait.h>

#include <string.h>

#include <errno.h>
#include <signal.h>

#include <time.h>

#include <stdbool.h>

#include "../src/common/error.h"



/* -- CLI stuff -- */
#define CLI_FORK_OPTION    "--fork"
#define CLI_PTHREAD_OPTION "--pthread"
#define CLI_LOOP_OPTION    "--loop"
#define CLI_HELP_OPTION    "--help"

void usage(char** argv) {
    fprintf(stderr, "Usage: %s ["CLI_LOOP_OPTION"] ["CLI_FORK_OPTION" | "CLI_PTHREAD_OPTION"]\n", argv[0]);
}

typedef struct {
    bool loop;
    bool fork;
    bool pthread;
} cli_args_t;

int parse_cli_args(int argc, char** argv, cli_args_t* args) {
    /* - Defaults - */
    args->loop = false;
    args->fork = false;
    args->pthread = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(CLI_HELP_OPTION, argv[i])) {
            usage(argv);
            exit(0);
        }

        if (!strcmp(CLI_LOOP_OPTION, argv[i])) {
            args->loop = true;
            continue;
        }

        if (!strcmp(CLI_FORK_OPTION, argv[i])) {
            args->fork = true;
            continue;
        }

        if (!strcmp(CLI_PTHREAD_OPTION, argv[i])) {
            args->pthread = true;
            continue;
        }

        return -1;              /* Unrecognized option */
    }

    return (args->fork && args->pthread) ? (-1) : (0);        /* `fork` & `pthread` are mutually eXclusive */
}




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
    struct sigaction sa;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);   /* Mask no signals during execution of handler */
    sa.sa_handler = sig_handler_func_ptr;

    if (
        // sigaction(SIGSTOP, &sa, NULL) == -1 ||             /* cannot be handled */
            sigaction(SIGCONT, &sa, NULL) == -1 ||
            sigaction(SIGINT, &sa, NULL) == -1 ||
            sigaction(SIGTERM, &sa, NULL) == -1 ||
            sigaction(SIGQUIT, &sa, NULL) == -1 ||
            // sigaction(SIGKILL, &sa, NULL) == -1 ||             /* cannot be handled */
            sigaction(SIGUSR1, &sa, NULL) == -1 ||
            sigaction(SIGUSR2, &sa, NULL) == -1
            ) {
        LOG_ERROR_AND_EXIT("Couldn't register signal handler");
    }
}


/* -- Actual test program -- */
typedef struct {
    char* pname;
    bool loop;
    void(*sig_handler_func_ptr)(int);
} routine_arg_t;

void* routine(void* arg) {
    const char* const pname = ((routine_arg_t*)arg)->pname;
    const bool loop = ((routine_arg_t*)arg)->loop;
    void(*sig_handler_func_ptr)(int) = ((routine_arg_t*)arg)->sig_handler_func_ptr;

    register_sig_handlers(sig_handler_func_ptr);

    do {
        fprintf(stdout, "tid = %5d, pid = %5d, ppid = %5d, pgid = %5d, sid = %5d [%s]\n",
                gettid(), getpid(), getppid(), getpgid(0), getsid(0), pname);
        nanosleep((const struct timespec[]){{3, 250000000L}}, NULL);
    } while(loop);

    return NULL;
}


int main(int argc, char** argv) {

    cli_args_t args;
    if (-1 == parse_cli_args(argc, argv, &args)) {
        usage(argv);
        return(1);
    }

    /* Disable IO buffering for stdout */
    if (0 != setvbuf(stdout, NULL, _IONBF, 0)) {
        LOG_WARN("Couldn't change buffering for `stdout`");
    }

/* - fork - */
    if (args.fork) {
        puts("Forking child ...");
        const pid_t child_pid = DIE_WHEN_ERRNO( fork() );

        routine((routine_arg_t[]){{ .pname = (!child_pid) ? "Child" : "Parent", .loop=args.loop, .sig_handler_func_ptr=(!child_pid) ? &child_signal_handler : &parent_signal_handler }});

        if (child_pid) {
            DIE_WHEN_ERRNO( wait(NULL) );         /* Wait for child process to exit */
        }

/* - pthread - */
    } else if (args.pthread) {
        puts("Creating additional thread ...");
        pthread_t t1;

        //pthread_create(&t1, NULL, routine, (routine_arg_t[]){{ .pname = "Thread-1", .loop=args.loop, .sig_handler_func_ptr = &child_signal_handler }});
        // Checking (as shown above) causes it to print "Thread-0" (instead of "Thread-1")
        if (0 != pthread_create(&t1, NULL, routine, (routine_arg_t[]){{ .pname = "Thread-1", .loop=args.loop, .sig_handler_func_ptr = &child_signal_handler }}) ) {      // NOTE: Child-thread will overwrite parent's signal handler ??
            LOG_ERROR_AND_EXIT("Couldn't create additional thread!");
        }

        routine((routine_arg_t[]){{ .pname = "Thread-0", .loop=args.loop, .sig_handler_func_ptr = &parent_signal_handler }});
        pthread_join(t1, NULL);

/* - default (single threaded) - */
    } else {
        puts("Running single threaded ...");
        routine((routine_arg_t[]){{ .pname = "Thread-0", .loop=args.loop, .sig_handler_func_ptr = &parent_signal_handler }});
    }

    return 0;
}
