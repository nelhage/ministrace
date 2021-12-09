#ifndef CLI_H
#define CLI_H


typedef struct cli_args {
    bool list_syscalls;
    bool follow_fork;
    int pause_on_scall_nr;
    int exec_arg_offset;
} cli_args;


/* -- Function prototypes -- */
void parse_cli_args(int argc, char** argv,
                    cli_args* parsed_cli_args_ptr);

#endif /* CLI_H */
