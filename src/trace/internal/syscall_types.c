#include "syscall_types.h"


/* -- Functions -- */
const char* arg_type_enum_to_str(arg_type_t arg) {
    if (((unsigned int)-1) == arg) {
        return "N/A";
    }

    static const char* strings[] = {
            [ARG_INT] = "ARG_INT",
            [ARG_PTR] = "ARG_PTR",
            [ARG_STR] = "ARG_STR"
    };
    return strings[arg];
}
