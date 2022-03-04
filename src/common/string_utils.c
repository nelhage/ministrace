#include <errno.h>
#include <stdlib.h>

#include "string_utils.h"


int str_to_long(char* str, long* num) {
    char* parse_end_ptr = NULL;
    if (NULL != (parse_end_ptr = str) && NULL != num) {
        char* p_end_ptr = NULL;
        const long parsed_number = (int)strtol(parse_end_ptr, &p_end_ptr, 10);

        if (parse_end_ptr != p_end_ptr && ERANGE != errno) {
            *num = parsed_number;
            return 0;
        }
    }
    return -1;
}
