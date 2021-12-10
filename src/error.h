#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* - Error handling marcos - */
#define PRINT_ERR(MSG) fprintf(stderr, "ERROR (" __FILE__ ":%d) -- %s\n", __LINE__, (MSG))

#define DIE_WHEN_ERRNO(FUNC) ({ \
    int __val = (FUNC); \
    (-1 == __val ? ({ PRINT_ERR(strerror(errno)); exit(1); -1; }) : __val); \
})


#endif /* ERROR_H */
