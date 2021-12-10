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


#if !defined(NDEBUG)
#  define LOG_DEBUG(format, ...) \
	do { \
		fprintf(stdout, "[DEBUG] In function %s (file %s, line %d): " format ".\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
	} while(0)
#else
#  define LOG_DEBUG(format, ...)
#endif

#define LOG_WARN(format, ...) \
	do { \
		fprintf(stderr, "[WARN] In function %s (file %s, line %d): " format ".\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
	} while(0)

#define LOG_ERROR(format, ...) \
	do { \
		fprintf(stderr, "[ERROR] In function %s (file %s, line %d): " format ".\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while(0)


#endif /* ERROR_H */
