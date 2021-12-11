#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


/* - Error handling marcos - */
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

#define LOG_ERROR_AND_EXIT(format, ...) \
	do { \
		fprintf(stderr, "[ERROR] In function %s (file %s, line %d): " format ".\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while(0)


#define DIE_WHEN_ERRNO(FUNC) ({ \
    int __val = (FUNC); \
    (-1 == __val ? ({ LOG_ERROR_AND_EXIT("%s", strerror(errno)); -1; }) : __val); \
})

#endif /* ERROR_H */
