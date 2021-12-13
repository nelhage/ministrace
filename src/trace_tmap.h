/**
 * Tasks (LWP) map (tmap)
 *   Implements abstraction (API) for map implementation (which is used for tracking tasks)
 */
#ifndef TMAP_H
#define TMAP_H

#include <sys/types.h>


/* - Data structures - */
#define TMAP_KEY_SIZE sizeof(pid_t)


/* - Function prototypes - */
void tmap_create(size_t max_size);
void tmap_destroy(void);

int tmap_get(pid_t *tid, long **s_nr);
void tmap_add_or_update(pid_t *tid, long *s_nr);
void tmap_remove(pid_t *tid);
// void tmap_clear(void);

#endif /* TMAP_H */