#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "trace_tmap.h"
#include "libs/hashmap/atomic_hash.h"
#include "error.h"


/* - Constants - */
#define TTL_DISABLE 0


// #define NDEBUG_TMAP

/* - Macros - */
/* - Debugging stuff - */
#ifndef NDEBUG_TMAP
#  define LOG_DEBUG_TMAP(FORMAT, ...) LOG_DEBUG(FORMAT, ##__VA_ARGS__)
#else
#  define LOG_DEBUG_TMAP(FORMAT, ...) do { } while(0)
#endif


/* - Globals - */
static hash_t* global_map = NULL;


/* -- Functions -- */
/* - Internal functions - */
/* ... hooks for hashmap */
/* Hook is necessary for destroying map (and removing values) */
int __del_hook(void *hash_data, void *caller_data __attribute__((unused))) {
    if (hash_data) {
        LOG_DEBUG_TMAP("Freeing child `s_nr` %ld", *((long*)hash_data));    // DEBUGGING; TODO: print tid
        free(hash_data);
    }

    return PLEASE_REMOVE_HASH_NODE;
}


/* - Public functions - */
/**
 * Shall be called by `init_process` in event.c
 */
void tmap_create(size_t max_size) {
    if (global_map) {
        LOG_ERROR_AND_EXIT("tmap has been already init'ed");
    }

    if (!(global_map = atomic_hash_create(max_size, TTL_DISABLE))) {
        LOG_ERROR_AND_EXIT("Couldn't init tmap");
    } else {
        global_map->on_del = __del_hook;
    }
}

void tmap_destroy(void) {
    if (!global_map) {
        LOG_ERROR_AND_EXIT("tmap hasn't been init'ed yet");
    }

    if ((atomic_hash_destroy(global_map))) {
        LOG_WARN("Couldn't uninit tmap");
    } else {
        global_map = NULL;
    }
}

int tmap_get(pid_t *tid, long **s_nr) {
    if (!global_map || !tid) {
        LOG_ERROR_AND_EXIT("Invalid `tid` or uninit tmap");
    }

    const int map_operation_result = atomic_hash_get(global_map, tid, TMAP_KEY_SIZE, NULL, s_nr);
    if (map_operation_result) {
        LOG_DEBUG_TMAP("Couldn't find child `s_nr` using tid %d (err_code=%d) ...", *tid, map_operation_result);
    }
    return map_operation_result;
}

void tmap_add_or_update(pid_t *tid, long *s_nr) {
    if (!global_map || !tid || !s_nr) {
        LOG_ERROR_AND_EXIT("Invalid `tid` / `s_nr` or uninit tmap");
    }

    long *new_s_nr;
    if ((new_s_nr = malloc(sizeof(*new_s_nr)))) {
        memcpy(new_s_nr, s_nr, sizeof(*new_s_nr));                    /* Make copy of child state (which will be stored in tmap as value) */

        int map_operation_result; bool value_already_removed_for_update = false;
    update_value_after_removal:
        if ((map_operation_result = atomic_hash_add(global_map, tid, TMAP_KEY_SIZE, new_s_nr, TTL_DISABLE, NULL, NULL)) ) {

            if (1 == map_operation_result && !value_already_removed_for_update) {      /* UPDATE value under already used tid */
                LOG_DEBUG_TMAP("Updating value under already existing tid %d", *tid);    // DEBUGGING
                tmap_remove(tid);
                value_already_removed_for_update = true;
                goto update_value_after_removal;
            }

            LOG_ERROR_AND_EXIT("Couldn't add value (err_code=%d [%s])", map_operation_result, (
                    (-1 == map_operation_result) ? "max child state in tmap exceeded" : "unknown"));
        } else {
            LOG_DEBUG_TMAP("Added child `s_nr` %ld under `tid` %d...", *new_s_nr, *tid);    // DEBUGGING
        }
    } else {
        LOG_ERROR_AND_EXIT("`malloc` returned NULL");
    }
}

void tmap_remove(pid_t *tid) {
    if (!global_map || !tid) {
        LOG_ERROR_AND_EXIT("Invalid `tid` or uninit tmap");
    }

    int map_operation_result;
    if ((map_operation_result = atomic_hash_del(global_map, tid, TMAP_KEY_SIZE, NULL, NULL))) {
        LOG_ERROR_AND_EXIT("Couldn't delete value (i.e., child `s_nr`) (err_code=%d) using `tid` %d", map_operation_result, *tid);
    } else {
        LOG_DEBUG_TMAP("Removed child `s_nr` using `tid` %d", *tid);    // DEBUGGING
    }
}
