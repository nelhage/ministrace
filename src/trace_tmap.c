#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "trace_tmap.h"
#include "libs/hashmap/atomic_hash.h"
#include "error.h"


/* - Constants - */
#define TTL_DISABLE 0


/* - Globals - */
static hash_t* global_map = NULL;



/* - Internal functions - */
/* ... debugging functions ... */
#ifndef NDEBUG
static int __sprint_syscall_state(child_syscall_state* scall, char* str_buf, size_t str_buf_size) {
    return snprintf(str_buf, str_buf_size, "s_nr=%ld, state=%s",
                    scall->s_nr, SYSCALL_ENTERED == scall->s_state ? "SYSCALL_ENTERED" : "SYSCALL_EXITED");
}

static void __log_syscall_state(child_syscall_state* scall) {
    char* str_buf = NULL;
    int key_str_buf_size = __sprint_syscall_state(scall, NULL, 0) + ((int)sizeof((char)'\0'));
    if ((str_buf = malloc(key_str_buf_size))) {
        __sprint_syscall_state(scall, str_buf, key_str_buf_size);
        LOG_DEBUG("Child syscallstate: %s", str_buf);

        free(str_buf);
    } else {
        LOG_ERROR_AND_EXIT("Failed printing key (`malloc` returned NULL)");
    }
}

/* ... hooks for hashmap */
/* Hook is necessary for destroying map (and removing values) */
int __del_hook(void* hash_data, void* caller_data) {
    if (hash_data) {
        LOG_DEBUG("Freeing child syscall state");    // DEBUGGING; TODO: print tid
        free(hash_data);
    }

    return PLEASE_REMOVE_HASH_NODE;
}


#  define LOG_DEBUG_FNMAP_KEY(key) __log_fnmap_key(key)
#else
#  define LOG_DEBUG_FNMAP_KEY(key) do {} while(0)
#endif



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

int tmap_get(pid_t *key, child_syscall_state** found_sstate) {
    if (!global_map || !key) {   /* Used to be assert */
        LOG_ERROR_AND_EXIT("Invalid key or uninit tmap");
    }

    int map_operation_result = atomic_hash_get(global_map, key, TMAP_KEY_SIZE, NULL, found_sstate);
    if (map_operation_result) {
        LOG_WARN("Couldn't find child state using the key %d (err_code=%d) ...", *key, map_operation_result);
    }
    return map_operation_result;
}

void tmap_add_or_update(pid_t *key, child_syscall_state* sstate) {
    if (!global_map || !key || !sstate) {
        LOG_ERROR_AND_EXIT("Invalid key / sstate or uninit tmap");
    }

    child_syscall_state* new_sstate;
    if ((new_sstate = malloc(sizeof(*new_sstate)))) {
        memcpy(new_sstate, sstate, sizeof(*new_sstate));                    /* Make copy of child state (which will be stored in tmap as value) */

        int map_operation_result; bool value_already_removed_for_update = false;
    update_value_after_removal:
        if ((map_operation_result = atomic_hash_add(global_map, key, TMAP_KEY_SIZE, new_sstate, TTL_DISABLE, NULL, NULL)) ) {

            if (1 == map_operation_result && !value_already_removed_for_update) {      /* UPDATE value under already used key */
                LOG_DEBUG("Updating value under already existing key %d", *key);    // DEBUGGING
                tmap_remove(key);
                value_already_removed_for_update = true;
                goto update_value_after_removal;
            }

            LOG_ERROR_AND_EXIT("Couldn't add value (err_code=%d [%s])", map_operation_result, (
                    (-1 == map_operation_result) ? "max filenames in tmap exceeded" : "unknown"));
        } else {
            LOG_DEBUG("Added child state using the key %d...", *key);    // DEBUGGING
        }
    } else {
        LOG_ERROR_AND_EXIT("`malloc` returned NULL");
    }
}

void tmap_remove(pid_t *key) {
    if (!global_map || !key) {
        LOG_ERROR_AND_EXIT("Invalid key or uninit tmap");
    }

    int map_operation_result;
    if ((map_operation_result = atomic_hash_del(global_map, key, TMAP_KEY_SIZE, NULL, NULL))) {
        LOG_ERROR_AND_EXIT("Couldn't delete value (child syscall state) (err_code=%d) using the key %d", map_operation_result, *key);
    } else {
        LOG_DEBUG("Removed child syscall state using the key %d", *key);    // DEBUGGING
    }
}
