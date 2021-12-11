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


/* -- Functions -- */
/* - Internal functions - */
/* ... hooks for hashmap */
/* Hook is necessary for destroying map (and removing values) */
int __del_hook(void* hash_data, void* caller_data) {
    if (hash_data) {
        LOG_DEBUG("Freeing child syscall state");    // DEBUGGING; TODO: print tid
        free(hash_data);
    }

    return PLEASE_REMOVE_HASH_NODE;
}

/* ... debugging functions ... */
#ifndef NDEBUG
static int __sprint_syscall_state(child_syscall_state* scall, char* str_buf, size_t str_buf_size) {
    return snprintf(str_buf, str_buf_size, "s_nr=%ld, state=%s",
                    scall->s_nr, SYSCALL_ENTERED == scall->s_state ? "SYSCALL_ENTERED" : "SYSCALL_EXITED");
}

static void __log_syscall_state(child_syscall_state* scall) {
    char* str_buf = NULL;
    int str_buf_size = __sprint_syscall_state(scall, NULL, 0) + ((int)sizeof((char)'\0'));
    if ((str_buf = malloc(str_buf_size))) {
        __sprint_syscall_state(scall, str_buf, str_buf_size);
        LOG_DEBUG("Child syscall state: %s", str_buf);

        free(str_buf);
    } else {
        LOG_ERROR_AND_EXIT("Failed printing child syscall state (`malloc` returned NULL)");
    }
}

#  define LOG_DEBUG_SCALL_STATE(SCALL) __log_syscall_state(SCALL)
#else
#  define LOG_DEBUG_SCALL_STATE(SCALL) do {} while(0)
#endif /* NDEBUG */


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

int tmap_get(pid_t *tid, child_syscall_state** found_sstate) {
    if (!global_map || !tid) {
        LOG_ERROR_AND_EXIT("Invalid `tid` or uninit tmap");
    }

    const int map_operation_result = atomic_hash_get(global_map, tid, TMAP_KEY_SIZE, NULL, found_sstate);
    if (map_operation_result) {
        LOG_WARN("Couldn't find child state using the tid %d (err_code=%d) ...", *tid, map_operation_result);
    }
    return map_operation_result;
}

void tmap_add_or_update(pid_t *tid, child_syscall_state* sstate) {
    if (!global_map || !tid || !sstate) {
        LOG_ERROR_AND_EXIT("Invalid `tid` / `sstate` or uninit tmap");
    }

    child_syscall_state *new_sstate;
    if ((new_sstate = malloc(sizeof(*new_sstate)))) {
        memcpy(new_sstate, sstate, sizeof(*new_sstate));                    /* Make copy of child state (which will be stored in tmap as value) */

        int map_operation_result; bool value_already_removed_for_update = false;
    update_value_after_removal:
        if ((map_operation_result = atomic_hash_add(global_map, tid, TMAP_KEY_SIZE, new_sstate, TTL_DISABLE, NULL, NULL)) ) {

            if (1 == map_operation_result && !value_already_removed_for_update) {      /* UPDATE value under already used tid */
                LOG_DEBUG("Updating value under already existing tid %d", *tid);    // DEBUGGING
                tmap_remove(tid);
                value_already_removed_for_update = true;
                goto update_value_after_removal;
            }

            LOG_ERROR_AND_EXIT("Couldn't add value (err_code=%d [%s])", map_operation_result, (
                    (-1 == map_operation_result) ? "max child state in tmap exceeded" : "unknown"));
        } else {
            LOG_DEBUG("Added following child state using the tid %d...", *tid);    // DEBUGGING
            LOG_DEBUG_SCALL_STATE(new_sstate);
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
        LOG_ERROR_AND_EXIT("Couldn't delete value (child syscall state) (err_code=%d) using `tid` %d", map_operation_result, *tid);
    } else {
        LOG_DEBUG("Removed child syscall state using `tid` %d", *tid);    // DEBUGGING
    }
}
