/**
 * Simple test program for validating functionality of tmap
 */
#define _GNU_SOURCE         /* Necessary for gettid */
#include <unistd.h>
#include <asm/unistd.h>

#include <stdio.h>

#include <assert.h>

#include "../src/trace_tmap.h"


/* -- Constants -- */
#define DEFAULT_TMAP_MAX_SIZE 100


void assert_exists_in_map(pid_t tid, child_syscall_state *original_c_sstate) {
    child_syscall_state *found_c_sstate = NULL;
    tmap_get(&tid, &found_c_sstate);

    assert(found_c_sstate->s_state == original_c_sstate->s_state &&
           found_c_sstate->s_nr == original_c_sstate->s_nr);
}

void assert_not_exists_in_map(pid_t tid) {
    child_syscall_state *found_c_sstate = NULL;
    tmap_get(&tid, &found_c_sstate);

    assert(!found_c_sstate);
}


int main (void) {
    // Disable IO buffering for stdout
    setvbuf(stdout, NULL, _IONBF, 0);


/* Test 0: Setup */
    tmap_create(DEFAULT_TMAP_MAX_SIZE);


/* Test 1: Insert value & check exists */
    pid_t tid = gettid();
    child_syscall_state c_sstate = {
            .s_nr = __NR_execve,
            .s_state = SYSCALL_ENTERED
    };
    tmap_add_or_update(&tid, &c_sstate);

    assert_exists_in_map(tid, &c_sstate);


/* Test 2: Update value & check updated */
    c_sstate.s_state = SYSCALL_EXITED;
    tmap_add_or_update(&tid, &c_sstate);

    assert_exists_in_map(tid, &c_sstate);


/* Test 3: Delete & check doesn't exist anymore */
    tmap_remove(&tid);

    assert_not_exists_in_map(tid);


/* Test 4: Destroy map (Cleanup) */
    tmap_destroy();


    return 0;
}