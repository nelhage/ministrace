/**
 * Simple test program for validating functionality of tmap
 */
#define _GNU_SOURCE         /* Necessary for `gettid` */
#include <unistd.h>
#include <asm/unistd.h>

#include <stdio.h>

#include <assert.h>

#include "../src/trace/internal/tmap.h"


/* -- Constants -- */
#define DEFAULT_TMAP_MAX_SIZE 100


void assert_exists_in_map(const pid_t tid, const long *original_c_s_nr) {
    long *found_c_s_nr = NULL;
    tmap_get(&tid, &found_c_s_nr);

    assert(*found_c_s_nr == *original_c_s_nr);
}

void assert_not_exists_in_map(const pid_t tid) {
    long *found_c_s_nr = NULL;
    tmap_get(&tid, &found_c_s_nr);

    assert(!found_c_s_nr);
}


int main (void) {
    /* Disable IO buffering */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);


/* Test 0: Setup */
    tmap_create(DEFAULT_TMAP_MAX_SIZE);


/* Test 1: Insert value & check exists */
    pid_t tid = gettid();
    long c_s_nr = __NR_execve;
    tmap_add_or_update(&tid, &c_s_nr);

    assert_exists_in_map(tid, &c_s_nr);


/* Test 2: Update value & check updated */
    c_s_nr = -1;
    tmap_add_or_update(&tid, &c_s_nr);

    assert_exists_in_map(tid, &c_s_nr);


/* Test 3: Delete & check doesn't exist anymore */
    tmap_remove(&tid);

    assert_not_exists_in_map(tid);


/* Test 4: Destroy map (Cleanup) */
    tmap_destroy();


    return 0;
}