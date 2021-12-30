/*
 *  atomic_hash.h
 *
 * 2012-2015 Copyright (c)
 * Fred Huang, <divfor@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef ATOMIC_HASH_H
#define ATOMIC_HASH_H

#include <stdint.h>

typedef int (*callback)(void *hash_data, void *caller_data);
typedef int (*hook) (void *hash_data, void *rtn_data);

/* callback function idx */
#define PLEASE_REMOVE_HASH_NODE    -1
#define PLEASE_SET_TTL_TO_DEFAULT  -2
#define PLEASE_DO_NOT_CHANGE_TTL   -3
#define PLEASE_SET_TTL_TO(n)       (n)


/* -- Avaiable hash functions -- */
#define CITY3HASH_128 1
#define MD5HASH 2


#if FUNCTION == CITY3HASH_128 || FUNCTION == MD5HASH
#define NCMP 2
typedef uint64_t hvu;
typedef struct hv { hvu x, y; } hv;
#endif

#define shared __attribute__((aligned(64)))

typedef uint32_t nid;
typedef struct {
    unsigned long expires;
    unsigned long escapes;
    unsigned long add_nomem;
    unsigned long add_nosit;
    unsigned long del_nohit;
    unsigned long get_nohit;
    unsigned long mem_htabs;
    unsigned long mem_nodes;
    unsigned long max_nodes;
    unsigned long key_collided;
} hstats_t;

typedef struct {
    unsigned long xadd, xget, xdel, nexp;
} hc_t; /* 64-bytes cache line */

typedef struct {
    void **ba;
    shared nid mask, shift; /* used for i2p() only */
    shared nid max_blocks, blk_node_num, node_size, blk_size;
    volatile nid curr_blocks;
} mem_pool_t;

typedef union {
    struct { nid mi, rfn; } cas;
    uint64_t all;
} cas_t;

typedef struct {
    volatile hv v;
    unsigned long expire; /* expire in ms # of gettimeofday(), 0 = never */
    void *data;
} node_t;

typedef struct {
    nid *b;             /* hash tab (int arrary as memory index */
    unsigned long ncur, n, nb;  /* nb: buckets #, set by n * r */
    unsigned long nadd, ndup, nget, ndel;
} htab_t;

typedef struct {
/* hash function, here select cityhash_128 as default */
    shared void (* hash_func) (const void *key, size_t len, void *r);

/* hook func to deal with user data in safe zone */
    shared hook on_ttl, on_add, on_dup, on_get, on_del;
    shared volatile cas_t freelist; /* free hash node list */
    shared htab_t ht[3]; /* ht[2] for array [MINTAB] */
    shared hstats_t stats;
    shared void **hp;
    shared mem_pool_t *mp;
    shared unsigned long reset_expire; /* if > 0, reset node->expire */
    shared unsigned long nmht, ncmp;
    shared unsigned long nkey, npos, nseat; /* nseat = 2*npos = 4*nkey */
    shared void *teststr;
    shared unsigned long testidx, teststr_num;
} hash_t;


/*
Summary
This is a hash table designed with high performance, lock-free and memory-saving. Multiple threads can concurrently perform read/write/delete operations up to 10M ops/s in modern computer platform. It supports up to 2^32 hash items with O(1) performance for both of successful and unsuccessful search from the hash table.
By giving max hash item number, atomic_hash calculates two load factors to match expected collision rate and creates array 1 with higher load factor, array 2 with lower load factor, and a small array 3 to store collision items. memory pool for hash nodes (not for user data) is also designed for both of high performance and memory saving.

Usage
Use below functions to create a hash handle that associates its arrays and memory pool, print statistics of it, or release it.

hash_t * atomic_hash_create (unsigned int max_nodes, int reset_ttl);
int atomic_hash_stats (hash_t *h, unsigned long escaped_milliseconds);
int atomic_hash_destroy (hash_t *h);

The hash handle can be copied to any number of threads for calling below hash functions:

int atomic_hash_add (hash_t *h, void *key, int key_len, void *user_data, int init_ttl, hook func_on_dup, void *out);
int atomic_hash_del (hash_t *h, void *key, int key_len, hook func_on_del, void *out); //delete all matches
int atomic_hash_get (hash_t *h, void *key, int key_len, hook func_on_get, void *out); //get the first match

Not like normal hash functions that return user data directly, atomic hash functions return status code -- 0 for successful operation and non-zero for unsuccessful operation. Instead, atomic hash functions call hook functions to deal with user data once they find target hash node. The hook functions should be defined as following format:

typedef int (*hook)(void *hash_data, void *out)

here 'hash_data' will be copied from target hash node's 'data' field by atomic hash functions (generally it is a pointer to link the user data), and 'out' will be given by atomic hash function's caller. There are 5 function pointers (on_ttl, on_del, on_add, on_get and on_dup) to register hook functions. The hook function should obey below rules:

1. must be non-blocking and essential actions only. too much execution time will drop performance remarkablly;
2. on_ttl and on_del should free user data and must return -1(PLEASE_REMOVE_HASH_NODE).
3. on_get and on_dup may return either -2 (PLEASE_SET_TTL_TO_DEFAULT) or a positive number that indicates updating ttl;
4. on_add must return -3 (PLEASE_DO_NOT_CHANGE_TTL) as ttl will be set by initial_ttl;

atomic_hash_create will initialize some built-in functions as default hook functions that only do value-copy for hash node's 'data' field and then return code. So you need to write your own hook functions to replace default ones if you want to free your user data's memeory or adjust ttl in the fly:

h->on_ttl = your_own_on_ttl_hook_func;
h->on_add = your_own_on_add_hook_func;
...

In the call time, instead of hook functions registered in on_dup/on_get/on_del, hash functions atomic_hash_add, atomic_hash_get, atomic_hash_del are able to use an alternative function as long as they obey above hook function rules. This will give flexibility to deal with different user data type in a same hash table.


About TTL
TTL (in milliseconds) is designed to enable timer for hash nodes. Set 'reset_ttl' to 0 to disable this feature so that all hash items never expire. If reset_ttl is set to >0, you still can set 'init_ttl' to 0 to mark specified hash items that never expire.
reset_ttl: atomic_hash_create uses it to set hash_node->expire. each successful lookup by atomic_hash_add or atomic_hash_get may reset target item's hash_node->expire to (now + reset_ttl), per your on_dup / on_get hook functions;
init_ttl：atomic_hash_add uses it to set hash_node->expire to (now + init_ttl). If init_ttl == 0, hash_node will never expires as it will NOT be reset by reset_ttl.
hash_node->expire: hash node's 'expire' field. If expire == 0, this hash node will never expire; If expire > 0, this hash node will become expired when current time is larger than expire, but no removal action immediately applies on it. However, since it's expired, it may be removed by any of hash add/get/del calls that traverses it (in another words, no active cleanup thread to clear expired item). So your must free user data's memory in your own hash_handle->on_ttl hook function!!!
*/

/* return (int): 0 for successful operation and non-zero for unsuccessful operation */
hash_t *atomic_hash_create (unsigned int max_nodes, int reset_ttl);
int atomic_hash_destroy (hash_t *h);
int atomic_hash_add (hash_t *h, const void *key, int key_len, void *user_data, int init_ttl, hook func_on_dup, void *out);
int atomic_hash_del (hash_t *h, const void *key, int key_len, hook func_on_del, void *out); //delete all matches
int atomic_hash_get (hash_t *h, const void *key, int key_len, hook func_on_get, void *out); //get the first match
int atomic_hash_stats (hash_t *h, unsigned long escaped_milliseconds);

#endif /* ATOMIC_HASH_H */
