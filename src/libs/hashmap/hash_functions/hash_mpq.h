#ifndef HASH_MPQ_H
#define HASH_MPQ_H

#include <stdint.h>


void init_crypt_table (uint32_t *ct);
void mpq3hash (const void *s, const size_t len, void *r);

#endif /* HASH_MPQ_H */
