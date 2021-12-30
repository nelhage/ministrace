#include "hash_md5.h"


inline void md5hash(const void *s, const size_t len, void *r) {
  MD5((unsigned char *)s, (size_t)len, (unsigned char *)r);
}
