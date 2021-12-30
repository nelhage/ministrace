// Note: Requires installed libssl-dev + linker flag `-lssl -lcrypto`
#include <openssl/md5.h>

void md5hash(const void *s, const size_t len, void *r);
