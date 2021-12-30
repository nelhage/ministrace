#include "hash_mpq.h"

void init_crypt_table (uint32_t *ct) {
  static int inited = 0;
  if (inited == 0)
    {
      inited = 1;
      uint32_t sd = 0x00100001, idx1 = 0, idx2 = 0, i, t1, t2;
      for (idx1 = 0; idx1 < 0x100; idx1++)
        for (idx2 = idx1, i = 0; i < 5; i++, idx2 += 0x100)
          {
            sd = (sd * 125 + 3) % 0x2AAAAB;
            t1 = (sd & 0xFFFF) << 0x10;
            sd = (sd * 125 + 3) % 0x2AAAAB;
            t2 = (sd & 0xFFFF);
            ct[idx2] = (t1 | t2);
          }
    }
}

inline void mpq3hash (const void *s, const size_t len, void *r) {                               /* 1:18889465931478580854784 */
  register uint32_t i, c, x1 = 0x7FED7FED, y1 = 0x7FED7FED, z1 = 0x7FED7FED;
  register uint32_t x2 = 0x7FED7FED, y2 = 0x7FED7FED, z2 = 0x7FED7FED;
  register unsigned char *k = (unsigned char *) s;
//  while ((c = *k++) != '\0')    /*c = toupper (*k++); */
  for (i = 0; i < len; i++) {
      c = k[i];
      x1 = ct[c] ^ (x1 + x2);
      x2 = c + x1 + x2 + (x2 << 5) + 3;
      y1 = ct[256 + c] ^ (y1 + y2);
      y2 = c + y1 + y2 + (y2 << 5) + 3;
      z1 = ct[512 + c] ^ (z1 + z2);
      z2 = c + z1 + z2 + (z2 << 5) + 3;
    }
  ((uint32_t *)r)[0] = x1;
  ((uint32_t *)r)[1] = y1;
  ((uint32_t *)r)[2] = z1;
}

