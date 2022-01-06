#!/usr/bin/env python3

"""
Helps generating hash consts of function names for stack unwinding
"""

import sys
from string_utils import str_hash_djb2


# -- Config --
FUNCTION_NAMES = [
    "main"
]

PRINT_HASHES_IN_HEX = True

CONST_PREFIX = "FNNAME_HASH"
CONST_ALIGN_PADDING = 14



if __name__ == '__main__':
    hashed_fct_names = str_hash_djb2(FUNCTION_NAMES, PRINT_HASHES_IN_HEX)

    if hashed_fct_names != None:
        for string, hash in hashed_fct_names.items():
            print(f"#define {CONST_PREFIX}_{string.upper()} {hash.rjust(CONST_ALIGN_PADDING)}", end='\n')
        sys.exit(0)

    sys.exit(1)
