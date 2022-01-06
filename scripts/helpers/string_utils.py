#!/usr/bin/env python3

import sys


# --------------------------------- Hashing ---------------------------------
def _hash_djb2(string):
    """
    C code of hash function:

    /* djb2 by Dan Bernstein */
    static u_int64_t hash_string(const char *str) {
        unsigned long hash = 5381;
        int c;

        while ((c = *str++)) hash = ((hash << 5) + hash) + c;
        return hash;
    }
    """

    hash = 5381
    for char in string:
        hash = ((hash << 5) + hash) + ord(char)
    return hash & 0xffffffffffffffff


def _generate_string_hashes(
        strings,
        print_as_hex, hash_function):
    """
    Generates hashes of strings
    """

    generated_str_hashes = { string: hex(hash_function(string)) if print_as_hex else hash_function(string) for string in strings }

    if len(generated_str_hashes.values()) != len(set(generated_str_hashes.values())):
        print("!! WARNING: DETECTED HASH COLLISION !!", file=sys.stderr)
        return None

    return generated_str_hashes



def str_hash_djb2(strings, print_as_hex):
    return _generate_string_hashes(strings, print_as_hex, _hash_djb2)
# --------------------------------- Hashing ---------------------------------
