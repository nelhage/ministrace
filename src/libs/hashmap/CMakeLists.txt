
add_library(hashmap OBJECT
        hash_functions/hash_city.c
        atomic_hash.c)

target_link_libraries(hashmap PRIVATE m pthread)
target_compile_options(hashmap PRIVATE -march=native -msse4.2 -fPIC)
