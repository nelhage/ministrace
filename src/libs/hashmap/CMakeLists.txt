
add_library(hashmap OBJECT
        hash_functions/hash_city.c
        atomic_hash.c)

target_link_libraries(hashmap PRIVATE m pthread)
target_compile_options(hashmap PRIVATE -march=native -fPIC)   # -msse4.2


EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE CPU_ARCH )
message( STATUS "Detected CPU arch: ${CPU_ARCH}" )
