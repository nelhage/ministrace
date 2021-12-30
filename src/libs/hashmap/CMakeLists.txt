
# -- UI options --
set(FUNCTION "CITY3HASH_128" CACHE STRING "Function to be used")
set(FUNCTION_VALUES "CITY3HASH_128;MD5HASH;MPQ3HASH;NEWHASH;MURMUR3HASH_128")
set_property(CACHE FUNCTION PROPERTY STRINGS ${FUNCTION_VALUES})



# -- Compiler/Linker "settings" --
set(MAP_SOURCE
        atomic_hash.c)

set(MAP_COMPILE_OPTIONS
        -fPIC
        -march=native -msse4.2)     # ?? Really necessary

set(MAP_LINK_LIBS
        m
        pthread)


# IMPORTANT: Must match macros in `atomic_hash.h`
if (FUNCTION STREQUAL "CITY3HASH_128")
    list(APPEND MAP_COMPILE_OPTIONS -DFUNCTION=1)
    list(APPEND MAP_SOURCE hash_functions/hash_city.c)
elseif (FUNCTION STREQUAL "MD5HASH")
    list(APPEND MAP_SOURCE hash_functions/hash_md5.c)
    list(APPEND MAP_COMPILE_OPTIONS -DFUNCTION=2)
    list(APPEND MAP_LINK_LIBS ssl crypto)
elseif (FUNCTION STREQUAL "MPQ3HASH")
    list(APPEND MAP_SOURCE hash_functions/hash_mpq.c)
    list(APPEND MAP_COMPILE_OPTIONS -DFUNCTION=3)
elseif (FUNCTION STREQUAL "NEWHASH")
    list(APPEND MAP_SOURCE hash_functions/hash_newhash.c)
    list(APPEND MAP_COMPILE_OPTIONS -DFUNCTION=4)
elseif (FUNCTION STREQUAL "MURMUR3HASH_128")
    list(APPEND MAP_SOURCE hash_functions/hash_murmur3.c)
    list(APPEND MAP_COMPILE_OPTIONS -DFUNCTION=5)
else()
    error("Invalid function")
endif()


# EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE CPU_ARCH )
# message( STATUS "Detected CPU arch: ${CPU_ARCH}" )



# -- "Project" --
add_library(hashmap OBJECT ${MAP_SOURCE})

target_compile_options(hashmap PUBLIC ${MAP_COMPILE_OPTIONS})
target_link_libraries(hashmap PRIVATE ${MAP_LINK_LIBS})
