project(ministrace)


# -- Project settings --
cmake_minimum_required(VERSION 3.21)
set(CMAKE_C_STANDARD 99)
enable_language(C)


# -- Options --
option (WITH_TESTS "Build tests" ON)


# -- Preprocessor / Compile options --
add_compile_options(-Wall -Wextra)

set(OPTIONS
    -D_GNU_SOURCE
)


add_subdirectory(src)
add_subdirectory(test)
