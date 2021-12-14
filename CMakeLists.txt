project(ministrace)


# -- Project settings --
cmake_minimum_required(VERSION 3.3.2)
set(CMAKE_C_STANDARD 99)
enable_language(C)


# set(CMAKE_C_COMPILER clang)

# -- Options --
option(WITH_TESTS "Build tests" ON)

set(LINUX_SRC_DIR "/usr/src/linux-5.4.0" CACHE STRING "Location of kernel source used to parse syscalls")


# -- Preprocessor / Compile options --
add_compile_options(
        -Wall -Wextra -pedantic -pedantic-errors -Wformat=2
        -Wformat-signedness -Walloc-zero -Wdouble-promotion
        -Wduplicated-cond -Wfloat-equal -Winit-self
        -Wstrict-prototypes -Wundef -Wunused-macros
        -Wswitch-enum -Wswitch-default -Werror -frecord-gcc-switches)

set(OPTIONS
    -D_GNU_SOURCE
)


add_subdirectory(src)
add_subdirectory(test)
