project(ministrace)


# -- Project settings --
cmake_minimum_required(VERSION 3.3.2)
set(CMAKE_C_STANDARD 99)
# set(CMAKE_C_COMPILER clang)
enable_language(C)

# - CMake Debugging options -
# set(CMAKE_VERBOSE_MAKEFILE ON)
# set(CMAKE_DEBUG_TARGET_PROPERTIES INCLUDE_DIRECTORIES)


# -- Preprocessor / Compile options --
add_compile_options(
        -Wall -Wextra -pedantic -pedantic-errors -Wformat=2
        -Wformat-signedness -Walloc-zero -Wdouble-promotion
        -Wduplicated-cond -Wfloat-equal -Winit-self
        -Wstrict-prototypes -Wundef -Wunused-macros
        -Wswitch-enum -Wswitch-default -Werror -frecord-gcc-switches)


# -- "Subdirs" containing projects --
include(${ministrace_SOURCE_DIR}/cmake/AddGitSubModule.cmake)

# Solution from https://www.scivision.dev/cmake-git-submodule/
#
# If this fails, start anew by adding the  git as submodule
# git rm --cached ext/atomic_hash
# rm -rf atomic_hash
# git submodule add https://github.com/therealthingy/atomic_hash.git

add_git_submodule(ext/atomic_hash)

add_subdirectory(ext)

add_subdirectory(src)
add_subdirectory(test)
