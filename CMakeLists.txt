project(ministrace)


# -- Project settings --
cmake_minimum_required(VERSION 3.21)
set(CMAKE_C_STANDARD 99)
enable_language(C)


# -- Preprocessor / Compile options --
add_compile_options(-Wall -Wextra)

set(OPTIONS
    -D_GNU_SOURCE
)


# -- Build --
set(LINUX_SRC_DIR "/usr/src/linux-5.4.0")

set(CMAKE_SOURCE_DIR "src")

find_package(PythonInterp 3.2 REQUIRED)

set(gen_dir "src/generated")

add_custom_command(
        OUTPUT "${gen_dir}/syscallents.h"
        COMMAND
        "${PYTHON_EXECUTABLE}"
        "${CMAKE_CURRENT_LIST_DIR}/scripts/gen_syscalls.py"
        --dir "${gen_dir}"
        --smart
        --check-changes
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/gen_syscalls.py"
        COMMENT "Parse syscalls from kernel source and generate header file"
)

# Please keep in alphabetical order
set(SOURCE
    ${CMAKE_SOURCE_DIR}/__syscallents.c
    ${CMAKE_SOURCE_DIR}/cli.c
    ${CMAKE_SOURCE_DIR}/main.c
    ${CMAKE_SOURCE_DIR}/trace_ptrace.c
    ${CMAKE_SOURCE_DIR}/trace_syscalls.c
)
add_executable(ministrace ${SOURCE})
