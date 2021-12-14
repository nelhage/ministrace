
# -- Generate syscalls --
set(GEN_SYSCALLS_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/../scripts/gen_syscalls.py")

find_package(PythonInterp 3.4 REQUIRED)
add_custom_command(
    COMMENT "Parse syscalls from kernel source and generate source files"
    DEPENDS ${GEN_SYSCALLS_SCRIPT}
    OUTPUT "__syscalls.c" "__syscalls.h"
    COMMAND "${PYTHON_EXECUTABLE}"
    ARGS ${GEN_SYSCALLS_SCRIPT} ${LINUX_SRC_DIR} "."
    WORKING_DIR "${ministrace_BINARY_DIR}"
)


# -- Build --
add_subdirectory(libs/hashmap)

add_executable(ministrace
        __syscalls.c
        cli.c
        main.c
        trace_ptrace.c
        trace_syscalls.c
        trace_tmap.c)
target_link_libraries(ministrace hashmap)
target_include_directories(ministrace PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${ministrace_BINARY_DIR}/src")