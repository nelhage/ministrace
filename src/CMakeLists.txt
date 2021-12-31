
set(SOURCE
        trace/internal/ptrace_arch.h
        trace/internal/ptrace_fcts.h
        trace/internal/ptrace_fcts.c
        trace/internal/syscalls.h
        trace/internal/syscalls.c
        trace/internal/tmap.h
        trace/internal/tmap.c
        trace/tracing.h
        trace/tracing.c
        cli.h
        cli.c
        main.c)


# -- Parse syscalls + generate source --
set(GEN_SYSCALLS_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/../scripts/gen_syscalls.py")
set(GEN_SYSCALLS_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")

find_package(PythonInterp 3.4 REQUIRED)
add_custom_command(
    COMMENT "Parse syscalls from kernel source and generate source files"
    DEPENDS ${GEN_SYSCALLS_SCRIPT}
    OUTPUT "${GEN_SYSCALLS_TARGET_DIR}/syscallents.c" "${GEN_SYSCALLS_TARGET_DIR}/syscallents.h"

    COMMAND ${CMAKE_COMMAND} -E make_directory ${GEN_SYSCALLS_TARGET_DIR}
    COMMAND ${PYTHON_EXECUTABLE} ${GEN_SYSCALLS_SCRIPT} ${LINUX_SRC_DIR} ${GEN_SYSCALLS_TARGET_DIR})

list(APPEND SOURCE
        ${GEN_SYSCALLS_TARGET_DIR}/syscallents.h
        ${GEN_SYSCALLS_TARGET_DIR}/syscallents.c)



# -- Build --
add_subdirectory(libs/hashmap)

add_executable(ministrace ${SOURCE})

target_link_libraries(ministrace PRIVATE
        hashmap)

target_include_directories(ministrace PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${ministrace_BINARY_DIR}/src"
         $<TARGET_PROPERTY:hashmap,INTERFACE_INCLUDE_DIRECTORIES>)
