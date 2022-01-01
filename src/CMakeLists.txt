
# -- Variables --
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

set(COMPILE_OPTIONS
        "")

set(LINK_OPTIONS
        "atomic_hash_object")


# -- CMake options --
set(LINUX_SRC_DIR "/usr/src/linux-5.4.0" CACHE STRING "Location of kernel source used to parse syscalls")
option(PRINT_STRINGS "Print string instead of pointer (e.g., in read syscall); Disabling this option improves stability / performance" OFF)
option(WITH_STACK_UNWINDING "Stack unwinding option -k" OFF)

if (PRINT_STRINGS)
    list(APPEND COMPILE_OPTIONS "-DPRINT_STRINGS")
endif()

if (WITH_STACK_UNWINDING)
    list(APPEND SOURCE
            trace/internal/unwind.h
            trace/internal/unwind.c)
    list(APPEND COMPILE_OPTIONS "-DWITH_STACK_UNWINDING")
    list(APPEND LINK_OPTIONS
            unwind-ptrace unwind-generic
            iberty)
endif()


# -- Build targets/commands --
# - Parse syscalls + generate source -
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


# -- Project --
add_executable(ministrace ${SOURCE})

target_compile_options(ministrace PRIVATE
        ${COMPILE_OPTIONS})

target_link_libraries(ministrace PRIVATE
        ${LINK_OPTIONS})

target_include_directories(ministrace PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${ministrace_BINARY_DIR}/src"
         $<TARGET_PROPERTY:atomic_hash_object,INTERFACE_INCLUDE_DIRECTORIES>)
