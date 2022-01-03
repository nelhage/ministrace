
# -- Variables --
set(HEADERS
        trace/internal/arch/ptrace_utils.h
        trace/internal/ptrace_utils.h
        trace/internal/syscalls.h
        trace/tracing.h
        cli.h)
set(SOURCES
        trace/internal/arch/ptrace_utils.c
        trace/internal/ptrace_utils.c
        trace/internal/syscalls.c
        trace/tracing.c
        cli.c
        main.c)

set(COMPILE_OPTIONS
        "")


# -- CMake options --
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Default build type: Release" FORCE)
endif()

set(LINUX_SRC_DIR "/usr/src/linux-5.4.0" CACHE STRING "Location of kernel source used to parse syscalls")
option(PRINT_STRINGS "Print string instead of pointer (e.g., in `read` syscall); Note: Disabling this option improves performance" OFF)
option(WITH_STACK_UNWINDING "Stack unwinding option -k" OFF)

if (PRINT_STRINGS)
    list(APPEND COMPILE_OPTIONS "-DPRINT_STRINGS")
endif()

if (WITH_STACK_UNWINDING)
    list(APPEND HEADERS
            trace/internal/unwind.h)
    list(APPEND SOURCES
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

list(APPEND HEADERS
        ${GEN_SYSCALLS_TARGET_DIR}/syscallents.h)
list(APPEND SOURCES
        ${GEN_SYSCALLS_TARGET_DIR}/syscallents.c)


# -- Project --
add_executable(ministrace
        ${HEADERS}
        ${SOURCES})

target_compile_options(ministrace PRIVATE
        ${COMPILE_OPTIONS})

target_link_libraries(ministrace PRIVATE
        ${LINK_OPTIONS})

target_include_directories(ministrace PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${ministrace_BINARY_DIR}/src")
