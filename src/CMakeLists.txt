
# - Generate syscalls -
set(GEN_SYSCALLS_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/../scripts/gen_syscalls.py")

find_package(PythonInterp 3.4 REQUIRED)
add_custom_command(
    COMMENT "Parse syscalls from kernel source and generate source files"
    DEPENDS ${GEN_SYSCALLS_SCRIPT}
    OUTPUT "${CMAKE_CURRENT_LIST_DIR}/__syscallents.h" "${CMAKE_CURRENT_LIST_DIR}/__syscallents.c"
    COMMAND "${PYTHON_EXECUTABLE}"
    ARGS ${GEN_SYSCALLS_SCRIPT} ${LINUX_SRC_DIR} ${CMAKE_CURRENT_LIST_DIR}
)



# - Build -
# Please keep in alphabetical order
set(SOURCE
    __syscallents.c
    cli.c
    main.c
    trace_ptrace.c
    trace_syscalls.c
)
add_executable(ministrace ${SOURCE})