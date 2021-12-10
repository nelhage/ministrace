
# - Generate syscalls -
set(LINUX_SRC_DIR "/usr/src/linux-5.4.0")

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