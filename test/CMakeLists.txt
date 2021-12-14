# Ensure debug info and assert functions are build during compile of tests
set(CMAKE_BUILD_TYPE Debug)


# -- Ultimate test program --
if (WITH_TESTS)
    # - Component tests -
    add_executable(tmap_test
            ../src/trace_tmap.c
            tmap_test.c)
    target_link_libraries(tmap_test hashmap)


    # - Test tracing programs -
    add_executable(trace_pthread_fork trace_pthread_fork.c)
    target_link_libraries(trace_pthread_fork pthread)

    add_executable(trace_descendants trace_descendants.c)
endif()
