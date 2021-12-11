# Ensure debug info and assert functions are build during compile of tests
set(CMAKE_BUILD_TYPE Debug)


# -- Ultimate test program --
if (WITH_TESTS)
    add_executable(ultimate_test_program ultimate_test_program.c)
    target_link_libraries(ultimate_test_program pthread)

    add_executable(testing_trace_tmap
            ../src/trace_tmap.c
            testing_trace_tmap.c)
    target_link_libraries(testing_trace_tmap hashmap)
endif()
