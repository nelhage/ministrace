# ensure debug info and assert functions are build during compile of tests
set(CMAKE_BUILD_TYPE Debug)


# -- Ultimate test program --
add_executable(ultimate_test_program ultimate_test_program.c)
target_link_libraries(ultimate_test_program "-lpthread")