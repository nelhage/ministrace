# From https://www.scivision.dev/cmake-git-submodule/

function(add_git_submodule dir)
# add a Git submodule directory to CMake, assuming the
# Git submodule directory is a CMake project.
#
# Usage: in CMakeLists.txt
# 
# include(AddGitSubModule.cmake)
# add_git_submodule(mysubmod_dir)

find_package(Git REQUIRED)

if(NOT EXISTS ${dir}/CMakeLists.txt)
# git submodule add https://gitlab.com/cunity/cunit.git ext/cunit
  execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive -- ${dir}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    RESULT_VARIABLE _err)

  if(NOT _err EQUAL 0)
    message(SEND_ERROR "Could not retrieve Git submodule ${dir}.")
  endif()
endif()

endfunction()