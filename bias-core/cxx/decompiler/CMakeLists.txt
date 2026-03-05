cmake_minimum_required(VERSION 3.7)
project(decompiler CXX)

option(BUILD_DECOMPILE_EXECUTABLE
       "Build \"decompile\" executable as used by Ghidra" OFF)
option(BUILD_DECOMPILE_CLI_EXECUTABLE "Build REPL decompiler" OFF)

if(CMAKE_VERSION VERSION_LESS "3.1")
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_definitions(-std=c++20)
  endif()
else()
  set(CMAKE_CXX_STANDARD 20)
endif()

add_subdirectory(ghidra)

include_directories(${PROJECT_SOURCE_DIR}/ghidra/decompile)
include_directories(${PROJECT_SOURCE_DIR}/src)
# add_definitions(-DDEBUG)

# decompiler sources
set(decompiler_src
    "src/decompiler_test.cc" "src/decompiler_scope.cc"
    "src/decompiler_loadimage.cc" "src/decompiler_arch.cc" "src/decompiler.cc")

# decompiler executable
add_executable(decompiler ${decompiler_src})
target_link_libraries(decompiler ghidra_libdecomp)

# install library
install(TARGETS ghidra_libdecomp ghidra_decompiler ghidra_sleigh ghidra_base
        ARCHIVE)
