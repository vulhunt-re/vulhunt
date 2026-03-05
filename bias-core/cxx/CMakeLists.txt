cmake_minimum_required(VERSION 3.7)
project(decompiler_ffi CXX)

if(CMAKE_VERSION VERSION_LESS "3.1")
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_definitions(-std=c++20)
  endif()
else()
  set(CMAKE_CXX_STANDARD 20)
endif()

add_subdirectory(decompiler)
add_subdirectory(third-party)

include_directories(${PROJECT_SOURCE_DIR}/ghidra/decompile)

set(DECOMPILER_FFI_SOURCES
    decompiler.cc
    decompiler.hh

    decompiler_annot.cc
    decompiler_annot.hh

    decompiler_arch.cc
    decompiler_arch.hh

    decompiler_loadimage.cc
    decompiler_loadimage.hh

    decompiler_scope.cc
    decompiler_scope.hh

    printc2.cc
    printc2.hh
)

add_compile_options(-O3)
add_library(decompiler_ffi ${DECOMPILER_FFI_SOURCES})
target_link_libraries(decompiler_ffi ghidra_libdecomp ghidra_decompiler ghidra_sleigh ghidra_base pugixml)

install(TARGETS decompiler_ffi RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
