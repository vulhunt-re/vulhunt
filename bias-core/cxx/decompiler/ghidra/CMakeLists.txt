# ##############################################################################
# adopted from https://github.com/rizinorg/rz-ghidra/tree/dev/ghidra

# Base of everything
set(SOURCE_BASE_CXX
    # xml.cc
    marshal.cc
    space.cc
    float.cc
    address.cc
    pcoderaw.cc
    translate.cc
    opcodes.cc
    globalcontext.cc)

set(SOURCE_BASE_YACC xml.y)

# For libdecomp used in our decompiler and ghidra's decompile executable
set(SOURCE_DECOMPILER_CXX
    capability.cc
    architecture.cc
    modelrules.cc
    options.cc
    graph.cc
    cover.cc
    block.cc
    cast.cc
    typeop.cc
    database.cc
    cpool.cc
    comment.cc
    fspec.cc
    action.cc
    loadimage.cc
    # grammar.cc
    varnode.cc
    op.cc
    type.cc
    variable.cc
    varmap.cc
    jumptable.cc
    emulate.cc
    emulateutil.cc
    flow.cc
    userop.cc
    funcdata.cc
    funcdata_block.cc
    funcdata_varnode.cc
    unionresolve.cc
    funcdata_op.cc
    pcodeinject.cc
    heritage.cc
    prefersplit.cc
    rangeutil.cc
    ruleaction.cc
    subflow.cc
    blockaction.cc
    merge.cc
    double.cc
    coreaction.cc
    condexe.cc
    override.cc
    dynamic.cc
    crc32.cc
    prettyprint.cc
    printlanguage.cc
    printc.cc
    printjava.cc
    memstate.cc
    opbehavior.cc
    paramid.cc
    transform.cc
    # string_ghidra.cc
    stringmanage.cc
    signature.cc)

# libdecomp only
set(SOURCE_LIBDECOMP_CXX libdecomp.cc)

# specific to Ghidra's decompile executable
set(SOURCE_GHIDRA_CXX
    ghidra_process.cc
    ghidra_arch.cc
    loadimage_ghidra.cc
    typegrp_ghidra.cc
    database_ghidra.cc
    ghidra_context.cc
    cpool_ghidra.cc
    comment_ghidra.cc
    inject_ghidra.cc
    ghidra_translate.cc)

set(SOURCE_SLEIGH_CXX
    sleigh_arch.cc
    sleigh.cc
    inject_sleigh.cc
    filemanage.cc
    semantics.cc
    slghsymbol.cc
    context.cc
    sleighbase.cc
    slghpatexpress.cc
    slghpattern.cc
    pcodecompile.cc)

set(SOURCE_SLEIGH_YACC pcodeparse.y grammar.y)

# cli
set(SOURCE_CONSOLE_CXX
    consolemain.cc
    interface.cc
    ifacedecomp.cc
    testfunction.cc
    ifaceterm.cc
    callgraph.cc
    raw_arch.cc)

# sleighc
set(SLEIGH_COMPILER_SOURCE_CXX slgh_compile.cc slgh_compile.hh)

set(SLEIGH_COMPILER_SOURCE_YACC slghparse.y)

set(SLEIGH_COMPILER_SOURCE_FLEX slghscan.l)

set(SOURCE_DIR decompile)

# ##############################################################################

function(prepend_src_dir list_name)
  set(tmp)
  foreach(r ${${list_name}})
    list(APPEND tmp "${SOURCE_DIR}/${r}")
  endforeach()
  set(${list_name}
      "${tmp}"
      PARENT_SCOPE)
endfunction()

prepend_src_dir(SOURCE_BASE_CXX)
prepend_src_dir(SOURCE_DECOMPILER_CXX)
prepend_src_dir(SOURCE_LIBDECOMP_CXX)
prepend_src_dir(SOURCE_GHIDRA_CXX)
prepend_src_dir(SOURCE_SLEIGH_CXX)
prepend_src_dir(SOURCE_CONSOLE_CXX)
prepend_src_dir(SLEIGH_COMPILER_SOURCE_CXX)

if(GENERATE_PARSERS)
  find_package(BISON REQUIRED)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bison")
  find_package(FLEX REQUIRED)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/flex")

  # build yacc files and append the output files to OUT_VAR
  macro(build_bison OUT_VAR)
    foreach(yacc_file ${ARGN})
      get_filename_component(yacc_name "${yacc_file}" NAME_WE)
      if("${yacc_name}" STREQUAL "slghparse")
        set(yacc_prefix yy)
      else()
        set(yacc_prefix "${yacc_name}")
      endif()
      if(BISON_VERSION VERSION_LESS 2.6)
        set(BISON_COMPILE_FLAGS "--name-prefix=${yacc_prefix}")
      else()
        set(BISON_COMPILE_FLAGS "-Dapi.prefix={${yacc_prefix}}")
      endif()
      bison_target(
        ${yacc_name} "${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_DIR}/${yacc_file}"
        "${CMAKE_CURRENT_BINARY_DIR}/bison/${yacc_name}.cpp"
        COMPILE_FLAGS ${BISON_COMPILE_FLAGS})
      list(APPEND ${OUT_VAR} "${BISON_${yacc_name}_OUTPUTS}")
    endforeach()
  endmacro()

  build_bison(SOURCE_BASE_CXX ${SOURCE_BASE_YACC})
  build_bison(SOURCE_SLEIGH_CXX ${SOURCE_SLEIGH_YACC})
  build_bison(SLEIGH_COMPILER_SOURCE_CXX ${SLEIGH_COMPILER_SOURCE_YACC})

  flex_target(slghscan "${SOURCE_DIR}/${SLEIGH_COMPILER_SOURCE_FLEX}"
              "${CMAKE_CURRENT_BINARY_DIR}/flex/slghscan.cpp")
  list(APPEND SLEIGH_COMPILER_SOURCE_CXX
       "${CMAKE_CURRENT_BINARY_DIR}/flex/slghscan.cpp")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/flex/slghparse.tab.hh"
       "#include \"../bison/slghparse.hpp\"")
else()
  list(APPEND SOURCE_BASE_CXX "${SOURCE_DIR}/xml.hh" "${SOURCE_DIR}/xml.cc")
  list(APPEND SOURCE_SLEIGH_CXX "${SOURCE_DIR}/pcodeparse.hh"
       "${SOURCE_DIR}/pcodeparse.cc" "${SOURCE_DIR}/grammar.hh"
       "${SOURCE_DIR}/grammar.cc")
  list(APPEND SLEIGH_COMPILER_SOURCE_CXX "${SOURCE_DIR}/slghparse.hh"
       "${SOURCE_DIR}/slghparse.cc" "${SOURCE_DIR}/slghscan.cc")
endif()

add_library(ghidra_base STATIC ${SOURCE_BASE_CXX})
target_include_directories(ghidra_base PUBLIC "${SOURCE_DIR}")
set_target_properties(ghidra_base PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(ghidra_decompiler STATIC ${SOURCE_DECOMPILER_CXX})
target_link_libraries(ghidra_decompiler PUBLIC ghidra_base)
target_include_directories(ghidra_decompiler PUBLIC "${SOURCE_DIR}")
set_target_properties(ghidra_decompiler PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(ghidra_sleigh STATIC ${SOURCE_SLEIGH_CXX})
target_link_libraries(ghidra_sleigh PUBLIC ghidra_base)
target_include_directories(ghidra_sleigh PUBLIC "${SOURCE_DIR}")
set_target_properties(ghidra_sleigh PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(ghidra_libdecomp STATIC ${SOURCE_LIBDECOMP_CXX})
target_link_libraries(ghidra_libdecomp PUBLIC ghidra_decompiler ghidra_sleigh)
set_target_properties(ghidra_libdecomp PROPERTIES POSITION_INDEPENDENT_CODE ON)

# "decompile" executable as used by Ghidra
if(BUILD_DECOMPILE_EXECUTABLE)
  add_executable(ghidra_decompiler_exec ${SOURCE_GHIDRA_CXX})
  target_link_libraries(ghidra_decompiler_exec ghidra_decompiler)
  set_target_properties(ghidra_decompiler_exec PROPERTIES OUTPUT_NAME decompile)
endif()

if(BUILD_DECOMPILE_CLI_EXECUTABLE)
  add_executable(ghidra_decompiler_cli ${SOURCE_CONSOLE_CXX})
  target_link_libraries(ghidra_decompiler_cli ghidra_libdecomp)
  set_target_properties(ghidra_decompiler_cli PROPERTIES OUTPUT_NAME
                                                         decompile_cli)
endif()

add_executable(sleighc ${SLEIGH_COMPILER_SOURCE_CXX})
target_link_libraries(sleighc ghidra_sleigh)
target_include_directories(sleighc PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/flex")
