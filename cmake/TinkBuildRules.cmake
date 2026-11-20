# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Partially adapted from Abseil's CMake helpers
# https://github.com/abseil/abseil-cpp/blob/master/CMake/AbseilHelpers.cmake

# Rules for declaring Tink targets in a way similar to Bazel.
#
# These functions are intended to reduce the difficulty of supporting completely
# different build systems, and are designed for Tink internal usage only.
# They may work outside this project too, but we don't support that.
#
# A set of global variables influences the behavior of the rules:
#
#   TINK_MODULE name used to build more descriptive names and for namespaces.
#   TINK_GENFILE_DIR generated content root, such pb.{cc,h} files.
#   TINK_INCLUDE_DIRS list of global include paths.
#   TINK_CXX_STANDARD C++ standard to enforce, 11 for now.
#   TINK_BUILD_TESTS enables building tests (requires TINK_BUILD_TESTONLY).
#   TINK_BUILD_TESTONLY enables building test-only helper libraries.
#   TINK_ENABLE_INSTALL enables installation.
#
# Sensible defaults are provided for all variables, except TINK_MODULE, which is
# defined by calls to tink_module(). Please don't alter it directly.

include(CMakeParseArguments)
include(GNUInstallDirs)

if (TINK_BUILD_TESTS)
  if (NOT TINK_BUILD_TESTONLY)
    message(FATAL_ERROR "TINK_BUILD_TESTS requires TINK_BUILD_TESTONLY")
  endif()
  enable_testing()
endif()

if (NOT DEFINED TINK_GENFILE_DIR)
  set(TINK_GENFILE_DIR "${PROJECT_BINARY_DIR}/__generated")
endif()

if (NOT DEFINED TINK_CXX_STANDARD)
  set(TINK_CXX_STANDARD 17)
  if (DEFINED CMAKE_CXX_STANDARD_REQUIRED AND CMAKE_CXX_STANDARD_REQUIRED AND DEFINED CMAKE_CXX_STANDARD)
    set(TINK_CXX_STANDARD ${CMAKE_CXX_STANDARD})
  endif()
endif()

set(TINK_DEFAULT_COPTS "")
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  # This is required to avoid error C1128.
  # See https://learn.microsoft.com/en-us/cpp/error-messages/compiler-errors-1/fatal-error-c1128?view=msvc-170.
  set(TINK_DEFAULT_COPTS "/bigobj")
endif()

list(APPEND TINK_INCLUDE_DIRS "${TINK_GENFILE_DIR}")

set(TINK_IDE_FOLDER "Tink")

set(TINK_TARGET_EXCLUDE_IF_BORINGSSL "exclude_if_boringssl")
set(TINK_TARGET_EXCLUDE_IF_WINDOWS "exclude_if_windows")

# Declare the beginning of a new Tink library namespace.
#
# As a rule of thumb, every CMakeLists.txt should be a different module, named
# after the directory that contains it, and this function should appear at the
# top of each CMakeLists script.
#
# This is not a requirement, though. Targets should be grouped logically, and
# multiple directories can be part of the same module as long as target names
# do not collide.
#
macro(tink_module NAME)
  set(TINK_MODULE ${NAME})
endmacro()

# Filters DEPS down to external targets, leaving out any `tink::` ones.
#
# Parameters:
#   DEPS             list of dependencies, as e.g. used by `tink_cc_library`.
#   OUTPUT_VARIABLE  variable to store the result in.
#
# Sets OUTPUT_VARIABLE to the list of external targets in DEPS.
#
# TODO(b/570488948): Remove this after removing the tink:: dependencies in our
# `tink_cc_library` etc. rules.
function(_tink_set_to_external_target_deps)
  # Filter DEPS down to external targets (absl::, protobuf::, ...), dropping
  # Tink-internal tink::<MODULE>::<NAME> deps that are already folded into
  # `tink` / `tink_testonly`.
  cmake_parse_arguments(PARSE_ARGV 0 arg
    ""
    "OUTPUT_VARIABLE"
    "DEPS"
  )
  set(result "")
  foreach(dep IN LISTS arg_DEPS)
    if(NOT dep MATCHES "^tink::")
      list(APPEND result "${dep}")
    endif()
  endforeach()
  set(${arg_OUTPUT_VARIABLE} "${result}" PARENT_SCOPE)
endfunction()

# Returns a CMake target name for the given namespaced Tink name.
#
# Parameters:
#   NAME             internal name of the target relative to the current module.
#   OUTPUT_VARIABLE  variable to store the result in.
#
# Sets OUTPUT_VARIABLE to the target name usable for e.g. add_library().
#
# TODO(b/570488948): Once the legacy target names are gone, consider just
# storing the fully qualified and escaped form in TINK_MODULE and removing this
# function.
function(_tink_set_to_escaped_target_name)
  # We replace :: with __ in targets, because :: may not appear in target names.
  # However, the target name should still span multiple name spaces.
  cmake_parse_arguments(PARSE_ARGV 0 arg
    ""
    "NAME;OUTPUT_VARIABLE"
    ""
  )
  set(full_name tink::${TINK_MODULE}::${arg_NAME})
  string(REPLACE "::" "__" escaped_name "${full_name}")
  set(${arg_OUTPUT_VARIABLE} "${escaped_name}" PARENT_SCOPE)
endfunction()

# Merges one library into another.
#
# Parameters:
#   TARGET   CMake target name of the library to merge into.
#   LIBRARY  CMake target name of the library to merge from. Must be `STATIC`.
#
# If `TARGET` is a shared library, just links to `LIBRARY` normally.
# If `TARGET` is a static library, creates an archive that contains both the
# contents of `TARGET` and `LIBRARY`.
#
# This is used to merge BoringSSL's `crypto` archive into libtink.a / tink.lib
# so that the static library is self-contained, and forward only BoringSSL's
# system link dependencies without putting libcrypto.a itself onto downstream
# linker command lines - thereby insulating downstream users from BoringSSL API
# changes and even allowing them to link to their own BoringSSL or OpenSSL.
function(_tink_target_link_merged_library)
  cmake_parse_arguments(PARSE_ARGV 0 arg
    ""
    "TARGET;LIBRARY"
    ""
  )
  get_target_property(library_type ${arg_LIBRARY} TYPE)
  if(NOT library_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR
            "_tink_target_link_merged_library requires a STATIC library")
  endif()
  get_target_property(target_type ${arg_TARGET} TYPE)
  if(NOT target_type STREQUAL "STATIC_LIBRARY")
    target_link_libraries(${arg_TARGET}
                          PRIVATE ${arg_LIBRARY})
    return()
  endif()

  add_dependencies(${arg_TARGET} ${arg_LIBRARY})
  get_target_property(library_deps ${arg_LIBRARY} INTERFACE_LINK_LIBRARIES)
  if(library_deps)
    target_link_libraries(${arg_TARGET} PRIVATE ${library_deps})
  endif()
  if(MSVC)
    # MSVC's linker just allows passing a .lib file as an input and it will
    # embed it into the output.
    set_property(TARGET ${arg_TARGET}
                 APPEND PROPERTY STATIC_LIBRARY_OPTIONS
                 "$<TARGET_FILE:${arg_LIBRARY}>")
  elseif(APPLE)
    # Apple's fat binary support is only implemented via Apple's libtool.
    add_custom_command(TARGET ${arg_TARGET}
                       POST_BUILD COMMAND
                       /usr/bin/libtool
                         -static -no_warning_for_no_symbols
                         -o "\"$<TARGET_FILE:${arg_TARGET}>\""
                         "\"$<TARGET_FILE:${arg_TARGET}>\""
                         "\"$<TARGET_FILE:${arg_LIBRARY}>\"" ||
                       (
                         "\"${CMAKE_COMMAND}\"" -E rm -f
                           "\"$<TARGET_FILE:${arg_TARGET}>\"" &&
                         "\"${CMAKE_COMMAND}\"" -E false
                       ))
  else()
    # Other systems either have GNU ar or LLVM ar, both of which support
    # `-M` MRI scripts.
    set(mri "${PROJECT_BINARY_DIR}/merge_${arg_TARGET}_$<CONFIG>.mri")
    string(CONCAT mri_content
           "CREATE $<TARGET_FILE:${arg_TARGET}>.merged\n"
           "ADDLIB $<TARGET_FILE:${arg_TARGET}>\n"
           "ADDLIB $<TARGET_FILE:${arg_LIBRARY}>\n"
           "SAVE\n"
           "END\n")
    file(GENERATE OUTPUT "${mri}" CONTENT "${mri_content}")
    add_custom_command(TARGET ${arg_TARGET}
                       POST_BUILD COMMAND
                       "${CMAKE_AR}"
                         -M < "\"${mri}\"" &&
                       "\"${CMAKE_COMMAND}\"" -E rename
                         "\"$<TARGET_FILE:${arg_TARGET}>.merged\""
                         "\"$<TARGET_FILE:${arg_TARGET}>\"" ||
                       (
                         "\"${CMAKE_COMMAND}\"" -E rm -f
                           "\"$<TARGET_FILE:${arg_TARGET}>\""
                           "\"$<TARGET_FILE:${arg_TARGET}>.merged\"" &&
                         "\"${CMAKE_COMMAND}\"" -E false
                       ))
  endif()
endfunction()

# Declare the main Tink library target.
#
# This target will contain all Tink source and headers that can be used by
# production code. This includes any public and non-public Tink targets, except
# for those declared TESTONLY.
#
# Actual sources and headers are added to this target by `tink_cc_library`.
add_library(tink "")
target_include_directories(tink PUBLIC
                           "${PROJECT_SOURCE_DIR}" ${TINK_INCLUDE_DIRS})
_tink_target_link_merged_library(TARGET tink
                                 LIBRARY tink::internal::boringssl)
target_compile_options(tink PRIVATE ${TINK_DEFAULT_COPTS})
target_compile_features(tink PUBLIC cxx_std_${TINK_CXX_STANDARD})
set_property(TARGET tink PROPERTY FOLDER "${TINK_IDE_FOLDER}")
set_property(TARGET tink PROPERTY OUTPUT_NAME tink${PROJECT_VERSION_MAJOR})
set_property(TARGET tink PROPERTY VERSION "${PROJECT_VERSION}")
set_property(TARGET tink PROPERTY SOVERSION "${PROJECT_VERSION_MAJOR}")
add_library(tink::tink ALIAS tink)

# Declare the test-only Tink library target.
#
# This target will contain all Tink source and headers that can be used by test
# code only. This means any Tink target declared TESTONLY.
#
# Actual sources and headers are added to this target by `tink_cc_library`.
if(TINK_BUILD_TESTONLY)
  add_library(tink_testonly "")
  target_link_libraries(tink_testonly PUBLIC tink)
  # Link test helpers also to BoringSSL.
  #
  # Some, few, test helpers make their own BoringSSL calls, but `tink` does not
  # re-export BoringSSL symbols due to BoringSSL using `-fvisibility=hidden`.
  _tink_target_link_merged_library(TARGET tink_testonly
                                   LIBRARY tink::internal::boringssl)
  target_compile_options(tink_testonly PRIVATE ${TINK_DEFAULT_COPTS})
  target_compile_features(tink_testonly PUBLIC cxx_std_${TINK_CXX_STANDARD})
  set_property(TARGET tink_testonly PROPERTY FOLDER "${TINK_IDE_FOLDER}")
  set_property(TARGET tink_testonly PROPERTY OUTPUT_NAME tink${PROJECT_VERSION_MAJOR}_testonly)
  set_property(TARGET tink_testonly PROPERTY VERSION "${PROJECT_VERSION}")
  set_property(TARGET tink_testonly PROPERTY SOVERSION "${PROJECT_VERSION_MAJOR}")
  add_library(tink::testonly ALIAS tink_testonly)
endif()

if(TINK_ENABLE_INSTALL)
  install(TARGETS tink)
  if(TINK_BUILD_TESTONLY)
    install(TARGETS tink_testonly)
  endif()
endif()

# Preference list of source directories for headers. Headers will be assumed
# relative to the first matching directory in this list.
set(_tink_source_dirs)
foreach(_tink_source_dir "${TINK_GENFILE_DIR}" "${PROJECT_SOURCE_DIR}")
  cmake_path(ABSOLUTE_PATH _tink_source_dir
             BASE_DIRECTORY "${PROJECT_SOURCE_DIR}"
             NORMALIZE)
  list(APPEND _tink_source_dirs "${_tink_source_dir}")
endforeach()

define_property(SOURCE PROPERTY _TINK_HEADER_INSTALLED
                BRIEF_DOCS "Header install indicator."
                FULL_DOCS  "Indicates whether a header has been installed.")

# Installs headers under `<includedir>/tink-<major>`, preserving each header's
# path relative to `TINK_GENFILE_DIR` (for generated headers) or
# `PROJECT_SOURCE_DIR` (for source headers).
function(_tink_install_headers)
  if(NOT TINK_ENABLE_INSTALL)
    return()
  endif()
  cmake_parse_arguments(PARSE_ARGV 0 arg
    ""
    ""
    "HDRS"
  )

  foreach(hdr IN LISTS arg_HDRS)
    cmake_path(ABSOLUTE_PATH hdr
               BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
               NORMALIZE)

    get_property(already_installed
                 SOURCE "${hdr}"
                 DIRECTORY "${PROJECT_SOURCE_DIR}"
                 PROPERTY _TINK_HEADER_INSTALLED)
    if(already_installed)
      continue()
    endif()

    foreach(source_dir IN LISTS _tink_source_dirs)
      cmake_path(IS_PREFIX source_dir "${hdr}" is_prefix)
      if(NOT is_prefix)
        continue()
      endif()
      cmake_path(RELATIVE_PATH hdr
                 BASE_DIRECTORY "${source_dir}"
                 OUTPUT_VARIABLE rel_hdr)
      cmake_path(GET rel_hdr PARENT_PATH rel_dir)
      set(dest "${CMAKE_INSTALL_INCLUDEDIR}/tink-${PROJECT_VERSION_MAJOR}")
      if(NOT "${rel_dir}" STREQUAL "")
        cmake_path(APPEND dest "${rel_dir}")
      endif()
      install(FILES "${hdr}" DESTINATION "${dest}")
      set_property(SOURCE "${hdr}"
                   DIRECTORY "${PROJECT_SOURCE_DIR}"
                   PROPERTY _TINK_HEADER_INSTALLED TRUE)
      break()
    endforeach()

    get_property(actually_installed
                 SOURCE "${hdr}"
                 DIRECTORY "${PROJECT_SOURCE_DIR}"
                 PROPERTY _TINK_HEADER_INSTALLED)
    if(NOT actually_installed)
      message(FATAL_ERROR "Header ${hdr} directory not in ${_tink_source_dirs}")
    endif()
  endforeach()
endfunction()

define_property(TARGET PROPERTY _TINK_LINKED_DEPS
                BRIEF_DOCS "Linked external dependencies."
                FULL_DOCS  "External targets already linked onto this target.")

# Declare a Tink library. Registers its sources, headers, and external
# dependencies as part of the `tink` library target (or `tink_testonly` when
# TESTONLY is specified). Tink library declarations mirror Bazel's cc_library
# rules to organise code across modules.
#
# Arguments:
#   NAME      base name of the library; ignored (accepted for parity with Bazel
#             rules). No tink::<MODULE>::<NAME> target or alias is exposed;
#             downstream code must link against `tink` or `tink_testonly`.
#   SRCS      list of source files, including headers for documentation purposes
#             and Bazel similarity.
#   DEPS      list of dependency targets (only external targets are used, the
#             rest serve documentation purposes only and should match Bazel).
#   PUBLIC    flag, ignored (accepted for parity with Bazel rules; all
#             non-TESTONLY libraries and headers are part of `tink`).
#   TESTONLY  flag, signals that this target belongs to tink_testonly and
#             should be ignored if TINK_BUILD_TESTONLY=OFF.
#
# Tink-internal `tink::*` entries in DEPS are ignored by CMake (since all Tink
# sources and headers are compiled together into `tink` / `tink_testonly`),
# while external entries in DEPS are linked onto `tink` / `tink_testonly`.
# Unlike Bazel, CMake does not enforce that all dependencies of a rule are
# listed: a file might still compile and link if another rule already pulled in
# a needed external dependency, which could break if that other rule changes.
# Make sure that all dependencies are explicitly specified to stay aligned with
# Bazel.
#
function(tink_cc_library)
  cmake_parse_arguments(PARSE_ARGV 0 arg
    "PUBLIC;TESTONLY"
    "NAME"
    "SRCS;DEPS;TAGS"
  )

  set(hdrs "${arg_SRCS}")
  list(FILTER hdrs INCLUDE REGEX "\\.h$")
  list(FILTER arg_SRCS EXCLUDE REGEX "\\.h$")

  if (arg_TESTONLY AND NOT TINK_BUILD_TESTONLY)
    return()
  endif()

  if (NOT DEFINED TINK_MODULE)
    message(FATAL_ERROR
            "TINK_MODULE not defined, perhaps you are missing a tink_module() statement?")
  endif()

  # Check if this target must be skipped.
  foreach(tag ${arg_TAGS})
    # Exclude if using BoringSSL.
    if (${tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_BORINGSSL})
      return()
    endif()
    # Exclude if building on Windows.
    if (${tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_WINDOWS} AND WIN32)
      return()
    endif()
  endforeach()

  _tink_set_to_external_target_deps(DEPS ${arg_DEPS}
                                    OUTPUT_VARIABLE external_deps)

  if(arg_TESTONLY)
    set(target_name "tink_testonly")
  else()
    set(target_name "tink")
  endif()

  target_sources(${target_name} PRIVATE ${arg_SRCS})
  if(external_deps)
    list(REMOVE_DUPLICATES external_deps)
    get_target_property(existing_deps ${target_name} _TINK_LINKED_DEPS)
    if(existing_deps)
      list(REMOVE_ITEM external_deps ${existing_deps})
    endif()
    if(external_deps)
      target_link_libraries(${target_name} PUBLIC ${external_deps})
      set_property(TARGET ${target_name} APPEND PROPERTY _TINK_LINKED_DEPS
                   ${external_deps})
    endif()
  endif()
  _tink_install_headers(HDRS ${hdrs})
endfunction(tink_cc_library)

# Declare a Tink test using googletest, with a syntax similar to Bazel.
#
# Parameters:
#   NAME  base name of the test.
#   SRCS  list of test source files, headers included.
#   DEPS  list of dependencies, see tink_cc_library above.
#   DATA  list of non-code dependencies, such as test vectors.
#
# Tests added with this macro are automatically registered.
# Each test produces a build target named tink__<ESCAPED_MODULE>__<NAME>,
# where <ESCAPED_MODULE> is <MODULE> with "::" replaced by "__".
#
function(tink_cc_test)
  cmake_parse_arguments(PARSE_ARGV 0 arg
    ""
    "NAME"
    "SRCS;DEPS;DATA;TAGS"
  )

  if (NOT TINK_BUILD_TESTS)
    return()
  endif()

  if (NOT DEFINED TINK_MODULE)
    message(FATAL_ERROR "TINK_MODULE not defined")
  endif()

  # Check if this target must be skipped.
  foreach(tag ${arg_TAGS})
    # Exclude if using BoringSSL.
    if (${tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_BORINGSSL})
      return()
    endif()
    # Exclude if building on Windows.
    if (${tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_WINDOWS} AND WIN32)
      return()
    endif()
  endforeach()

  _tink_set_to_escaped_target_name(NAME ${arg_NAME}
                                   OUTPUT_VARIABLE target_name)

  add_executable(${target_name}
    ${arg_SRCS}
  )

  _tink_set_to_external_target_deps(DEPS ${arg_DEPS}
                                    OUTPUT_VARIABLE external_deps)

  if(NOT "benchmark::benchmark_main" IN_LIST arg_DEPS
      AND NOT "GTest::gtest_main" IN_LIST arg_DEPS)
    target_link_libraries(${target_name} GTest::gtest_main)
  endif()
  target_link_libraries(${target_name} tink_testonly ${external_deps})

  # Link all tests also to BoringSSL.
  #
  # Some, few, tests make their own BoringSSL calls, but `tink` and
  # `tink_testonly` do not re-export BoringSSL symbols due to BoringSSL using
  # `-fvisibility=hidden`.
  target_link_libraries(${target_name} tink::internal::boringssl)

  set_property(TARGET ${target_name}
               PROPERTY FOLDER "${TINK_IDE_FOLDER}/Tests")
  set_property(TARGET ${target_name} PROPERTY CXX_STANDARD ${TINK_CXX_STANDARD})
  set_property(TARGET ${target_name} PROPERTY CXX_STANDARD_REQUIRED true)

  set(test_args "")
  # Make benchmarks run faster by default. Can always override via e.g.
  # `ctest -V -R 'benchmark'-- --benchmark_min_time=1s`.
  if("benchmark::benchmark" IN_LIST arg_DEPS)
    list(APPEND test_args "--benchmark_min_time=0.01s")
  endif()

  # Note: This was preferred over using gtest_discover_tests because of [1].
  # [1] https://gitlab.kitware.com/cmake/cmake/-/issues/23039
  add_test(NAME ${target_name}
           COMMAND ${target_name} ${test_args}
           WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endfunction(tink_cc_test)

# Declare a C++ Proto library.
#
# Parameters:
#   NAME base name of the library.
#   SRCS list of .proto source files.
#   DEPS list of proto library dependencies, produced by tink_cc_proto or not.
#
# Each tink_cc_proto rule produces a custom target named
# tink__<ESCAPED_MODULE>__<NAME> (where <ESCAPED_MODULE> is <MODULE> with "::"
# replaced by "__") that drives `.pb.{h,cc}` generation, which `tink` depends
# on, and registers the generated files and dependencies as part of `tink` via
# tink_cc_library.
#
function(tink_cc_proto)
  cmake_parse_arguments(PARSE_ARGV 0 arg
    ""
    "NAME"
    "SRCS;DEPS"
  )

  if (NOT DEFINED TINK_MODULE)
    message(FATAL_ERROR "TINK_MODULE not defined")
  endif()

  set(all_gen_srcs)
  foreach(src_path ${arg_SRCS})
    get_filename_component(src_absolute_path "${src_path}" ABSOLUTE)
    get_filename_component(src_basename "${src_path}" NAME_WE)
    get_filename_component(src_dir "${src_absolute_path}" DIRECTORY)
    file(RELATIVE_PATH src_rel_path "${PROJECT_SOURCE_DIR}" "${src_dir}")

    set(gen_srcs)
    foreach(gen_ext .pb.h .pb.cc)
      list(APPEND gen_srcs
           "${TINK_GENFILE_DIR}/${src_rel_path}/${src_basename}${gen_ext}")
    endforeach()

    list(APPEND all_gen_srcs ${gen_srcs})

    add_custom_command(
      COMMAND protobuf::protoc
      ARGS
        --cpp_out "${TINK_GENFILE_DIR}"
        -I "${PROJECT_SOURCE_DIR}"
        "${src_absolute_path}"
      OUTPUT
        ${gen_srcs}
      DEPENDS
        protobuf::protoc
        ${src_absolute_path}
      COMMENT "Running CXX protocol buffer compiler on ${src_path}"
      VERBATIM
    )
  endforeach()

  set_source_files_properties(
    ${all_gen_srcs} PROPERTIES GENERATED true)

  _tink_set_to_escaped_target_name(NAME ${arg_NAME}
                                   OUTPUT_VARIABLE target_name)
  add_custom_target(${target_name} DEPENDS ${all_gen_srcs})
  add_dependencies(tink ${target_name})

  tink_cc_library(
    NAME ${arg_NAME}
    SRCS ${all_gen_srcs}
    DEPS
      protobuf::libprotobuf
      ${arg_DEPS}
  )
endfunction()
