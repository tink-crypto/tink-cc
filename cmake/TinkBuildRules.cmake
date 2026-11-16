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
#
# Sensible defaults are provided for all variables, except TINK_MODULE, which is
# defined by calls to tink_module(). Please don't alter it directly.

include(CMakeParseArguments)

# We currently explicitly declare our libraries static below (in add_library).
# We might remove this, but I'm not confident enough in how this works to
# guarantee that shared libs work properly. Note that e.g. the protobuf
# library does extra work on Windows because of the way Abseil is bundled.
# https://github.com/protocolbuffers/protobuf/blob/v31.1/cmake/abseil-cpp.cmake

if (BUILD_SHARED_LIBS)
  message(FATAL_ERROR "Tink currently expects to be built with BUILD_SHARED_LIBS=OFF")
endif()

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
  cmake_parse_arguments(PARSE_ARGV 0 _tink_set_to_external_target_deps
    ""
    "OUTPUT_VARIABLE"
    "DEPS"
  )
  set(_result "")
  foreach(_DEP IN LISTS _tink_set_to_external_target_deps_DEPS)
    if(NOT _DEP MATCHES "^tink::")
      list(APPEND _result "${_DEP}")
    endif()
  endforeach()
  set(${_tink_set_to_external_target_deps_OUTPUT_VARIABLE} "${_result}" PARENT_SCOPE)
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
  cmake_parse_arguments(PARSE_ARGV 0 _tink_set_to_escaped_target_name
    ""
    "NAME;OUTPUT_VARIABLE"
    ""
  )
  set(_FULL_NAME tink::${TINK_MODULE}::${_tink_set_to_escaped_target_name_NAME})
  string(REPLACE "::" "__" _ESCAPED_NAME "${_FULL_NAME}")
  set(${_tink_set_to_escaped_target_name_OUTPUT_VARIABLE}
      "${_ESCAPED_NAME}" PARENT_SCOPE)
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
target_link_libraries(tink PUBLIC tink::internal::boringssl)
target_compile_options(tink PRIVATE ${TINK_DEFAULT_COPTS})
target_compile_features(tink PUBLIC cxx_std_${TINK_CXX_STANDARD})
set_property(TARGET tink PROPERTY FOLDER "${TINK_IDE_FOLDER}")
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
  target_compile_options(tink_testonly PRIVATE ${TINK_DEFAULT_COPTS})
  target_compile_features(tink_testonly PUBLIC cxx_std_${TINK_CXX_STANDARD})
  set_property(TARGET tink_testonly PROPERTY FOLDER "${TINK_IDE_FOLDER}")
  add_library(tink::testonly ALIAS tink_testonly)
endif()

# Declare a Tink library. Registers its sources, headers, and external
# dependencies as part of the `tink` library target (or `tink_testonly` when
# TESTONLY is specified). Tink library declarations mirror Bazel's cc_library
# rules to organise code across modules.
#
# Arguments:
#   NAME      base name of the library; defines a tink::<MODULE>::<NAME> alias
#             to `tink` or `tink_testonly`.
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
  cmake_parse_arguments(PARSE_ARGV 0 tink_cc_library
    "PUBLIC;TESTONLY"
    "NAME"
    "SRCS;DEPS;TAGS"
  )

  list(FILTER tink_cc_library_SRCS EXCLUDE REGEX "\\.h$")

  if (tink_cc_library_TESTONLY AND NOT TINK_BUILD_TESTONLY)
    return()
  endif()

  if (NOT DEFINED TINK_MODULE)
    message(FATAL_ERROR
            "TINK_MODULE not defined, perhaps you are missing a tink_module() statement?")
  endif()

  # Check if this target must be skipped.
  foreach(_tink_cc_library_tag ${tink_cc_library_TAGS})
    # Exclude if using BoringSSL.
    if (${_tink_cc_library_tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_BORINGSSL})
      return()
    endif()
    # Exclude if building on Windows.
    if (${_tink_cc_library_tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_WINDOWS} AND WIN32)
      return()
    endif()
  endforeach()

  _tink_set_to_external_target_deps(DEPS ${tink_cc_library_DEPS}
                                    OUTPUT_VARIABLE _external_deps)

  if(tink_cc_library_TESTONLY)
    set(_target_name "tink_testonly")
  else()
    set(_target_name "tink")
  endif()

  target_sources(${_target_name} PRIVATE ${tink_cc_library_SRCS})
  target_link_libraries(${_target_name} PUBLIC ${_external_deps})
  add_library(
    tink::${TINK_MODULE}::${tink_cc_library_NAME} ALIAS ${_target_name})
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
  cmake_parse_arguments(PARSE_ARGV 0 tink_cc_test
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
  foreach(_tink_cc_test_tag ${tink_cc_test_TAGS})
    # Exclude if using BoringSSL.
    if (${_tink_cc_test_tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_BORINGSSL})
      return()
    endif()
    # Exclude if building on Windows.
    if (${_tink_cc_test_tag} STREQUAL ${TINK_TARGET_EXCLUDE_IF_WINDOWS} AND WIN32)
      return()
    endif()
  endforeach()

  _tink_set_to_escaped_target_name(NAME ${tink_cc_test_NAME}
                                   OUTPUT_VARIABLE _target_name)

  add_executable(${_target_name}
    ${tink_cc_test_SRCS}
  )

  _tink_set_to_external_target_deps(DEPS ${tink_cc_test_DEPS}
                                    OUTPUT_VARIABLE _external_deps)

  if(NOT "benchmark::benchmark_main" IN_LIST tink_cc_test_DEPS
      AND NOT "GTest::gtest_main" IN_LIST tink_cc_test_DEPS)
    target_link_libraries(${_target_name} GTest::gtest_main)
  endif()
  target_link_libraries(${_target_name} tink_testonly ${_external_deps})

  set_property(TARGET ${_target_name}
               PROPERTY FOLDER "${TINK_IDE_FOLDER}/Tests")
  set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD ${TINK_CXX_STANDARD})
  set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD_REQUIRED true)

  set(_test_args "")
  # Make benchmarks run faster by default. Can always override via e.g.
  # `ctest -V -R 'benchmark'-- --benchmark_min_time=1s`.
  if("benchmark::benchmark" IN_LIST tink_cc_test_DEPS)
    list(APPEND _test_args "--benchmark_min_time=0.01s")
  endif()

  # Note: This was preferred over using gtest_discover_tests because of [1].
  # [1] https://gitlab.kitware.com/cmake/cmake/-/issues/23039
  add_test(NAME ${_target_name}
           COMMAND ${_target_name} ${_test_args}
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
  cmake_parse_arguments(PARSE_ARGV 0 tink_cc_proto
    ""
    "NAME"
    "SRCS;DEPS"
  )

  if (NOT DEFINED TINK_MODULE)
    message(FATAL_ERROR "TINK_MODULE not defined")
  endif()

  set(tink_cc_proto_GEN_SRCS)
  foreach(_src_path ${tink_cc_proto_SRCS})
    get_filename_component(_src_absolute_path "${_src_path}" ABSOLUTE)
    get_filename_component(_src_basename "${_src_path}" NAME_WE)
    get_filename_component(_src_dir "${_src_absolute_path}" DIRECTORY)
    file(RELATIVE_PATH _src_rel_path "${PROJECT_SOURCE_DIR}" "${_src_dir}")

    set(_gen_srcs)
    foreach(_gen_ext .pb.h .pb.cc)
      list(APPEND _gen_srcs
           "${TINK_GENFILE_DIR}/${_src_rel_path}/${_src_basename}${_gen_ext}")
    endforeach()

    list(APPEND tink_cc_proto_GEN_SRCS ${_gen_srcs})

    add_custom_command(
      COMMAND protobuf::protoc
      ARGS
        --cpp_out "${TINK_GENFILE_DIR}"
        -I "${PROJECT_SOURCE_DIR}"
        "${_src_absolute_path}"
      OUTPUT
        ${_gen_srcs}
      DEPENDS
        protobuf::protoc
        ${_src_absolute_path}
      COMMENT "Running CXX protocol buffer compiler on ${_src_path}"
      VERBATIM
    )
  endforeach()

  set_source_files_properties(
    ${tink_cc_proto_GEN_SRCS} PROPERTIES GENERATED true)

  _tink_set_to_escaped_target_name(NAME ${tink_cc_proto_NAME}
                                  OUTPUT_VARIABLE _target_name)
  add_custom_target(${_target_name} DEPENDS ${tink_cc_proto_GEN_SRCS})
  add_dependencies(tink ${_target_name})

  tink_cc_library(
    NAME ${tink_cc_proto_NAME}
    SRCS ${tink_cc_proto_GEN_SRCS}
    DEPS
      protobuf::libprotobuf
      ${tink_cc_proto_DEPS}
  )
endfunction()

# Group related dependencies under a single logical rule name.
#
# Parameters:
#   NAME  base name of the group.
#   DEPS  list of dependencies to group.
#
# Delegates to tink_cc_library to forward any external DEPS to `tink`.
function(tink_target_group)
  cmake_parse_arguments(PARSE_ARGV 0 tink_target_group "" "NAME" "DEPS")
  tink_cc_library(NAME ${tink_target_group_NAME}
                  DEPS ${tink_target_group_DEPS})
endfunction()
