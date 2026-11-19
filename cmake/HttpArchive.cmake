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

include(FetchContent)
include(CMakeParseArguments)

cmake_policy(PUSH)
if (POLICY CMP0135)
  # Extract downloaded archives with the extraction timestamp rather than the
  # archive's timestamps so URL updates reliably trigger rebuilds.
  cmake_policy(SET CMP0135 NEW)
endif()

# Download, unpack and configure a dependency.
#
# The project is added as a subdirectory of Tink, unless DATA_ONLY is
# specified. This makes all target defined by it available as dependencies.
#
# This rule also defines two variables:
#   - <NAME>_SOURCE_DIR points to the root directory of the downloaded package;
#     it can be used to reference data in tests, or append extra include/link
#     paths in the Workspace file.
#   - <NAME>_BINARY_DIR points to the build directory.
#
# Parameters:
#   NAME name of the dependency.
#   URL url to fetch a source archive from.
#   SHA256 hash of the file downloaded from URL.
#
# Optional parameters:
#   CMAKE_ARGS any additional argument that should be passed to cmake when
#     configuring the downloaded archive. Defaults to empty.
#   DATA_ONLY flag, if present the package will only be downloaded, verified and
#     unpacked. No configuration step is performed, and no target included. This
#     is useful for downloading archives of test vectors or artifacts.
#     False by default.
#
function(_tink_http_archive)
  cmake_parse_arguments(PARSE_ARGV 0 arg
    "DATA_ONLY"
    "NAME;URL;SHA256"
    "CMAKE_ARGS"
  )

  string(TOLOWER "${arg_NAME}" lc_name)
  message(STATUS "Fetching ${arg_NAME}")

  # Point SOURCE_SUBDIR at a non-existent directory so FetchContent_MakeAvailable
  # only populates the archive without calling add_subdirectory() itself. That
  # avoids adding root CMakeLists.txt files for DATA_ONLY archives (such as
  # tink_boringssl) and lets us pass EXCLUDE_FROM_ALL to add_subdirectory()
  # directly without requiring CMake 3.28+.
  FetchContent_Declare(
    "${arg_NAME}"
    URL           "${arg_URL}"
    URL_HASH      "SHA256=${arg_SHA256}"
    SOURCE_SUBDIR "__tink_populate_only__"
  )

  FetchContent_GetProperties(${arg_NAME})
  set(already_populated "${${lc_name}_POPULATED}")
  get_property(subdirs_before DIRECTORY PROPERTY SUBDIRECTORIES)
  FetchContent_MakeAvailable(${arg_NAME})
  get_property(subdirs_after DIRECTORY PROPERTY SUBDIRECTORIES)

  if (NOT arg_DATA_ONLY
      AND NOT already_populated                        # Not already populated.
      AND subdirs_before STREQUAL subdirs_after        # Not merely declared by parent project.
      AND NOT "${${lc_name}_SOURCE_DIR}" STREQUAL "")  # Not satisfied by find_package() or provider.
    set(subdir "${${lc_name}_SOURCE_DIR}")
    message(STATUS "Adding subdirectory ${subdir} for ${arg_NAME}")
    add_subdirectory("${subdir}" "${${lc_name}_BINARY_DIR}" EXCLUDE_FROM_ALL)
  endif()

  # Expose these variables to the caller.
  set("${arg_NAME}_SOURCE_DIR" "${${lc_name}_SOURCE_DIR}" PARENT_SCOPE)
  set("${arg_NAME}_BINARY_DIR" "${${lc_name}_BINARY_DIR}" PARENT_SCOPE)
endfunction(_tink_http_archive)

cmake_policy(POP)
