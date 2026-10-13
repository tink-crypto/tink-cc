# Copyright 2026 Google LLC
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

# Builds the private copy of BoringSSL used by Tink.
#
# Tink always links its own, statically linked BoringSSL, whose symbols are
# prefixed with `bssl_tink`, so that it never interferes with any other OpenSSL
# or BoringSSL linked into the same process. It never reuses a `crypto` target
# or a `boringssl` download declared by the including project.
#
# BoringSSL is downloaded at configure time and built at build time as a
# separate CMake project (ExternalProject). This keeps BoringSSL's own targets
# (`crypto`, `ssl`) and directory-level settings out of the including project,
# so they cannot collide with another copy of BoringSSL.
#
# This file defines:
#   - tink::internal::boringssl: the static library Tink targets link against.
#   - BORINGSSL_PREFIX: the symbol prefix. Tink's top-level CMakeLists.txt
#     compiles Tink's own sources with the matching define.

include(ExternalProject)
include(HttpArchive)

set(BORINGSSL_PREFIX "bssl_tink")
# Release from 2026-09-29.
set(_tink_boringssl_version "0.20260929.0")
set(_tink_boringssl_sha256
    "04da9ba0664e0a7f028e961c38d604f2cc6dac852a84ca0e51dc1fa051d4c8fe")

# Download and unpack the sources at configure time: CMake requires the include
# directory of an imported target to exist when it generates the build files.
# The name is Tink-specific because FetchContent names are global.
http_archive(
  NAME tink_boringssl
  URL "https://github.com/google/boringssl/releases/download/${_tink_boringssl_version}/boringssl-${_tink_boringssl_version}.tar.gz"
  SHA256 "${_tink_boringssl_sha256}"
  DATA_ONLY
)

# BoringSSL is built in a directory owned by Tink. The version is part of the
# name, so that a version update always starts from a clean build.
set(_tink_boringssl_dir
    "${CMAKE_CURRENT_BINARY_DIR}/tink_boringssl-${_tink_boringssl_version}")
set(_tink_boringssl_lib_dir "${_tink_boringssl_dir}/lib")
# libcrypto.a on Unix, crypto.lib on Windows.
set(_tink_boringssl_lib_name
    "${CMAKE_STATIC_LIBRARY_PREFIX}crypto${CMAKE_STATIC_LIBRARY_SUFFIX}")
# True for Visual Studio, Xcode and Ninja Multi-Config, which build several
# configurations (Debug, Release, ...) from one build directory.
get_property(_tink_is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

# Settings that make this BoringSSL Tink's private copy. They are passed to
# BoringSSL's own `cmake` run.
set(_tink_boringssl_cmake_args
  # Add the Tink-specific prefix to all BoringSSL symbols (see "Building with
  # Prefixed Symbols" in BoringSSL's BUILDING.md).
  "-DBORINGSSL_PREFIX=${BORINGSSL_PREFIX}"
  "-DBUILD_SHARED_LIBS=OFF"
  # BoringSSL only builds position-independent code for shared builds. It is
  # needed so the static library can be linked into shared objects.
  "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
  # Do not export BoringSSL's symbols from shared objects (see "Symbols" in
  # BoringSSL's INCORPORATING.md).
  "-DCMAKE_C_VISIBILITY_PRESET=hidden"
  "-DCMAKE_CXX_VISIBILITY_PRESET=hidden"
  # Skip BoringSSL's test-only configuration.
  "-DBUILD_TESTING=OFF"
)

# Write the static library ("archive" in CMake terms) to a known location
# instead of relying on each generator's directory layout. The library is
# declared as a byproduct of the build step, so that Ninja knows which step
# creates it.
if (_tink_is_multi_config)
  foreach(_tink_config IN LISTS CMAKE_CONFIGURATION_TYPES)
    string(TOUPPER "${_tink_config}" _tink_config_upper)
    list(APPEND _tink_boringssl_cmake_args
      "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_tink_config_upper}=${_tink_boringssl_lib_dir}/${_tink_config}")
  endforeach()
  set(_tink_boringssl_byproduct
      "${_tink_boringssl_lib_dir}/$<CONFIG>/${_tink_boringssl_lib_name}")
else()
  list(APPEND _tink_boringssl_cmake_args
    "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=${_tink_boringssl_lib_dir}")
  set(_tink_boringssl_byproduct
      "${_tink_boringssl_lib_dir}/${_tink_boringssl_lib_name}")
endif()

# ExternalProject only inherits the generator from this project, but BoringSSL
# must be built with the same toolchain, flags and configuration as Tink. The
# settings that are set here are copied into a script that BoringSSL's
# configure step runs first (`cmake -C <script>`). Raw strings ([==[...]==])
# keep values verbatim, including `;` and generator expressions such as the one
# in CMAKE_MSVC_RUNTIME_LIBRARY, which BoringSSL then evaluates for each
# configuration.
set(_tink_boringssl_copied_settings
  CMAKE_BUILD_TYPE
  CMAKE_CONFIGURATION_TYPES
  CMAKE_MAKE_PROGRAM
  CMAKE_TOOLCHAIN_FILE
  CMAKE_SYSROOT
  # Compilers and binutils.
  CMAKE_C_COMPILER
  CMAKE_CXX_COMPILER
  CMAKE_ASM_COMPILER
  CMAKE_C_COMPILER_LAUNCHER
  CMAKE_CXX_COMPILER_LAUNCHER
  CMAKE_ASM_COMPILER_LAUNCHER
  CMAKE_ADDR2LINE
  CMAKE_AR
  CMAKE_DLLTOOL
  CMAKE_LINKER
  CMAKE_NM
  CMAKE_OBJCOPY
  CMAKE_OBJDUMP
  CMAKE_RANLIB
  CMAKE_READELF
  CMAKE_STRIP
  # Compiler and linker flags.
  CMAKE_C_FLAGS
  CMAKE_CXX_FLAGS
  CMAKE_ASM_FLAGS
  CMAKE_EXE_LINKER_FLAGS
  CMAKE_MODULE_LINKER_FLAGS
  CMAKE_SHARED_LINKER_FLAGS
  CMAKE_STATIC_LINKER_FLAGS
  CMAKE_MSVC_RUNTIME_LIBRARY
  # Target platform.
  CMAKE_OSX_SYSROOT
  CMAKE_OSX_ARCHITECTURES
  CMAKE_OSX_DEPLOYMENT_TARGET
  ANDROID_ABI
  ANDROID_PLATFORM
)
set(_tink_boringssl_init_cache "")
foreach(_tink_var IN LISTS _tink_boringssl_copied_settings)
  # Skip unset settings and tools that were not found (e.g. CMAKE_DLLTOOL on
  # Linux is "CMAKE_DLLTOOL-NOTFOUND").
  if (NOT "${${_tink_var}}" STREQUAL "" AND
      NOT "${${_tink_var}}" MATCHES "-NOTFOUND$")
    string(APPEND _tink_boringssl_init_cache
      "set(${_tink_var} [==[${${_tink_var}}]==] CACHE STRING \"\" FORCE)\n")
  endif()
endforeach()
set(_tink_boringssl_init_cache_file "${_tink_boringssl_dir}/init_cache.cmake")
# Only touch the script when its content changes, so that BoringSSL is
# reconfigured only when a copied setting changes.
file(WRITE "${_tink_boringssl_init_cache_file}.tmp"
  "${_tink_boringssl_init_cache}")
configure_file("${_tink_boringssl_init_cache_file}.tmp"
  "${_tink_boringssl_init_cache_file}" COPYONLY)
list(APPEND _tink_boringssl_cmake_args -C "${_tink_boringssl_init_cache_file}")

# Only build BoringSSL's `crypto` library. With Makefile generators, `$(MAKE)`
# shares the job pool of the parent `make -jN`.
if (CMAKE_GENERATOR MATCHES "Makefiles")
  set(_tink_boringssl_build_command $(MAKE) crypto)
else()
  set(_tink_boringssl_build_command
    ${CMAKE_COMMAND} --build <BINARY_DIR> --target crypto)
  if (_tink_is_multi_config)
    list(APPEND _tink_boringssl_build_command --config $<CONFIG>)
  endif()
endif()

ExternalProject_Add(tink_boringssl_build
  # The sources were downloaded by http_archive above.
  SOURCE_DIR "${tink_boringssl_SOURCE_DIR}"
  PREFIX "${_tink_boringssl_dir}"
  BINARY_DIR "${_tink_boringssl_dir}/build"
  CMAKE_ARGS ${_tink_boringssl_cmake_args}
  BUILD_COMMAND ${_tink_boringssl_build_command}
  BUILD_BYPRODUCTS "${_tink_boringssl_byproduct}"
  # Tink links the library from the build directory; nothing to install.
  INSTALL_COMMAND ""
)
# Rerun BoringSSL's configure step when the copied settings change.
ExternalProject_Add_StepDependencies(tink_boringssl_build configure
  "${_tink_boringssl_init_cache_file}")

# The library built above, as a target Tink can link against.
add_library(tink_internal_boringssl STATIC IMPORTED GLOBAL)
# CMake does not build imported targets: make everything that links this target
# wait for the BoringSSL build.
add_dependencies(tink_internal_boringssl tink_boringssl_build)
if (_tink_is_multi_config)
  # IMPORTED_LOCATION cannot contain $<CONFIG>: set one path per configuration.
  foreach(_tink_config IN LISTS CMAKE_CONFIGURATION_TYPES)
    string(TOUPPER "${_tink_config}" _tink_config_upper)
    set_property(TARGET tink_internal_boringssl PROPERTY
      "IMPORTED_LOCATION_${_tink_config_upper}"
      "${_tink_boringssl_lib_dir}/${_tink_config}/${_tink_boringssl_lib_name}")
  endforeach()
else()
  set_property(TARGET tink_internal_boringssl PROPERTY
    IMPORTED_LOCATION "${_tink_boringssl_lib_dir}/${_tink_boringssl_lib_name}")
endif()

# TODO: b/537605175 - Make BoringSSL a PRIVATE dependency of Tink targets once
# no public Tink header includes OpenSSL headers. Until then, this include
# directory propagates to every target that links Tink, so code that uses
# another OpenSSL may pick up BoringSSL's headers instead.
target_include_directories(tink_internal_boringssl INTERFACE
  "${tink_boringssl_SOURCE_DIR}/include")
# Mirror the link dependencies of BoringSSL's `crypto` target: a static library
# does not carry its own dependencies.
if (WIN32)
  target_link_libraries(tink_internal_boringssl INTERFACE ws2_32)
elseif (NOT CMAKE_SYSTEM_NAME MATCHES "^(Generic|Android)$")
  find_package(Threads REQUIRED)
  target_link_libraries(tink_internal_boringssl INTERFACE Threads::Threads)
endif()

add_library(tink::internal::boringssl ALIAS tink_internal_boringssl)

if (TINK_BUILD_TESTS)
  # Checks that all the symbols of BoringSSL contain BORINGSSL_PREFIX, using
  # BoringSSL's audit tool (requires Go). Not part of the default build; run:
  #   cmake --build <build dir> --target tink_check_boringssl_symbols
  add_custom_target(tink_check_boringssl_symbols
    COMMAND go run util/audit_symbols.go
      -ignore-symbols-with "${BORINGSSL_PREFIX}"
      "$<TARGET_FILE:tink_internal_boringssl>"
    WORKING_DIRECTORY "${tink_boringssl_SOURCE_DIR}"
    USES_TERMINAL
    VERBATIM)
  add_dependencies(tink_check_boringssl_symbols tink_boringssl_build)
endif()
