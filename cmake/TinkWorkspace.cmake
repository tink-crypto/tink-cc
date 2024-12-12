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

# Download, unpack and setup Tink dependencies.
#
# Despite the looks, http_archive rules are not purely declarative, and order
# matters. All variables defined before a rule are visible when configuring the
# dependency it declares, and the targets provided by a dependency are visible
# (only) after it has been declared. Following dependencies may rely on targets
# defined by a previous one, for instance on gtest or absl.
#
# Some rules imported from dependencies require small fixes, which are specified
# after the relative http_archive rule. Please always document the intended
# purpose of such statements, and why they are necessary.
#
# In general, when adding a new dependency you should follow this structure:
#
# <set any configuration variable, if any>
# <http_archive for your dependency>
# <define or fix newly imported targets, if any>
#
# Many projects provide switches to disable tests or examples, which you should
# specify, in order to speed up the compilation process.

include(HttpArchive)
include(TinkUtil)

# Creates an interface target from an imported one.
#
# Parameters:
#   INTERFACE_TARGET Name of the interface target.
#   IMPORTED_TARGET Name of the imported target (e.g., with find_package).
#
macro(_create_interface_target INTERFACE_TARGET IMPORTED_TARGET)
  add_library(${INTERFACE_TARGET} INTERFACE)
  target_link_libraries(${INTERFACE_TARGET} INTERFACE ${IMPORTED_TARGET})
  target_include_directories(${INTERFACE_TARGET} INTERFACE ${IMPORTED_TARGET})
endmacro()

set(gtest_force_shared_crt ON CACHE BOOL "Tink dependency override" FORCE)

if (TINK_BUILD_TESTS)
  if (TINK_USE_INSTALLED_GOOGLETEST)
    # This uses the CMake's FindGTest module; if successful, this call to
    # find_package generates the targets GTest::gmock, GTest::gtest and
    # GTest::gtest_main.
    find_package(GTest CONFIG REQUIRED)
    _create_interface_target(gmock GTest::gmock)
    _create_interface_target(gtest_main GTest::gtest_main)
  else()
    http_archive(
      NAME googletest
      URL https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz
      SHA256 7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
    )
  endif()

  http_archive(
    NAME wycheproof
    URL https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip
    SHA256 eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545
    DATA_ONLY
  )
  # Symlink the Wycheproof test data.
  # Tests expect Wycheproof test vectors to be in a local testvectors/ folder.
  add_directory_alias("${wycheproof_SOURCE_DIR}/testvectors"
    "${CMAKE_BINARY_DIR}/testvectors")
endif()

if (NOT TINK_USE_INSTALLED_ABSEIL)
  # Release from 2024-01-22.
  http_archive(
    NAME abseil
    URL https://github.com/abseil/abseil-cpp/releases/download/20240722.0/abseil-cpp-20240722.0.tar.gz
    SHA256 f50e5ac311a81382da7fa75b97310e4b9006474f9560ac46f54a9967f07d4ae3
  )
else()
  # This is everything that needs to be done here. Abseil already defines its
  # targets, which gets linked in tink_cc_(library|test).
  find_package(absl REQUIRED)
endif()

# Don't fetch BoringSSL or look for OpenSSL if target `crypto` is already
# defined.
if (NOT TARGET crypto)
  if (NOT TINK_USE_SYSTEM_OPENSSL)
    # Release from 2024-10-03.
    http_archive(
      NAME boringssl
      URL https://github.com/google/boringssl/releases/download/0.20240930.0/boringssl-0.20240930.0.tar.gz
      SHA256 812f77dd57fef845c4ed630430f1f8efc7e255c4d572fa58b71e6e3ce1692a4a
    )
    # BoringSSL targets do not carry include directory info, this fixes it.
    target_include_directories(crypto PUBLIC
      "$<BUILD_INTERFACE:${boringssl_SOURCE_DIR}/src/include>")
  else()
    # Support for ED25519 was added from 1.1.1.
    find_package(OpenSSL 1.1.1 REQUIRED)
    _create_interface_target(crypto OpenSSL::Crypto)
  endif()
else()
  message(STATUS "Using an already declared `crypto` target")
  get_target_property(crypto_INCLUDE_DIR crypto INTERFACE_INCLUDE_DIRECTORIES)
  message(STATUS "crypto Include Dir: ${crypto_INCLUDE_DIR}")
endif()

if (NOT TINK_USE_INSTALLED_PROTOBUF)
  set(protobuf_BUILD_TESTS OFF CACHE BOOL "Tink dependency override" FORCE)
  set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "Tink dependency override" FORCE)
  set(protobuf_INSTALL OFF CACHE BOOL "Tink dependency override" FORCE)

  http_archive(
    NAME com_google_protobuf
    URL https://github.com/protocolbuffers/protobuf/releases/download/v27.4/protobuf-27.4.tar.gz
    SHA256 023e2bb164b234af644c5049c6dac1d9c9f6dd2acb133b960d9009105b4226bd
  )
else()
  find_package(Protobuf REQUIRED CONFIG)
  include_directories(${Protobuf_INCLUDE_DIRS})
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
endif()
