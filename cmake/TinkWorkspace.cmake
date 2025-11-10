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
      URL https://github.com/google/googletest/releases/download/v1.16.0/googletest-1.16.0.tar.gz
      SHA256 78c676fc63881529bf97bf9d45948d905a66833fbfa5318ea2cd7478cb98f399
    )
  endif()

  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Tink dependency override" FORCE)

  http_archive(
      NAME benchmark
      URL https://github.com/google/benchmark/archive/refs/tags/v1.9.1.tar.gz
      SHA256 32131c08ee31eeff2c8968d7e874f3cb648034377dfc32a4c377fa8796d84981
    )

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
  http_archive(
    NAME abseil
    URL https://github.com/abseil/abseil-cpp/releases/download/20250814.1/abseil-cpp-20250814.1.tar.gz
    SHA256 1692f77d1739bacf3f94337188b78583cf09bab7e420d2dc6c5605a4f86785a1
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
      URL https://github.com/google/boringssl/releases/download/0.20251002.0/boringssl-0.20251002.0.tar.gz
      SHA256 f96733fc3df03d4195db656d1b7b8c174c33f95d052f811f0ecc8f4e4e3db332
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
    NAME protobuf
    URL https://github.com/protocolbuffers/protobuf/releases/download/v30.2/protobuf-30.2.zip
    SHA256 6544e5ceec7f29d00397193360435ca8b3c4e843de3cf5698a99d36b72d65342
  )
else()
  find_package(Protobuf REQUIRED CONFIG)
  include_directories(${Protobuf_INCLUDE_DIRS})
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
endif()
