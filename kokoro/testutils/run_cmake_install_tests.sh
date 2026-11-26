#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# This script installs a built CMake project into its configured
# CMAKE_INSTALL_PREFIX and runs verification tests on the installed headers,
# libraries, and linkage.

# Generated with openssl rand -hex 10
echo "================================================================================"
echo "Tink Script ID: b3e10c66ad05672b362a (to quickly find the script from logs)"
echo "================================================================================"

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <build directory> <install prefix>"
  exit 1
fi
CMAKE_BUILD_DIR=$(cd "$1" && pwd)
CMAKE_INSTALL_PREFIX=$(cd "$2" && pwd)

test_headers() {
  local header
  while read header; do
    echo "Testing header: ${header}"
    local include=${header#*/tink-*/}
    local prefix=${header%${include}}
    local macros
    macros=$(
      c++ \
        -E -dM \
        -I "${prefix}" \
        -x c++ -std=c++17 "${header}"
    )
    case "${macros}" in
      '')
        echo "Preprocessing ${header} failed."
        return 1
        ;;
      *OPENSSL*)
        echo "${header} depends on OpenSSL."
        return 1
        ;;
    esac
  done
}

test_libraries() {
  local ldpath="$1"
  local library
  while read library; do
    echo "Testing library: ${library}"
    case "${library}" in
      *.so)
        local deps
        deps=$(
          LD_LIBRARY_PATH="${ldpath}" ldd "${library}"
        )
        if echo "${deps}" | grep 'not found'; then
          return 1
        fi
        ;;
      *)
        echo "Don't know how to test ${library}"
        ;;
    esac
  done
}

test_installation() {
  cd "${CMAKE_INSTALL_PREFIX}"

  local ldpath="${CMAKE_INSTALL_PREFIX}/lib64:${CMAKE_INSTALL_PREFIX}/lib"

  echo "=== List of installed files: ==="
  find . -ls
  echo

  echo "=== Testing headers: ==="
  find "${CMAKE_INSTALL_PREFIX}/include"/tink-* \
    -name '*.h' -not -path '*/internal/*' |\
    test_headers
  echo

  echo "=== Testing libraries: ==="
  find "${CMAKE_INSTALL_PREFIX}"/lib* -name '*.so' |\
    test_libraries "${ldpath}"
  echo

  echo "=== Testing compilation of a simple program: ==="
  local -r testdir="${CMAKE_BUILD_DIR}/comptest"
  mkdir -p "${testdir}"
  cat <<'EOF' >"${testdir}/comptest.cc"
#include <iostream>
#include "tink/big_integer.h"
#include "tink/util/test_util.h"
int main() {
  // Utilize some random Tink public APIs that are unlikely to change and
  // exercise both main-Tink and Tink-BoringSSL link boundaries.
  crypto::tink::BigInteger a("\x01\x02");
  crypto::tink::BigInteger b("\x01\x02");
  crypto::tink::BigInteger c("\x01\x03");
  if (a != b) {
    std::cerr << "ERROR: a != b" << std::endl;
    return 1;
  }
  if (a == c) {
    std::cerr << "ERROR: a == c" << std::endl;
    return 1;
  }
  std::string hex_a = crypto::tink::test::HexEncode("a");
  if (hex_a != "61") {
    std::cerr << "ERROR: HexEncode(\"a\") got " << hex_a
              << ", want \"61\"" << std::endl;
    return 1;
  }
  std::cerr << "OK" << std::endl;
  return 0;
}
EOF
  # TODO(b/570488948): Migrate from hardcoding to pkg-config to discover Tink.
  set -- "${CMAKE_INSTALL_PREFIX}"/include/tink-*
  tink_major_version=${1##*-}
  c++ \
    -I "$1" \
    -o "${testdir}/comptest" \
    -std=c++17 "${testdir}/comptest.cc" \
    -L "${CMAKE_INSTALL_PREFIX}/lib64" \
    -L "${CMAKE_INSTALL_PREFIX}/lib" \
    -ltink"${tink_major_version}"_testonly \
    -ltink"${tink_major_version}"
  env \
    LD_LIBRARY_PATH="${ldpath}" \
    LD_DEBUG=libs \
    "${testdir}/comptest"
  echo
}

cmake --install "${CMAKE_BUILD_DIR}"
test_installation "${CMAKE_INSTALL_PREFIX}"
