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

# Builds Tink's private BoringSSL with CMake and checks that none of its global
# symbols is also defined by OpenSSL, so that Tink can be linked into a binary
# that also links OpenSSL.
#
# Only BoringSSL is checked: OpenSSL only defines C symbols, while Tink's own
# code (including its instantiations of BoringSSL templates) only defines
# mangled C++ symbols, which cannot be equal to C symbols.
#
# OpenSSL's static libraries come from the libssl-dev package, which is
# installed if missing (this requires root, as in the CI container).
#
# Extra arguments are passed to CMake (e.g. ccache launchers).
# Usage: do_run_test.sh [cmake args...]

set -euo pipefail
export CCACHE_DIR="$(pwd)/ccache"
export CCACHE_READONLY=1

if ! dpkg -s libssl-dev &> /dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libssl-dev
fi
readonly OPENSSL_LIB_DIR="/usr/lib/x86_64-linux-gnu"

# Same build directory as the cmake_ccache_update job: ccache includes the
# build directory in its cache keys (BoringSSL compiles with debug info), so a
# different path would miss every cached object.
readonly BUILD_DIR="out"
rm -rf "${BUILD_DIR}"
cmake -S . -B "${BUILD_DIR}" "$@"
cmake --build "${BUILD_DIR}" --parallel "$(nproc)" --target tink_boringssl_build

# Prints the sorted global symbols defined by the given static libraries. In
# nm's POSIX format, symbol lines are "<name> <type> ..."; the lines that name
# archive members ("lib.a[member.o]:") have a single field. nm fails if a
# library does not exist.
defined_global_symbols() {
  nm -P -g --defined-only "$@" | awk 'NF >= 2 { print $1 }' | sort -u
}

# See cmake/TinkBoringSSL.cmake for the location of Tink's BoringSSL. The
# build directory is new, so the pattern matches only the current version.
WORK_DIR="$(mktemp -dt tink-symbols.XXXXXX)"
readonly WORK_DIR
defined_global_symbols "${BUILD_DIR}"/tink_boringssl-*/lib/libcrypto.a \
  > "${WORK_DIR}/boringssl_symbols.txt"
defined_global_symbols "${OPENSSL_LIB_DIR}/libcrypto.a" \
  "${OPENSSL_LIB_DIR}/libssl.a" > "${WORK_DIR}/openssl_symbols.txt"

comm -12 "${WORK_DIR}/boringssl_symbols.txt" "${WORK_DIR}/openssl_symbols.txt" \
  > "${WORK_DIR}/collisions.txt"
if [[ -s "${WORK_DIR}/collisions.txt" ]]; then
  echo "ERROR: Symbols defined by both Tink's BoringSSL and OpenSSL:"
  cat "${WORK_DIR}/collisions.txt"
  exit 1
fi
echo "No symbol collision between Tink's BoringSSL and OpenSSL."
