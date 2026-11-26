#!/bin/bash
# Copyright 2022 Google LLC
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

# Generated with openssl rand -hex 10
echo "==========================================================================="
echo "Tink Script ID: 19d6a7ea6aab67aa26fc (to quickly find the script from logs)"
echo "==========================================================================="

set -euo pipefail

# Disable Homebrew auto-updates and cleanup to speed up builds and avoid
# pulling rolling HEAD package changes on Kokoro VMs.
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_INSTALL_CLEANUP=1
# Enable retry-all-errors for curl in Homebrew so that connection resets
# and timeouts to ghcr.io are retried alongside HTTP errors.
export HOMEBREW_CURLRC="${HOME}/.homebrew_curlrc"
echo "retry-all-errors" > "${HOMEBREW_CURLRC}"

DEPS_PREFIX="$(mktemp -dt tink-cmake-deps.XXXXXX)"
DEPS_PREFIX="$(cd "${DEPS_PREFIX}" && pwd -P)"
readonly DEPS_PREFIX
TINK_SRC_DIR=""
cleanup() {
  rm -rf "${DEPS_PREFIX}"
  if [[ -n "${TINK_SRC_DIR}" ]]; then
    # Kokoro rsyncs all created/modified files under KOKORO_ARTIFACTS_DIR back
    # off the VM when the job ends; delete build and cache directories on exit so
    # multi-GB build outputs are not transferred back.
    rm -rf "${TINK_SRC_DIR}/ccache" \
      "${TINK_SRC_DIR}/out" \
      "${TINK_SRC_DIR}/out_install" \
      "${TINK_SRC_DIR}/out_examples"
  fi
}
trap cleanup EXIT

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
  TINK_SRC_DIR="$(pwd)"
  readonly TINK_SRC_DIR
fi

# Install cmake if not available
if ! command -v cmake &> /dev/null; then
  brew install cmake
fi

# Install ccache if not available
if ! command -v ccache &> /dev/null; then
  brew install ccache
fi

export CCACHE_DIR="$(pwd)/ccache"
mkdir -p "${CCACHE_DIR}"
EXTRA_CMAKE_ARGS=(
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
  -DCMAKE_C_COMPILER_LAUNCHER=ccache
  -DCMAKE_ASM_COMPILER_LAUNCHER=ccache
  -DCMAKE_PREFIX_PATH="${DEPS_PREFIX}"
  -DCMAKE_INSTALL_RPATH="${DEPS_PREFIX}/lib"
  -DBUILD_SHARED_LIBS=ON
  -DTINK_USE_INSTALLED_ABSEIL=ON
  -DTINK_USE_INSTALLED_GOOGLETEST=ON
  -DTINK_USE_INSTALLED_PROTOBUF=ON
)

rm -rf out_install
mkdir -p out out_install out_examples
./kokoro/testutils/install_cmake_deps.sh "${DEPS_PREFIX}"
./kokoro/testutils/run_cmake_tests.sh -o out . -DCMAKE_INSTALL_PREFIX="$(pwd)/out_install" "${EXTRA_CMAKE_ARGS[@]}"
./kokoro/testutils/run_cmake_install_tests.sh out out_install "${DEPS_PREFIX}"
./kokoro/testutils/run_cmake_tests.sh -o out_examples "examples" -DTINK_BUILD_TESTS=OFF "${EXTRA_CMAKE_ARGS[@]}"
