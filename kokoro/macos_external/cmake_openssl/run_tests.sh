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
echo "Tink Script ID: 98fe051eb8c78e2cc0ff (to quickly find the script from logs)"
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

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
fi

# Install cmake if not available
if ! command -v cmake &> /dev/null; then
  brew install cmake
fi

# Sourcing is needed to update the caller environment.
source ./kokoro/testutils/install_openssl.sh
./kokoro/testutils/run_cmake_tests.sh . -DTINK_USE_SYSTEM_OPENSSL=ON
./kokoro/testutils/run_cmake_tests.sh "examples" -DTINK_BUILD_TESTS=OFF \
  -DTINK_USE_SYSTEM_OPENSSL=ON
