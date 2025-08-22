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
echo "Tink Script ID: 41fa20f4161078ed5a2f (to quickly find the script from logs)"
echo "==========================================================================="

set -euo pipefail

# If we are running on Kokoro cd into the repository.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
fi

CACHE_FLAGS=""
if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  CACHE_FLAGS="-c ${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/macos"
fi
readonly CACHE_FLAGS

echo "=========================================================== BUILDING MAIN"
bazelisk

./kokoro/testutils/run_bazel_tests.sh ${CACHE_FLAGS} .
./kokoro/testutils/run_bazel_tests.sh ${CACHE_FLAGS} "examples"
