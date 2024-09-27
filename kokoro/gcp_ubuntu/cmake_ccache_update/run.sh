#!/bin/bash
# Copyright 2024 Google LLC
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

# Builds tink-cc with CMake and uploads the ccache to GCS.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-cmake:latest" \
#     sh ./kokoro/gcp_ubuntu/cmake_ccache_update/run_tests.sh
#
set -euo pipefail

IS_KOKORO="true"
if [[ -z "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  readonly IS_KOKORO="false"
fi
readonly IS_KOKORO

RUN_COMMAND_ARGS=()
if [[ "${IS_KOKORO}" == "true" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
  source kokoro/testutils/cc_test_container_images.sh
  CONTAINER_IMAGE="${TINK_CC_CMAKE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )

  # Activate the service account for the remote cache.
  gcloud auth activate-service-account \
    --key-file="${TINK_REMOTE_CACHE_SERVICE_KEY}"
  gcloud config set project tink-test-infrastructure
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

readonly CONFIG_CACHE_DIR=config_cache

# Output folder for ccache.
mkdir -p ccache
# Output folder for caching the CMake config.
mkdir -p "${CONFIG_CACHE_DIR}"

cat <<EOF > _run.sh
#!/bin/bash
set -euo pipefail

export CCACHE_DIR="$(pwd)/ccache"

readonly CMAKE_OPS=(
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
  -DCMAKE_CXX_STANDARD=14
  -DCMAKE_CXX_STANDARD_REQUIRED=ON
)

set -x
mkdir -p out
cmake -S . -B out "${CMAKE_OPS[@]}"

# Create the config cache.
tar -C . -czf "$(pwd)/${CONFIG_CACHE_DIR}/config_cache.tgz" out
cmake --build out --parallel "$(nproc)"
tar -C . -czf "$(pwd)/ccache.tgz" ccache
EOF

chmod +x _run.sh

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_run.sh

if [[ "${IS_KOKORO}" == "true" ]]; then
  readonly REMOTE_CACHE_URL="https://storage.googleapis.com/${TINK_REMOTE_CACHE_GCS_BUCKET}/cmake/${TINK_CC_BASE_IMAGE_HASH}"

  gsutil cp ccache.tgz "${REMOTE_CACHE_URL}/ccache/ccache.tgz"
  gsutil cp "${CONFIG_CACHE_DIR}/cache.tgz" "${REMOTE_CACHE_URL}/config_cache/config_cache.tgz"
fi
