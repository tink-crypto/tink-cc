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
#     sh ./kokoro/gcp_ubuntu/cmake_ccache_update/run.sh
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
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

readonly CONFIG_CACHE_DIR="config_cache"
readonly CONFIG_CACHE_TAR="config_cache.tgz"
readonly CCACHE_TAR="ccache.tgz"

# Output folder for ccache.
mkdir -p ccache
# Output folder for caching the CMake config.
mkdir -p "${CONFIG_CACHE_DIR}"

readonly CMAKE_OPTS=(
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
  -DCMAKE_CXX_STANDARD=14
  -DCMAKE_CXX_STANDARD_REQUIRED=ON
)

cat <<EOF > _run.sh
#!/bin/bash
set -euo pipefail

# TODO: b/369963540 - Remove this once the Docker image is updated.
apt install ccache

export CCACHE_DIR=ccache

set -x
rm -rf out && mkdir -p out
cmake -S . -B out ${CMAKE_OPTS[@]}
# Create the config cache.
tar -C . -czf "${CONFIG_CACHE_DIR}/${CONFIG_CACHE_TAR}" out

# Build and create the ccache TAR.
cmake --build out --parallel "$(nproc)"
tar -C . -czf "${CCACHE_TAR}" ccache
EOF

chmod +x _run.sh

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_run.sh

if [[ "${IS_KOKORO}" == "true" ]]; then
  readonly REMOTE_CACHE_URL="gs://${TINK_REMOTE_CACHE_GCS_BUCKET}/cmake/${TINK_CC_CMAKE_IMAGE_HASH}"

  # Activate the service account for the remote cache.
  gcloud auth activate-service-account \
    --key-file="${TINK_REMOTE_CACHE_SERVICE_KEY}"
  gcloud config set project tink-test-infrastructure

  gsutil cp "${CCACHE_TAR}" "${REMOTE_CACHE_URL}/ccache/${CCACHE_TAR}"
  gsutil cp "${CONFIG_CACHE_DIR}/${CONFIG_CACHE_TAR}" \
    "${REMOTE_CACHE_URL}/${CONFIG_CACHE_DIR}/${CONFIG_CACHE_TAR}"
fi
