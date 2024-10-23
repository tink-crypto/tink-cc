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

# Builds and tests tink-cc and its examples using CMake.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-cmake:latest" \
#     sh ./kokoro/gcp_ubuntu/cmake/run_tests.sh
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

EXTRA_CMAKE_ARGS=()

# CMake output directory.
mkdir -p out

if [[ "${IS_KOKORO}" == "true" ]]; then
  readonly REMOTE_CACHE_URL="gs://${TINK_REMOTE_CACHE_GCS_BUCKET}/cmake/${TINK_CC_CMAKE_IMAGE_HASH}"

  set -x
  # Activate the service account for the remote cache.
  gcloud auth activate-service-account \
    --key-file="${TINK_REMOTE_CACHE_SERVICE_KEY}"
  gcloud config set project tink-test-infrastructure

  # Try to use the config cache.
  if gsutil stat "${REMOTE_CACHE_URL}/config_cache/config_cache.tgz"; then
    echo "Using config cache: ${REMOTE_CACHE_URL}/config_cache/config_cache.tgz"
    gsutil cat "${REMOTE_CACHE_URL}/config_cache/config_cache.tgz" \
      | tar -C out -xzf - --strip-components=1
  fi

  # Try to use the ccache.
  if gsutil stat "${REMOTE_CACHE_URL}/ccache/ccache.tgz"; then
    echo "Using ccache: ${REMOTE_CACHE_URL}/ccache/ccache.tgz"
    mkdir -p ccache
    gsutil cat "${REMOTE_CACHE_URL}/ccache/ccache.tgz" \
      | tar -C ccache -xzf - --strip-components=1
    # Tell CMake to use CCache.
    EXTRA_CMAKE_ARGS+=( -DCMAKE_CXX_COMPILER_LAUNCHER=ccache )
  fi
  set +x
fi
readonly EXTRA_CMAKE_ARGS

cat <<EOF > _build_and_test_tink.sh
#!/bin/bash
set -euo pipefail

# TODO: b/369963540 - Remove this once the Docker image is updated.
apt install ccache

set -x

export CCACHE_DIR="\$(pwd)/ccache"
export CCACHE_READONLY=1

if [[ -d out ]]; then
  ./kokoro/testutils/run_cmake_tests.sh -o out . ${EXTRA_CMAKE_ARGS[@]}
else
  ./kokoro/testutils/run_cmake_tests.sh . ${EXTRA_CMAKE_ARGS[@]}
fi
EOF

chmod +x _build_and_test_tink.sh

readonly RUN_COMMAND_ARGS
./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
  ./_build_and_test_tink.sh

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
  ./kokoro/testutils/run_cmake_tests.sh "examples"
