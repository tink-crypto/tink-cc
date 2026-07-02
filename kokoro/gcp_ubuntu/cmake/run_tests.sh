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

# Generated with openssl rand -hex 10
echo "==========================================================================="
echo "Tink Script ID: bfe3f9f9300bd78170dd (to quickly find the script from logs)"
echo "==========================================================================="

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
  RUN_COMMAND_ARGS+=( -m "type=bind,src=/tmp,dst=/tmp" )
fi

EXTRA_CMAKE_ARGS=()

# CMake output directory.
mkdir -p out

if [[ "${IS_KOKORO}" == "true" ]]; then
  source kokoro/testutils/ccache_enable.sh "${TINK_CC_CMAKE_IMAGE_HASH}"

  # Try to use the config cache only if the remote cache was successfully enabled.
  if [[ -n "${REMOTE_CACHE_URL:-}" ]]; then
    if gcloud storage objects list --stat --fetch-encrypted-object-hashes "${REMOTE_CACHE_URL}/config_cache/config_cache.tgz" &> /dev/null; then
      echo "Using config cache: ${REMOTE_CACHE_URL}/config_cache/config_cache.tgz"
      gcloud storage cat "${REMOTE_CACHE_URL}/config_cache/config_cache.tgz" \
        | tar -C out -xzf - --strip-components=1
    fi
  fi
fi
readonly EXTRA_CMAKE_ARGS

# Construct the command to be executed inside the Docker container (or on the host).
# This command:
# 1. Sets up the ccache environment variables.
# 2. Runs the main Tink C++ CMake tests.
# 3. Runs the examples CMake tests.
# Both test suites are run in the same container instance to preserve the ccache
# environment and avoid the overhead of starting a second container.
cat << EOF > /tmp/do_run_test.sh
set -euo pipefail
export CCACHE_DIR="\$(pwd)/ccache"
export CCACHE_READONLY=1
set -x
if [[ -d out ]]; then
  ./kokoro/testutils/run_cmake_tests.sh -o out . -DTINK_USE_INSTALLED_BENCHMARK=ON ${EXTRA_CMAKE_ARGS[@]@Q}
else
  ./kokoro/testutils/run_cmake_tests.sh . -DTINK_USE_INSTALLED_BENCHMARK=ON ${EXTRA_CMAKE_ARGS[@]@Q}
fi
./kokoro/testutils/run_cmake_tests.sh examples -DTINK_USE_INSTALLED_BENCHMARK=ON
EOF

readonly RUN_COMMAND_ARGS
if [[ -z "${CONTAINER_IMAGE:-}" ]]; then
  echo "Running command on the host"
  time bash /tmp/do_run_test.sh
else
  ./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
    bash /tmp/do_run_test.sh
fi

