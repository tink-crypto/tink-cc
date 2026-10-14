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
# symbols is also defined by OpenSSL's static libraries.
#
# On Kokoro, the check runs in the Tink C++ CMake container image, in which
# do_run_test.sh installs OpenSSL (libssl-dev). Locally, set CONTAINER_IMAGE to
# run in a container, or leave it unset to run on the host (libssl-dev must
# then be installed).

# Generated with openssl rand -hex 10
echo "==========================================================================="
echo "Tink Script ID: ca6cbbb851173ceb4b89 (to quickly find the script from logs)"
echo "==========================================================================="

set -euo pipefail

IS_KOKORO="true"
if [[ -z "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  IS_KOKORO="false"
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
readonly CONTAINER_IMAGE="${CONTAINER_IMAGE:-}"

if [[ -n "${CONTAINER_IMAGE}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi
readonly RUN_COMMAND_ARGS

EXTRA_CMAKE_ARGS=()
if [[ "${IS_KOKORO}" == "true" ]]; then
  # Reuses the (read-only) ccache populated by the cmake_ccache_update job.
  source kokoro/testutils/ccache_enable.sh "${TINK_CC_CMAKE_IMAGE_HASH}"
fi
readonly EXTRA_CMAKE_ARGS

if [[ -z "${CONTAINER_IMAGE}" ]]; then
  echo "Running command on the host"
  time bash ./kokoro/gcp_ubuntu/cmake_check_symbols_collision/do_run_test.sh \
    "${EXTRA_CMAKE_ARGS[@]}"
else
  ./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
    bash ./kokoro/gcp_ubuntu/cmake_check_symbols_collision/do_run_test.sh \
    "${EXTRA_CMAKE_ARGS[@]}"
fi
