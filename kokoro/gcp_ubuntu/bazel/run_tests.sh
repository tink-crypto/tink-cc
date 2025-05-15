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

# Builds and tests tink-cc and its examples using Bazel.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-base:latest" \
#     sh ./kokoro/gcp_ubuntu/bazel/run_tests.sh
#
set -euo pipefail

RUN_COMMAND_ARGS=()
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
  source kokoro/testutils/cc_test_container_images.sh
  CONTAINER_IMAGE="${TINK_CC_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

CACHE_FLAGS=()
if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  CACHE_FLAGS+=(
    -c "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_CC_BASE_IMAGE_HASH}"
  )
fi
readonly CACHE_FLAGS

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
  ./kokoro/testutils/run_bazel_tests.sh "${CACHE_FLAGS[@]}" .

./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
  ./kokoro/testutils/run_bazel_tests.sh "${CACHE_FLAGS[@]}" examples

