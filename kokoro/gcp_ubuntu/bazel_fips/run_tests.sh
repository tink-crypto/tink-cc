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
echo "Tink Script ID: 73c0ab1d9e2aa29cc120 (to quickly find the script from logs)"
echo "==========================================================================="

set -eEuo pipefail

# By default when run locally this script runs the command below directly on the
# host. The CONTAINER_IMAGE variable can be set to run on a custom container
# image for local testing. E.g.:
#
# CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-cmake:latest" \
#  sh ./kokoro/gcp_ubuntu/bazel_fips/run_tests.sh
#
RUN_COMMAND_ARGS=()
CONTAINER_IMAGE=
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
  source kokoro/testutils/cc_test_container_images.sh
  CONTAINER_IMAGE="${TINK_CC_CMAKE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi
readonly RUN_COMMAND_ARGS

CACHE_FLAGS=()
if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  CACHE_FLAGS+=(
    "--remote_cache=https://storage.googleapis.com/${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_CC_BASE_IMAGE_HASH}"
    "--google_credentials=cache_key"
  )
fi
readonly CACHE_FLAGS

cat <<EOF > _do_run_test.sh
set -euo pipefail

bazelisk build ${CACHE_FLAGS[@]} \
  --//tink/config:use_only_fips=True \
  --build_tag_filters=fips,-requires_boringcrypto_update \
  --override_module=boringssl=third_party/boringssl_fips -- ...

bazelisk test ${CACHE_FLAGS[@]} \
  --//tink/config:use_only_fips=True \
  --build_tag_filters=fips,-requires_boringcrypto_update \
  --build_tests_only \
  --test_output=errors \
  --override_module=boringssl=third_party/boringssl_fips \
  --test_tag_filters=fips,-requires_boringcrypto_update -- ...
EOF
chmod +x _do_run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh
}

./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh
