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
echo "Tink Script ID: 687fd47fd304409b05b2 (to quickly find the script from logs)"
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
  readonly TINK_SRC_DIR="$(pwd)"
  cleanup() {
    # Files created inside the Docker container are owned by root.
    sudo rm -rf "${TINK_SRC_DIR}/ccache" \
      "${TINK_SRC_DIR}/out" \
      "${TINK_SRC_DIR}/out_install" \
      "${TINK_SRC_DIR}/out_examples"
  }
  # Kokoro rsyncs all created/modified files under KOKORO_ARTIFACTS_DIR back
  # off the VM when the job ends; delete build and cache directories on exit so
  # multi-GB build outputs are not transferred back.
  trap cleanup EXIT
  source kokoro/testutils/cc_test_container_images.sh
  CONTAINER_IMAGE="${TINK_CC_CMAKE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
  RUN_COMMAND_ARGS+=( -m "type=bind,src=/tmp,dst=/tmp" )
fi

# CMake output directory.
mkdir -p out

EXTRA_CMAKE_ARGS=(
  -DBUILD_SHARED_LIBS=ON
)
if [[ "${IS_KOKORO}" == "true" ]]; then
  source kokoro/testutils/ccache_enable.sh "${TINK_CC_CMAKE_IMAGE_HASH}"
fi
readonly EXTRA_CMAKE_ARGS

# Construct the command to be executed inside the Docker container (or on the host).
# This command:
# 1. Sets up the ccache environment variables.
# 2. Compiles and installs GoogleTest, Abseil, and Protobuf into /usr/local.
# 3. Runs the main Tink C++ CMake tests and verifies installation.
# 4. Runs the examples CMake tests against the installed Tink.
# Both test suites are run in the same container instance to preserve the ccache
# environment and installed dependencies, avoiding the overhead of starting a
# second container.
cat << EOF > /tmp/do_run_test.sh
set -euo pipefail
export CCACHE_DIR="\$(pwd)/ccache"
export CCACHE_NOREADONLY=true
set -x
if ! command -v pkg-config &> /dev/null; then
  if [[ "\$(id -u)" -ne 0 ]]; then
    echo "ERROR: pkg-config is required. Install pkg-config or set CONTAINER_IMAGE." >&2
    exit 1
  fi
  # TODO(b/570488948): Remove once TINK_CC_CMAKE_IMAGE_HASH is updated to an
  # image containing pkg-config.
  apt-get update -o Acquire::Retries=3
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    -o Acquire::Retries=3 pkg-config
fi
./kokoro/testutils/install_cmake_deps.sh /usr/local

rm -rf out out_install out_examples
mkdir -p out out_install out_examples

TINK_EXTRA_CMAKE_ARGS=(
  ${EXTRA_CMAKE_ARGS[@]@Q}
  -DCMAKE_INSTALL_PREFIX="\$(pwd)/out_install"
  -DTINK_USE_INSTALLED_ABSEIL=ON
  -DTINK_USE_INSTALLED_BENCHMARK=ON
  -DTINK_USE_INSTALLED_GOOGLETEST=ON
  -DTINK_USE_INSTALLED_PROTOBUF=ON
)
./kokoro/testutils/run_cmake_tests.sh -o out . "\${TINK_EXTRA_CMAKE_ARGS[@]}"

./kokoro/testutils/run_cmake_install_tests.sh out out_install /usr/local

# Compile examples out-of-tree to ensure it has no access to Tink's sources.
EXAMPLES_TMP_DIR="\$(mktemp -dt tink-examples.XXXXXX)"
trap 'rm -rf "\${EXAMPLES_TMP_DIR}"' EXIT
cp -R examples "\${EXAMPLES_TMP_DIR}/examples"
EXAMPLES_EXTRA_CMAKE_ARGS=(
  ${EXTRA_CMAKE_ARGS[@]@Q}
  -DCMAKE_PREFIX_PATH="\$(pwd)/out_install"
  -DTINK_USE_INSTALLED_TINK=ON
)
./kokoro/testutils/run_cmake_tests.sh -o out_examples "\${EXAMPLES_TMP_DIR}/examples" "\${EXAMPLES_EXTRA_CMAKE_ARGS[@]}"
EOF

readonly RUN_COMMAND_ARGS
if [[ -z "${CONTAINER_IMAGE:-}" ]]; then
  echo "Running command on the host"
  time bash /tmp/do_run_test.sh
else
  ./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
    bash /tmp/do_run_test.sh
fi

