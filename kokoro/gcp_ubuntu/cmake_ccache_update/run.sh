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

# Function to build Tink and update the ccache for a given container image.
build_and_upload_ccache() {
  local -r container_image="$1"
  local -r image_hash="$2"
  shift 2
  local -a cmake_opts=("$@")

  echo "==========================================================================="
  echo "Updating ccache for image: ${container_image}"
  echo "Image hash: ${image_hash}"
  echo "==========================================================================="

  local -r config_cache_dir="config_cache"
  local -r config_cache_tar="config_cache.tgz"
  local -r ccache_tar="ccache.tgz"

  # Clean up and recreate directories.
  rm -rf ccache config_cache out
  mkdir -p ccache
  mkdir -p config_cache

  # Construct the command to build Tink and update the ccache.
  cat << EOF > /tmp/do_run_test.sh
set -euo pipefail
export CCACHE_DIR="\$(pwd)/ccache"
set -x
rm -rf out
mkdir -p out
cmake -S . -B out ${cmake_opts[@]@Q}
tar -C . -czf config_cache/config_cache.tgz out
cmake --build out --parallel \$(nproc)
tar -C . -czf ccache.tgz ccache
EOF

  local run_command_args=()
  if [[ "${IS_KOKORO}" == "true" ]]; then
    run_command_args+=( -k "${TINK_GCR_SERVICE_KEY}" )
  fi
  if [[ -n "${container_image}" ]]; then
    run_command_args+=( -c "${container_image}" )
    run_command_args+=( -m "type=bind,src=/tmp,dst=/tmp" )
  fi

  if [[ -z "${container_image}" ]]; then
    echo "Running command on the host"
    time bash /tmp/do_run_test.sh
  else
    ./kokoro/testutils/docker_execute.sh "${run_command_args[@]}" \
      bash /tmp/do_run_test.sh
  fi

  if [[ "${IS_KOKORO}" == "true" ]]; then
    local -r remote_cache_url="gs://${TINK_REMOTE_CACHE_GCS_BUCKET}/cmake/${image_hash}"

    # Activate the service account for the remote cache.
    gcloud auth activate-service-account \
      --key-file="${TINK_REMOTE_CACHE_SERVICE_KEY}"
    gcloud config set project tink-test-infrastructure

    gcloud storage cp "${ccache_tar}" "${remote_cache_url}/ccache/${ccache_tar}"
    gcloud storage cp "${config_cache_dir}/${config_cache_tar}" \
      "${remote_cache_url}/${config_cache_dir}/${config_cache_tar}"
  fi
}

if [[ "${IS_KOKORO}" == "true" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
  source kokoro/testutils/cc_test_container_images.sh

  # 1. Update ccache for standard CMake image.
  CMAKE_OPTS_STANDARD=(
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
    -DCMAKE_CXX_STANDARD=17
    -DCMAKE_CXX_STANDARD_REQUIRED=ON
    -DTINK_BUILD_TESTS=ON
    -DTINK_USE_INSTALLED_BENCHMARK=ON
  )
  build_and_upload_ccache \
    "${TINK_CC_CMAKE_IMAGE}" \
    "${TINK_CC_CMAKE_IMAGE_HASH}" \
    "${CMAKE_OPTS_STANDARD[@]}"

  # 2. Update ccache for installed dependencies CMake image.
  CMAKE_OPTS_INSTALLED_DEPS=(
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
    -DCMAKE_CXX_STANDARD=17
    -DCMAKE_CXX_STANDARD_REQUIRED=ON
    -DTINK_BUILD_TESTS=ON
    -DTINK_USE_SYSTEM_OPENSSL=ON
    -DTINK_USE_INSTALLED_ABSEIL=ON
    -DTINK_USE_INSTALLED_GOOGLETEST=ON
    -DTINK_USE_INSTALLED_PROTOBUF=ON
    -DTINK_USE_INSTALLED_BENCHMARK=ON
  )
  build_and_upload_ccache \
    "${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE}" \
    "${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH}" \
    "${CMAKE_OPTS_INSTALLED_DEPS[@]}"
else
  # Running locally.
  CMAKE_OPTS_STANDARD=(
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
    -DCMAKE_CXX_STANDARD=17
    -DCMAKE_CXX_STANDARD_REQUIRED=ON
    -DTINK_BUILD_TESTS=ON
    -DTINK_USE_INSTALLED_BENCHMARK=ON
  )
  if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
    build_and_upload_ccache "${CONTAINER_IMAGE}" "local-hash" "${CMAKE_OPTS_STANDARD[@]}"
  else
    build_and_upload_ccache "" "local-hash" "${CMAKE_OPTS_STANDARD[@]}"
  fi
fi
