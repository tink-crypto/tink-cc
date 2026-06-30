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

# This script enables ccache for Tink C++ CMake builds.
# It performs the following:
# 1. Sets the CCACHE_DIR to a local directory in the workspace.
# 2. Sets CCACHE_READONLY to 1 by default (preventing test runs from polluting the cache).
# 3. If running on Kokoro, it downloads the existing ccache tarball from GCS
#    using the provided Docker image hash to ensure cache compatibility.
# 4. Appends the CMAKE_CXX_COMPILER_LAUNCHER=ccache flag to EXTRA_CMAKE_ARGS
#    so CMake uses ccache during the build.

# This script must be sourced.
# Usage: source kokoro/testutils/ccache_enable.sh <image_hash>

if [[ -z "${1:-}" ]]; then
  echo "Error: Image hash argument is required."
  echo "Usage: source kokoro/testutils/ccache_enable.sh <image_hash>"
  return 1
fi
readonly CACHE_IMAGE_HASH="$1"

export CCACHE_DIR="$(pwd)/ccache"
export CCACHE_READONLY=${CCACHE_READONLY:-1} # Default to readonly for test runs

# If we are on the Kokoro host (not inside the Docker container yet),
# we download the cache from GCS. We detect this by checking if 'gcloud' is available
# and the required remote cache environment variables are set.
if [[ "${IS_KOKORO:-false}" == "true" || -n "${KOKORO_ARTIFACTS_DIR:-}" ]] && \
   [[ -n "${TINK_REMOTE_CACHE_GCS_BUCKET:-}" ]] && \
   [[ -n "${TINK_REMOTE_CACHE_SERVICE_KEY:-}" ]] && \
   command -v gcloud &> /dev/null; then
  REMOTE_CACHE_URL="gs://${TINK_REMOTE_CACHE_GCS_BUCKET}/cmake/${CACHE_IMAGE_HASH}"

  echo "Setting up ccache from GCS..."
  set -x
  gcloud auth activate-service-account --key-file="${TINK_REMOTE_CACHE_SERVICE_KEY}"
  gcloud config set project tink-test-infrastructure

  if gcloud storage objects list --stat --fetch-encrypted-object-hashes "${REMOTE_CACHE_URL}/ccache/ccache.tgz" &> /dev/null; then
    echo "Using ccache: ${REMOTE_CACHE_URL}/ccache/ccache.tgz"
    mkdir -p ccache
    gcloud storage cat "${REMOTE_CACHE_URL}/ccache/ccache.tgz" \
      | tar -C ccache -xzf - --strip-components=1
  else
    echo "No remote ccache found at ${REMOTE_CACHE_URL}"
  fi
  set +x
fi

# This variable can be passed to CMake: cmake ${EXTRA_CMAKE_ARGS[@]} ...
if [[ -d "${CCACHE_DIR}" ]]; then
  if [[ "$(declare -p EXTRA_CMAKE_ARGS 2>/dev/null)" == "declare -a"* ]]; then
    EXTRA_CMAKE_ARGS+=( "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache" )
  else
    export EXTRA_CMAKE_ARGS="${EXTRA_CMAKE_ARGS:-} -DCMAKE_CXX_COMPILER_LAUNCHER=ccache"
  fi
fi
