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

# This script builds with CMake and runs tests within a given directory.

set -eEo pipefail

usage() {
  cat <<EOF
Usage: $0 [-h] [-o <output directory>] <project directory> \
  [<additional CMake param> <additional CMake param> ...]"
  -o: Output directory. If not specified, a temporary directory will be used.
  -h: Show this help message.
EOF
  exit 1
}

CMAKE_PROJECT_DIR=
ADDITIONAL_CMAKE_PARAMETERS=
CMAKE_OUTPUT_DIR=

#######################################
# Process command line arguments.
#
# Globals:
#   CMAKE_OUTPUT_DIR
#   CMAKE_PROJECT_DIR
#   ADDITIONAL_CMAKE_PARAMETERS
#
#######################################
process_args() {
  while getopts "ho:" opt; do
    case "${opt}" in
      o) CMAKE_OUTPUT_DIR="$(cd "${OPTARG}" && pwd)" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))

  CMAKE_OUTPUT_DIR="${CMAKE_OUTPUT_DIR:-$(mktemp -dt cmake-build.XXXXXX)}"
  readonly CMAKE_OUTPUT_DIR

  CMAKE_PROJECT_DIR="$1"
  readonly CMAKE_PROJECT_DIR
  if [[ -z "${CMAKE_PROJECT_DIR}" ]]; then
    usage
  fi
  shift 1

  ADDITIONAL_CMAKE_PARAMETERS=("$@")
  readonly ADDITIONAL_CMAKE_PARAMETERS
}

main() {
  process_args "$@"
  local -r cmake_parameters=(
    -DTINK_BUILD_TESTS=ON
    -DCMAKE_CXX_STANDARD=17
    -DCMAKE_CXX_STANDARD_REQUIRED=ON
    "${ADDITIONAL_CMAKE_PARAMETERS[@]}"
  )
  # We need an absolute path to the CMake project directory.
  local -r tink_cmake_project_dir="$(cd "${CMAKE_PROJECT_DIR}" && pwd)"
  cd "${CMAKE_OUTPUT_DIR}"
  cmake --version
  set -x
  cmake -S "${tink_cmake_project_dir}" -B "${CMAKE_OUTPUT_DIR}" \
    "${cmake_parameters[@]}"
  cmake --build . --parallel "$(nproc)"
  CTEST_OUTPUT_ON_FAILURE=1 ctest --parallel "$(nproc)"
}

main "$@"
