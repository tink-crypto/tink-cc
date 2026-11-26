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

# Downloads, compiles, and installs GoogleTest, Abseil, and Protobuf using CMake.
# Supports both Linux and macOS.

# Generated with openssl rand -hex 10
echo "================================================================================"
echo "Tink Script ID: 8a3f1c7e4b2d9056e1a4 (to quickly find the script from logs)"
echo "================================================================================"

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <install prefix>"
  exit 1
fi
INSTALL_PREFIX=$(cd "$1" && pwd)
readonly INSTALL_PREFIX

get_ncpus() {
  if command -v nproc &> /dev/null; then
    nproc
  else
    sysctl -n hw.ncpu
  fi
}

verify_sha256() {
  local -r sha256="$1"
  local -r file="$2"
  if command -v sha256sum &> /dev/null; then
    echo "${sha256}  ${file}" | sha256sum -c -
  else
    echo "${sha256}  ${file}" | shasum -a 256 -c -
  fi
}

run_cmake_install() {
  local -r build_dir="$1"
  if [[ -w "${build_dir}" ]]; then
    cmake --install "${build_dir}"
  else
    sudo cmake --install "${build_dir}"
  fi
  if command -v ldconfig &> /dev/null && [[ "${INSTALL_PREFIX}" == "/usr" || "${INSTALL_PREFIX}" == "/usr/local" ]]; then
    if [[ -w "${build_dir}" ]]; then
      ldconfig
    else
      sudo ldconfig
    fi
  fi
}

install_cmake_dep() {
  local -r name="$1"
  local -r url="$2"
  local -r sha256="$3"
  local -r src_subdir="$4"
  shift 4

  local -r archive="${TMP_DIR}/${name}.archive"
  local -r work_dir="${TMP_DIR}/${name}"
  mkdir -p "${work_dir}"
  curl -LsS "${url}" -o "${archive}"
  verify_sha256 "${sha256}" "${archive}"
  if [[ "${url}" == *.zip ]]; then
    unzip -q "${archive}" -d "${work_dir}"
  else
    tar -xzf "${archive}" -C "${work_dir}"
  fi
  cmake -S "${work_dir}/${src_subdir}" -B "${work_dir}/build" \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_CXX_STANDARD=17 \
    -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DCMAKE_INSTALL_RPATH="${INSTALL_PREFIX}/lib" \
    -DCMAKE_PREFIX_PATH="${INSTALL_PREFIX}" \
    ${CMAKE_LAUNCHER_ARGS[@]+"${CMAKE_LAUNCHER_ARGS[@]}"} \
    "$@"
  cmake --build "${work_dir}/build" --parallel "${NCPUS}"
  run_cmake_install "${work_dir}/build"
  rm -rf "${work_dir}" "${archive}"
}

TMP_DIR="$(mktemp -dt tink-cmake-deps.XXXXXX)"
readonly TMP_DIR
trap 'rm -rf "${TMP_DIR}"' EXIT

NCPUS="$(get_ncpus)"
readonly NCPUS

CMAKE_LAUNCHER_ARGS=()
if command -v ccache &> /dev/null; then
  CMAKE_LAUNCHER_ARGS=(
    -DCMAKE_C_COMPILER_LAUNCHER=ccache
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
  )
fi
readonly CMAKE_LAUNCHER_ARGS

set -x

# Match the dependency versions pinned in cc/cmake/TinkWorkspace.cmake.
install_cmake_dep \
  "googletest" \
  "https://github.com/google/googletest/releases/download/v1.18.0/googletest-1.18.0.tar.gz" \
  "6e3191c1455468b3fc35a417fb565c1c5071aee1b7e7f85e30cf48a98d37d8b5" \
  "googletest-1.18.0"

install_cmake_dep \
  "abseil" \
  "https://github.com/abseil/abseil-cpp/releases/download/20260817.0/abseil-cpp-20260817.0.tar.gz" \
  "f7e05179df39c45434cad433f5783840bb3788ef322976f9138bc6b72b3a107d" \
  "abseil-cpp-20260817.0" \
  -DABSL_BUILD_TESTING=OFF \
  -DABSL_BUILD_TEST_HELPERS=ON \
  -DABSL_USE_EXTERNAL_GOOGLETEST=ON \
  -DABSL_FIND_GOOGLETEST=ON \
  -DABSL_ENABLE_INSTALL=ON

install_cmake_dep \
  "protobuf" \
  "https://github.com/protocolbuffers/protobuf/releases/download/v36.2/protobuf-36.2.zip" \
  "ec61440905b46d42dc58ce7b490f0469263a21f93407f741c97e9b6b09533eb6" \
  "protobuf-36.2" \
  -Dprotobuf_ABSL_PROVIDER=package \
  -Dprotobuf_BUILD_SHARED_LIBS=ON \
  -Dprotobuf_BUILD_TESTS=OFF \
  -Dprotobuf_BUILD_EXAMPLES=OFF
