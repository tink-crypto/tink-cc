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

# Builds Tink's BoringSSL with CMake and runs the `tink_check_boringssl_symbols`
# target, which checks with BoringSSL's `util/audit_symbols.go` that every
# symbol of the library contains the Tink-specific prefix.
#
# Extra arguments are passed to CMake (e.g. ccache launchers).
# Usage: do_run_test.sh [cmake args...]

set -euo pipefail
export CCACHE_DIR="$(pwd)/ccache"
export CCACHE_READONLY=1

# Same build directory as the cmake_ccache_update job: ccache includes the
# build directory in its cache keys (BoringSSL compiles with debug info), so a
# different path would miss every cached object.
readonly BUILD_DIR="out"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# BoringSSL's go.mod requires a recent Go version: with GOTOOLCHAIN=auto, Go
# downloads it if the installed one is older. Go's caches are kept out of the
# source tree; -modcacherw makes the module cache deletable.
GO_TMP_DIR="$(mktemp -dt tink-go.XXXXXX)"
readonly GO_TMP_DIR
export GOTOOLCHAIN=auto
export GOPATH="${GO_TMP_DIR}/go"
export GOCACHE="${GO_TMP_DIR}/go-build-cache"
export GOFLAGS=-modcacherw

# The target is only defined in test builds. Building it only builds BoringSSL.
cmake -S . -B "${BUILD_DIR}" -DTINK_BUILD_TESTS=ON "$@"
cmake --build "${BUILD_DIR}" --parallel "$(nproc)" \
  --target tink_check_boringssl_symbols
