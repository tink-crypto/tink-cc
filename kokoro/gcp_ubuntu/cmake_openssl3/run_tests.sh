#!/bin/bash
# Copyright 2023 Google LLC
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

set -euo pipefail

if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
fi

readonly OPENSSL3_VERSION="3.0.8"
readonly OPENSSL3_SHA256="6c13d2bf38fdf31eac3ce2a347073673f5d63263398f1f69d0df4a41253e4b3e"

source ./kokoro/testutils/install_openssl.sh "${OPENSSL3_VERSION}" \
  "${OPENSSL3_SHA256}"

./kokoro/testutils/run_cmake_tests.sh . -DTINK_USE_SYSTEM_OPENSSL=ON \
  -DOPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR}"
