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

set -euo pipefail

# If we are running on Kokoro cd into the repository.
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc"
  chmod +x "${KOKORO_GFILE_DIR}/use_bazel.sh"
  "${KOKORO_GFILE_DIR}/use_bazel.sh" "$(cat .bazelversion)"
fi

source ./kokoro/testutils/install_cmake.sh "3.8.0" \
  "330357990d84599f9c1a87f568a724f0fe5de1687c32961dda689d52588a5b24"

# Run build and tests with the BoringSSL FIPS module

# Prepare the workspace to use BoringCrypto which is in
# third_party/boringssl_fips; insert the local_repository instruction below
# in WORKSPACE.
APPEND_AFTER='workspace(name = "tink_cc")'
NUM_MATCHES="$(grep -c "${APPEND_AFTER}" WORKSPACE)"
if (( $? != 0 || NUM_MATCHES != 1)); then
  echo "ERROR: Could not patch WORKSPACE to build BoringSSL with FIPS module"
  exit 1
fi

mapfile LOCAL_FIPS_REPOSITORY <<EOM
local_repository(
  name = "boringssl",
  path = "third_party/boringssl_fips",
)
EOM

printf -v INSERT_TEXT '\\n%s' "${LOCAL_FIPS_REPOSITORY[@]//$'\n'/}"
sed -i.bak "/${APPEND_AFTER}/a \\${INSERT_TEXT}" WORKSPACE

BAZEL_FLAGS=(
  --//tink/config:use_only_fips=True
  --build_tag_filters=fips,-requires_boringcrypto_update
)

bazel build \
  "${BAZEL_FLAGS[@]}" \
  -- ...

bazel test \
  "${BAZEL_FLAGS[@]}" \
  --build_tests_only \
  --test_output=errors \
  --test_tag_filters=fips,-requires_boringcrypto_update \
  -- ...

mv WORKSPACE.bak WORKSPACE
