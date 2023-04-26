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

DEFAULT_DIR="$(pwd)"
if [[ -n "${TEST_SRCDIR}" ]]; then
  DEFAULT_DIR="${TEST_SRCDIR}"
fi
readonly DEFAULT_DIR
readonly CLI="${DEFAULT_DIR}/${1:-"update_build_files_for_tink_2_0_bazel.sh"}"
readonly TEST_UTILS="${DEFAULT_DIR}/${2:-test_utils.sh}"
readonly TESTDATA_DIR="${DEFAULT_DIR}/testdata"

# Load the test library.
source "${TEST_UTILS}"

_create_test_inputs() {
  local -r destination="$1"

  mkdir -p "${destination}/input_project/nested"

  cat <<EOF > "${destination}/input_project/BUILD"
cc_library(
    name = "example_target",
    srcs = ["example_target.cc"],
    hdrs = ["example_target.h"],
    deps = [
        "//some/other/dependency:dep",
        "@some_other_dep://some/other:dep",
        "@tink_cc",
        "@tink_cc//:keyset_handle",
        "@tink_cc//aead",
    ],
)
EOF

  cat <<EOF > "${destination}/input_project/BUILD_expected"
cc_library(
    name = "example_target",
    srcs = ["example_target.cc"],
    hdrs = ["example_target.h"],
    deps = [
        "//some/other/dependency:dep",
        "@some_other_dep://some/other:dep",
        "@tink_cc//tink:tink_cc",
        "@tink_cc//tink:keyset_handle",
        "@tink_cc//tink/aead",
    ],
)
EOF

  cat <<EOF > "${destination}/input_project/nested/BUILD.bazel"
cc_library(
    name = "example_target",
    srcs = ["example_target.cc"],
    hdrs = ["example_target.h"],
    deps = [
        "//some/other/dependency:dep",
        "@some_other_dep://some/other:dep",
        "@tink_cc",
        "@tink_cc//:keyset_handle",
        "@tink_cc//aead",
    ],
)
EOF

  cat <<EOF > "${destination}/input_project/nested/BUILD.bazel_expected"
cc_library(
    name = "example_target",
    srcs = ["example_target.cc"],
    hdrs = ["example_target.h"],
    deps = [
        "//some/other/dependency:dep",
        "@some_other_dep://some/other:dep",
        "@tink_cc//tink:tink_cc",
        "@tink_cc//tink:keyset_handle",
        "@tink_cc//tink/aead",
    ],
)
EOF
}

test_UpdateBuildFilesTest_GeneralTest() {
  _create_test_inputs "${TEST_CASE_TMPDIR}"
  "${CLI}" "${TEST_CASE_TMPDIR}/input_project" "tink_cc"
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${TEST_CASE_TMPDIR}/input_project/BUILD" \
    "${TEST_CASE_TMPDIR}/input_project/BUILD_expected"
  ASSERT_FILE_EQUALS "${TEST_CASE_TMPDIR}/input_project/nested/BUILD.bazel" \
    "${TEST_CASE_TMPDIR}/input_project/nested/BUILD.bazel_expected"
}

main() {
  run_all_tests "$@"
}

main "$@"
