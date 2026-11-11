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

DEFAULT_DIR="$(pwd)"
if [[ -n "${TEST_SRCDIR:-}" ]]; then
  DEFAULT_DIR="${TEST_SRCDIR}"
fi
readonly DEFAULT_DIR
readonly CLI="${DEFAULT_DIR}/${1:-check_rtti_type_ids.sh}"
readonly TEST_UTILS="${DEFAULT_DIR}/${2:-test_utils.sh}"

source "${TEST_UTILS}"

test_CheckRttiTypeIds_EmptyDirectorySucceeds() {
  mkdir -p "${TEST_CASE_TMPDIR}/src"
  echo "class Plain {};" > "${TEST_CASE_TMPDIR}/src/plain.h"
  "${CLI}" "${TEST_CASE_TMPDIR}/src"
  ASSERT_CMD_SUCCEEDED
}

test_CheckRttiTypeIds_ValidUniqueIdsAndIgnoredLinesSucceed() {
  mkdir -p "${TEST_CASE_TMPDIR}/src"
  cat <<'EOF' > "${TEST_CASE_TMPDIR}/src/rtti.h"
// Usage: TINK_RTTI_SET_TYPE_ID(1);
#define TINK_RTTI_SET_TYPE_ID(id)
#define TINK_RTTI_COMPUTE_TYPE_ID(id, ...)
"Must declare TINK_RTTI_SET_TYPE_ID."
EOF
  cat <<'EOF' > "${TEST_CASE_TMPDIR}/src/types.h"
class Foo {
  TINK_RTTI_SET_TYPE_ID(1);
};
class Bar {
  TINK_RTTI_SET_TYPE_ID(32767);
};
template <typename A, typename B>
class Wrapper {
  TINK_RTTI_COMPUTE_TYPE_ID(20, A,
                            B);
};
EOF
  cat <<'EOF' > "${TEST_CASE_TMPDIR}/src/rtti_test.cc"
#define TEST_RTTI_SET_TYPE_ID TINK_RTTI_SET_TYPE_ID
class Fake {
  TEST_RTTI_SET_TYPE_ID(1);
};
EOF
  "${CLI}" "${TEST_CASE_TMPDIR}/src"
  ASSERT_CMD_SUCCEEDED
}

test_CheckRttiTypeIds_DuplicateIdFails() {
  mkdir -p "${TEST_CASE_TMPDIR}/src"
  printf '  TINK_RTTI_SET_TYPE_ID(42);\n' > "${TEST_CASE_TMPDIR}/src/a.h"
  printf '  TINK_RTTI_COMPUTE_TYPE_ID(42, T);\n' > "${TEST_CASE_TMPDIR}/src/b.cc"
  "${CLI}" "${TEST_CASE_TMPDIR}/src"
  ASSERT_CMD_FAILED
}

test_CheckRttiTypeIds_InvalidRangeOrNonDecimalFails() {
  mkdir -p "${TEST_CASE_TMPDIR}/src"
  for bad in \
    "  TINK_RTTI_SET_TYPE_ID(0);" \
    "  TINK_RTTI_SET_TYPE_ID(32768);" \
    "  TINK_RTTI_SET_TYPE_ID(kMyId);" \
    "  TINK_RTTI_SET_TYPE_ID(012);" \
    "  TINK_RTTI_SET_TYPE_ID(0x10);"; do
    printf '%s\n' "${bad}" > "${TEST_CASE_TMPDIR}/src/bad.h"
    "${CLI}" "${TEST_CASE_TMPDIR}/src"
    ASSERT_CMD_FAILED
  done
}

main() {
  run_all_tests "$@"
}

main "$@"
