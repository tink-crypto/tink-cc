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

# Checks that all TINK_RTTI_SET_TYPE_ID and TINK_RTTI_COMPUTE_TYPE_ID usages in
# <source_dir> specify unique decimal integer literals in [1, 32767] and match
# the expected "<id> <file>" registry list.

# Generated with openssl rand -hex 10
echo "========================================================================="
echo "Tink Script ID: 9c4e17a83b05d2f641e9 (quickly find the script from logs)"
echo "========================================================================="

set -euo pipefail

# We currently hard code the list of files with IDs here -- this might or might
# not be useful. If it is annoying, please delete this part of the test.

DEFAULT_EXPECTED_IDS="$(cat <<'EOF'
1 //third_party/tink/cc/parameters.h
2 //third_party/tink/cc/key.h
101 //third_party/tink/cc/mac/mac_parameters.h
102 //third_party/tink/cc/mac/mac_key.h
103 //third_party/tink/cc/mac/hmac_parameters.h
104 //third_party/tink/cc/mac/hmac_key.h
105 //third_party/tink/cc/mac/aes_cmac_parameters.h
106 //third_party/tink/cc/mac/aes_cmac_key.h
30001 //third_party/tink/cc/internal/util_test.cc
30002 //third_party/tink/cc/internal/util_test.cc
30003 //third_party/tink/cc/internal/util_test.cc
30004 //third_party/tink/cc/internal/util_test.cc
30005 //third_party/tink/cc/internal/util_test.cc
30006 //third_party/tink/cc/mac/aes_cmac_parameters_test.cc
30007 //third_party/tink/cc/mac/aes_cmac_key_test.cc
30008 //third_party/tink/cc/mac/hmac_parameters_test.cc
30009 //third_party/tink/cc/mac/hmac_key_test.cc
EOF
)"
readonly DEFAULT_EXPECTED_IDS

if (( $# < 1 || $# > 2 )) || [[ ! -d "$1" ]]; then
  echo "Usage: $0 <source_dir> [expected_ids_file]" >&2
  exit 1
fi
readonly TARGET_DIR="${1%/}"
if (( $# == 2 )); then
  EXPECTED_IDS="$(cat "$2")"
else
  EXPECTED_IDS="${DEFAULT_EXPECTED_IDS}"
fi
readonly EXPECTED_IDS

LINES="$(grep -rnE --include='*.h' --include='*.cc' \
  'TINK_RTTI_(SET|COMPUTE)_TYPE_ID' "${TARGET_DIR}" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#define|")' || true)"
readonly LINES

if [[ -z "${LINES}" ]]; then
  if [[ -n "${EXPECTED_IDS}" ]]; then
    echo "ERROR: Found 0 RTTI type IDs, but expected:" >&2
    echo "${EXPECTED_IDS}" >&2
    exit 1
  fi
  echo "Checked 0 unique RTTI type ID(s)."
  exit 0
fi

VALID_RE='^[^:]+:[0-9]+:[[:space:]]*TINK_RTTI_(SET|COMPUTE)_TYPE_ID'
VALID_RE+='\([1-9][0-9]*[),]'
readonly VALID_RE

BAD_LINES="$(echo "${LINES}" | grep -vE "${VALID_RE}" || true)"
if [[ -n "${BAD_LINES}" ]]; then
  echo "ERROR: Malformed or non-literal TINK_RTTI_*_TYPE_ID line(s):" >&2
  echo "${BAD_LINES}" >&2
  exit 1
fi

IDS="$(echo "${LINES}" \
  | sed -E 's/.*TINK_RTTI_(SET|COMPUTE)_TYPE_ID\(([0-9]+).*/\2/' \
  | sort -n)"
readonly IDS

MAX_ID="$(echo "${IDS}" | tail -n 1)"
if (( MAX_ID > 32767 )); then
  echo "ERROR: RTTI type IDs in Tink must be <= 32767 (got ${MAX_ID}):" >&2
  echo "${LINES}" | grep -E "TINK_RTTI_(SET|COMPUTE)_TYPE_ID\(${MAX_ID}[),]" >&2
  exit 1
fi

DUPS="$(echo "${IDS}" | uniq -d)"
if [[ -n "${DUPS}" ]]; then
  echo "ERROR: Duplicate RTTI type IDs found:" >&2
  for id in ${DUPS}; do
    echo "${LINES}" | grep -E "TINK_RTTI_(SET|COMPUTE)_TYPE_ID\(${id}[),]" >&2
  done
  exit 1
fi

ACTUAL_IDS="$(echo "${LINES}" \
  | sed -E "s#^${TARGET_DIR}/([^:]+):[0-9]+:.*TINK_RTTI_(SET|COMPUTE)_TYPE_ID\(([0-9]+).*#\3 //third_party/tink/cc/\1#" \
  | LC_ALL=C sort -n -k1,1 -k2,2)"
readonly ACTUAL_IDS

if [[ "${ACTUAL_IDS}" != "${EXPECTED_IDS}" ]]; then
  echo "ERROR: Actual RTTI type IDs do not match expected list." >&2
  echo "Actual:" >&2
  echo "${ACTUAL_IDS}" >&2
  echo
  echo "Diff (-expected +actual):" >&2
  diff -u <(echo "${EXPECTED_IDS}") <(echo "${ACTUAL_IDS}") >&2
  exit 1
fi

echo "Checked $(echo "${IDS}" | wc -l | tr -d ' ') unique RTTI type ID(s)."
