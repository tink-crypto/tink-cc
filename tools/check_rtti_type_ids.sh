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
# <source_dir> specify unique decimal integer literals in [1, 32767].

# Generated with openssl rand -hex 10
echo "========================================================================="
echo "Tink Script ID: 9c4e17a83b05d2f641e9 (quickly find the script from logs)"
echo "========================================================================="

set -euo pipefail

if (( $# != 1 )) || [[ ! -d "$1" ]]; then
  echo "Usage: $0 <source_dir>" >&2
  exit 1
fi
readonly TARGET_DIR="$1"

LINES="$(grep -rnE --include='*.h' --include='*.cc' \
  'TINK_RTTI_(SET|COMPUTE)_TYPE_ID' "${TARGET_DIR}" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#define|")' || true)"
readonly LINES

if [[ -z "${LINES}" ]]; then
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

echo "Checked $(echo "${IDS}" | wc -l | tr -d ' ') unique RTTI type ID(s)."
