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

# This script updates BUILD files for tink-cc users who use Bazel.
#
# Tink C++ 2.0 changes the project structure moving source code into a `tink`
# folder. As a consequence, all Bazel targets new become `//tink:.*` or
# `//tink/.*`. This scripts perfoms the following replacements:
#
#   - "@${TINK_CC_REPO_NAME}//([a-z_]+)(.*)" => "@${TINK_CC_REPO_NAME}//tink/\1\2"
#   - "@${TINK_CC_REPO_NAME}//:([a-z_]+)" => "@${TINK_CC_REPO_NAME}//tink:\1"
#   - "@${TINK_CC_REPO_NAME}" => "@${TINK_CC_REPO_NAME}//tink:${TINK_CC_REPO_NAME}"

WORKSPACE_DIR=
TINK_CC_REPO_NAME=

usage() {
  echo "$0 [-h] <Project root dir> <Tink C++ Bazel repo name>"
  echo " -h: Show this help message."
  exit 1
}

process_params() {
  while getopts "h" opt; do
    case "${opt}" in
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))

  WORKSPACE_DIR="$1"
  TINK_CC_REPO_NAME="$2"
  readonly WORKSPACE_DIR
  readonly TINK_CC_REPO_NAME
}

main() {
  process_params "$@"

  if [[ ! -d "${WORKSPACE_DIR}" ]]; then
    echo "ERROR: ${WORKSPACE_DIR} does not exist." >&2
    usage
  fi

  pushd "${WORKSPACE_DIR}"
  grep "@${TINK_CC_REPO_NAME}" . -r -l --include BUILD --include BUILD.bazel \
    | xargs sed -i '' \
        -e 's#"@'"${TINK_CC_REPO_NAME}"'//\([a-z_]\{1,\}\)\(.*\)"#"@'"${TINK_CC_REPO_NAME}"'//tink/\1\2"#g' \
        -e 's#"@'"${TINK_CC_REPO_NAME}"'"#"@'"${TINK_CC_REPO_NAME}"'//tink:tink_cc"#g' \
        -e 's#"@'"${TINK_CC_REPO_NAME}"'//:\(.*\)"#"@'"${TINK_CC_REPO_NAME}"'//tink:\1"#g'
  popd
}

main "$@"
