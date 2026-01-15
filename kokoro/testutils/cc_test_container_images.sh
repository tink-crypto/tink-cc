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

_image_prefix() {
  local -r artifact_registry_url="us-docker.pkg.dev"
  local -r test_project="tink-test-infrastructure"
  local -r artifact_registry_repo="tink-ci-images"
  echo "${artifact_registry_url}/${test_project}/${artifact_registry_repo}"
}

# Linux container images for Tink C++ libraries.
readonly TINK_CC_BASE_IMAGE_NAME="linux-tink-cc-base"
readonly TINK_CC_BASE_IMAGE_HASH="e118dbf49610be95485895b9c0f4cf37d1314aa540dd332c7110b23d3368fdfa"
readonly TINK_CC_BASE_IMAGE="$(_image_prefix)/${TINK_CC_BASE_IMAGE_NAME}@sha256:${TINK_CC_BASE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_IMAGE_NAME="linux-tink-cc-cmake"
readonly TINK_CC_CMAKE_IMAGE_HASH="8c35c8f2ff4a4599dbf916db80d24394740f5decb21610b8e8ce9b736617ba26"
readonly TINK_CC_CMAKE_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-1_1_1"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH="38015d19339606aa5569198d18381a8652a54e92e03b7202ee6084695131c3dc"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-3"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH="9ed96c75561a794179f339c021f764d7c7ab893e6fe8e1be5216809d0b0b8eb7"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH}"

readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME="linux-tink-cc-cmake-installed-deps"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH="92963002896016668a14d906939ffd4d56bca7b6a6e9582c87a945058214ddbd"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH}"

unset -f _image_prefix
