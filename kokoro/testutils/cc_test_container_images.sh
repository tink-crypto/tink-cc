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
readonly TINK_CC_BASE_IMAGE_HASH="e4e7805d6688c855e9df54a60037ba655c17cd95375676cd16d79d8da9818d8f"
readonly TINK_CC_BASE_IMAGE="$(_image_prefix)/${TINK_CC_BASE_IMAGE_NAME}@sha256:${TINK_CC_BASE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_IMAGE_NAME="linux-tink-cc-cmake"
readonly TINK_CC_CMAKE_IMAGE_HASH="923c7266f444d702835378027d17661c7d098e84862512694e630e43a137e147"
readonly TINK_CC_CMAKE_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-1_1_1"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH="9af19696abeee2c5d289df499cf8ca2a1ffdeecc074ce07b149b7332db4cf412"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-3"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH="bf0f203542edb58e62635652cc0715c09447442d008ea19a84d13a55708d4172"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH}"

readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME="linux-tink-cc-cmake-installed-deps"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH="540b1fa6a03d158880a1666ddc1beace05cc61693cf37364423edc6fd6273600"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH}"

unset -f _image_prefix
