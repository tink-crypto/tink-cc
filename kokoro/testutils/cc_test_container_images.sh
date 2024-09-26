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
readonly TINK_CC_BASE_IMAGE_HASH="edbed5df7677c77a4be9700bc3eff2c3176d4cbbe53c06e5b2507fafb71073dd"
readonly TINK_CC_BASE_IMAGE="$(_image_prefix)/${TINK_CC_BASE_IMAGE_NAME}@sha256:${TINK_CC_BASE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_IMAGE_NAME="linux-tink-cc-cmake"
readonly TINK_CC_CMAKE_IMAGE_HASH="d32f6dd135291de77918935be3ab9cbcd7a740de9328b34e85b804c324fcdc8b"
readonly TINK_CC_CMAKE_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-1_1_1"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH="87f98190630f14bc95579f5807361b611aff247c372e4ec839c32115c6b3331b"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-3"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH="1c7358f590713cd66f37671ef70118b403d61930a6778033e331bac8326afa88"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH}"

readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME="linux-tink-cc-cmake-installed-deps"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH="1574541f9acd605b2b275ef6ef3272409e0fd816c6c4fc5c3c3ab8f2eaae3ea4"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH}"

unset -f _image_prefix
