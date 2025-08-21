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
readonly TINK_CC_BASE_IMAGE_HASH="c024b7c9db2387f4d28ced61e27e14aa078074e688779391bfdfbee724e1b3c7"
readonly TINK_CC_BASE_IMAGE="$(_image_prefix)/${TINK_CC_BASE_IMAGE_NAME}@sha256:${TINK_CC_BASE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_IMAGE_NAME="linux-tink-cc-cmake"
readonly TINK_CC_CMAKE_IMAGE_HASH="bd58dc50c8c691f95e08bd2f14e19c82d2c64bb4907939f65b4fee42ac2d8c01"
readonly TINK_CC_CMAKE_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-1_1_1"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH="8497aae1cc1954f20ec839aebea251e550e22d796a0f979b4477977c85d200d5"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-3"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH="dc2ec2ca3232edef946e9cad44c5f37ab6188be10ca59e37130aec9f5f286cac"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH}"

readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME="linux-tink-cc-cmake-installed-deps"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH="7f861e50e1ac1ee2fa94e6ce79c14f79fae324c6c4e463366df75a95b491a20d"
readonly TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE="$(_image_prefix)/${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_WITH_INSTALLED_DEPS_IMAGE_HASH}"

unset -f _image_prefix
