#!/bin/bash
# Copyright 2020 Google LLC
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


# This script builds BoringSSL as described in the security policy
# https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5104.pdf

set -e

if [[ "$(uname)" != "Linux" ]]; then
    echo "ERROR: BoringSSL only supports FIPS mode in Linux."
    exit 1
fi

# Install required build tools
#
# Clang 17.0.6
CLANG_PLATFORM="x86_64-linux-gnu-ubuntu-22.04"
CLANG_SHA256SUM="884ee67d647d77e58740c1e645649e29ae9e8a6fe87c1376be0f3a30f3cc9ab3"
curl -OLsS https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.6/clang+llvm-17.0.6-"${CLANG_PLATFORM}".tar.xz
echo "${CLANG_SHA256SUM}" clang+llvm-17.0.6-"${CLANG_PLATFORM}".tar.xz | sha256sum --check

tar -xf clang+llvm-17.0.6-"${CLANG_PLATFORM}".tar.xz
rm clang+llvm-17.0.6-"${CLANG_PLATFORM}".tar.xz

export HOME="${PWD}"
printf "set(CMAKE_C_COMPILER \"clang\")\nset(CMAKE_CXX_COMPILER \"clang++\")\n" > "${HOME}/toolchain"
export PATH="${PWD}/clang+llvm-17.0.6-${CLANG_PLATFORM}/bin:${PATH}"


# Go 1.22.3
GO_PLATFORM="linux-amd64"
GO_SHA256SUM="8920ea521bad8f6b7bc377b4824982e011c19af27df88a815e3586ea895f1b36"
curl -OLsS https://go.dev/dl/go1.22.3."${GO_PLATFORM}".tar.gz
echo "${GO_SHA256SUM}" go1.22.3."${GO_PLATFORM}".tar.gz | sha256sum --check
tar -xf go1.22.3."${GO_PLATFORM}".tar.gz
rm go1.22.3."${GO_PLATFORM}".tar.gz

export PATH="${PWD}/go/bin:${PATH}"

# Cmake 3.29.3
CMAKE_PLATFORM="linux-x86_64"
CMAKE_SHA256SUM="90b543a30220401db0e08347af067545be158ce89ffb09b7df1516cda8617329"
curl -OLsS https://github.com/Kitware/CMake/releases/download/v3.29.3/cmake-3.29.3-${CMAKE_PLATFORM}.tar.gz
echo "${CMAKE_SHA256SUM}" cmake-3.29.3-${CMAKE_PLATFORM}.tar.gz | sha256sum --check
tar -xf cmake-3.29.3-${CMAKE_PLATFORM}.tar.gz
rm cmake-3.29.3-${CMAKE_PLATFORM}.tar.gz

export PATH="${PWD}/cmake-3.29.3-${CMAKE_PLATFORM}/bin:${PATH}"


# Ninja 1.12.1
NINJA_SHA256SUM="6f98805688d19672bd699fbbfa2c2cf0fc054ac3df1f0e6a47664d963d530255"
curl -OLsS https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-linux.zip
echo "${NINJA_SHA256SUM}" ninja-linux.zip | sha256sum --check

unzip ninja-linux.zip
rm ninja-linux.zip

export PATH="${PWD}:${PATH}"


# Download BoringSSL and verify
BORINGSSL_SHA256SUM="b1c87a2746e831dd51448038d8ec7d0ba256d949e73dace0c9a1484889d82d1a"
BORINGSSL_FILENAME="boringssl-85897d07196b7bf164dbd4673fc78b762aff3e8b.tar.xz"

# Download archive and verify checksum
# Note: The public GCS bucket is no longer accessible due to policy changes.
# Using the archive attached to https://issues.chromium.org/issues/467869209 for now.
curl -LsS "https://issues.chromium.org/action/issues/467869209/attachments/72264454?download=true" -o "${BORINGSSL_FILENAME}"
echo "${BORINGSSL_SHA256SUM}" "${BORINGSSL_FILENAME}" | sha256sum --check

tar -xf "${BORINGSSL_FILENAME}"
rm "${BORINGSSL_FILENAME}"

# Build BoringSSL
(
  cd boringssl
  mkdir build && cd build && cmake -GNinja -DCMAKE_TOOLCHAIN_FILE=${HOME}/toolchain -DFIPS=1 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 ..
  ninja
  ninja run_tests

  if [[ "$(tool/bssl isfips)" != "1"  ]]; then
      echo "ERROR: BoringSSL FIPS build check failed."
      exit 1
  fi
)

# Cleanup build tools
rm -rf clang+llvm-17.0.6-"${CLANG_PLATFORM}"
rm -rf go
rm -rf cmake-3.29.3-"${CMAKE_PLATFORM}"
rm ninja
rm toolchain
