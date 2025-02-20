// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////
#ifndef TINK_INTERNAL_COMMON_PROTO_ENUMS_H_
#define TINK_INTERNAL_COMMON_PROTO_ENUMS_H_

#include <cstdint>

namespace crypto {
namespace tink {
namespace internal {

// Enum representing the elliptic curve type of a key.
// It represents the proto enum `google.crypto.tink.EllipticCurveType`.
enum class EllipticCurveTypeEnum : uint32_t {
  kUnknownCurve = 0,
  kNistP256 = 2,
  kNistP384 = 3,
  kNistP521 = 4,
  kCurve25519 = 5,
};

inline bool EllipticCurveTypeEnumIsValid(int c) {
  return 0 <= c && c != 1 && c <= 5;
}

// Enum representing the elliptic curve point format of a key.
// It represents the proto enum `google.crypto.tink.EcPointFormat`.
enum class EcPointFormatEnum : uint32_t {
  kUnknownFormat,
  kUncompressed,
  kCompressed,
  kDoNotUseCrunchyUncompressed,
};

inline bool EcPointFormatEnumIsValid(int c) { return 0 <= c && c <= 3; }

// Enum representing the hash type of a key.
// It represents the proto enum `google.crypto.tink.HashType`.
enum class HashTypeEnum : uint32_t {
  kUnknownHash,
  kSha1,
  kSha384,
  kSha256,
  kSha512,
  kSha224,
};

inline bool HashTypeEnumIsValid(int c) { return 0 <= c && c <= 5; }

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_COMMON_PROTO_ENUMS_H_
