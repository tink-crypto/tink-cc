// Copyright 2017 Google LLC
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

#include "tink/crypto_format.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/endian.h"
#include "proto/tink.pb.h"

using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

const int CryptoFormat::kNonRawPrefixSize;
const int CryptoFormat::kLegacyPrefixSize;
const uint8_t CryptoFormat::kLegacyStartByte;

const int CryptoFormat::kTinkPrefixSize;
const uint8_t CryptoFormat::kTinkStartByte;

const int CryptoFormat::kRawPrefixSize;
const absl::string_view CryptoFormat::kRawPrefix = "";

// static
absl::StatusOr<std::string> CryptoFormat::GetOutputPrefix(
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info) {
  static_assert(sizeof(key_info.key_id() == sizeof(uint32_t)), "");
  switch (key_info.output_prefix_type()) {
    case OutputPrefixType::TINK: {
      static_assert(kTinkPrefixSize == 1 + sizeof(uint32_t), "");
      std::string prefix(kTinkPrefixSize, '\0');
      prefix[0] = kTinkStartByte;
      internal::StoreBigEndian32(reinterpret_cast<uint8_t*>(&prefix[1]),
                                 key_info.key_id());
      return prefix;
    }
    case OutputPrefixType::CRUNCHY:
      // FALLTHROUGH
    case OutputPrefixType::LEGACY: {
      static_assert(kLegacyPrefixSize == 1 + sizeof(uint32_t), "");
      std::string prefix(kLegacyPrefixSize, '\0');
      prefix[0] = kLegacyStartByte;
      internal::StoreBigEndian32(reinterpret_cast<uint8_t*>(&prefix[1]),
                                 key_info.key_id());
      return prefix;
    }
    case OutputPrefixType::RAW:
      return std::string(kRawPrefix);
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "The given key has invalid OutputPrefixType.");
  }
}

}  // namespace tink
}  // namespace crypto
