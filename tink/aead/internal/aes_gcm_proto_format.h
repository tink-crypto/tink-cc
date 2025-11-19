// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_AEAD_INTERNAL_AES_GCM_PROTO_FORMAT_H_
#define TINK_AEAD_INTERNAL_AES_GCM_PROTO_FORMAT_H_

#include <array>
#include <cstdint>

#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"

namespace crypto {
namespace tink {
namespace internal {

class AesGcmKeyFormatTP : public proto_parsing::Message {
 public:
  AesGcmKeyFormatTP() = default;

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t key_size) { key_size_.set_value(key_size); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 2; }
  const proto_parsing::Field* field(int i) const override {
    return std::array<const proto_parsing::Field*, 2>{&key_size_, &version_}[i];
  }

  proto_parsing::Uint32Field key_size_{2};
  proto_parsing::Uint32Field version_{3};
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AES_GCM_PROTO_FORMAT_H_
