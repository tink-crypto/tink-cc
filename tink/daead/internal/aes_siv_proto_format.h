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

#ifndef TINK_DAEAD_INTERNAL_AES_SIV_PROTO_FORMAT_H_
#define TINK_DAEAD_INTERNAL_AES_SIV_PROTO_FORMAT_H_

#include <array>
#include <cstdint>

#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

// Proto message com.google.crypto.tink.AesSivKeyFormat.
class AesSivKeyFormatTP : public Message {
 public:
  AesSivKeyFormatTP() = default;
  using Message::SerializeAsString;

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t key_size) { key_size_.set_value(key_size); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&key_size_, &version_}[i];
  }

  Uint32Field key_size_{1, ProtoFieldOptions::kImplicit};
  Uint32Field version_{2, ProtoFieldOptions::kImplicit};
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_INTERNAL_AES_SIV_PROTO_FORMAT_H_
