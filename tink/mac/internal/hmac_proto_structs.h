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

#ifndef TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_
#define TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_

#include <array>
#include <cstdint>

#include "absl/strings/string_view.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

class HmacParamsTP : public proto_parsing::Message {
 public:
  HmacParamsTP() = default;

  HashTypeEnum hash() const { return hash_.value(); }
  void set_hash(HashTypeEnum value) { hash_.set_value(value); }

  uint32_t tag_size() const { return tag_size_.value(); }
  void set_tag_size(uint32_t value) { tag_size_.set_value(value); }

 private:
  size_t num_fields() const override { return 2; }
  const proto_parsing::Field* field(int i) const override {
    return std::array<const proto_parsing::Field*, 2>{&hash_, &tag_size_}[i];
  }

  proto_parsing::EnumField<HashTypeEnum> hash_{1, &HashTypeEnumIsValid};
  proto_parsing::Uint32Field tag_size_{2};
};

class HmacKeyFormatTP : public proto_parsing::Message {
 public:
  HmacKeyFormatTP() = default;

  const HmacParamsTP& params() const { return params_.value(); }
  HmacParamsTP* mutable_params() { return params_.mutable_value(); }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t value) { key_size_.set_value(value); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 3; }
  const proto_parsing::Field* field(int i) const override {
    return std::array<const proto_parsing::Field*, 3>{&params_, &key_size_,
                                                      &version_}[i];
  }

  proto_parsing::MessageField<HmacParamsTP> params_{1};
  proto_parsing::Uint32Field key_size_{2};
  proto_parsing::Uint32Field version_{3};
};

class HmacKeyTP : public proto_parsing::Message {
 public:
  HmacKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const HmacParamsTP& params() const { return params_.value(); }
  HmacParamsTP* mutable_params() { return params_.mutable_value(); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

 private:
  size_t num_fields() const override { return 3; }
  const proto_parsing::Field* field(int i) const override {
    return std::array<const proto_parsing::Field*, 3>{&version_, &params_,
                                                      &key_value_}[i];
  }

  proto_parsing::Uint32Field version_{1};
  proto_parsing::MessageField<HmacParamsTP> params_{2};
  proto_parsing::SecretDataField key_value_{3};
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_
