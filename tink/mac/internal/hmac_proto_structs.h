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

#include "absl/base/no_destructor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

class ProtoHmacParams : public proto_parsing::Message<ProtoHmacParams> {
 public:
  ProtoHmacParams() = default;

  HashTypeEnum hash() const { return hash_.value(); }
  void set_hash(HashTypeEnum value) { hash_.set_value(value); }

  uint32_t tag_size() const { return tag_size_.value(); }
  void set_tag_size(uint32_t value) { tag_size_.set_value(value); }

  std::array<const proto_parsing::OwningField*, 2> GetFields() const {
    return {&hash_, &tag_size_};
  }

 private:
  proto_parsing::EnumOwningField<HashTypeEnum> hash_{1, &HashTypeEnumIsValid};
  proto_parsing::Uint32OwningField tag_size_{2};
};

class ProtoHmacKeyFormat : public proto_parsing::Message<ProtoHmacKeyFormat> {
 public:
  ProtoHmacKeyFormat() = default;

  const ProtoHmacParams& params() const { return params_.value(); }
  ProtoHmacParams* mutable_params() { return params_.mutable_value(); }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t value) { key_size_.set_value(value); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

  std::array<const proto_parsing::OwningField*, 3> GetFields() const {
    return {&params_, &key_size_, &version_};
  }

 private:
  proto_parsing::MessageOwningField<ProtoHmacParams> params_{1};
  proto_parsing::Uint32OwningField key_size_{2};
  proto_parsing::Uint32OwningField version_{3};
};

class ProtoHmacKey : public proto_parsing::Message<ProtoHmacKey> {
 public:
  ProtoHmacKey() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const ProtoHmacParams& params() const { return params_.value(); }
  ProtoHmacParams* mutable_params() { return params_.mutable_value(); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) { key_value_.set_value(value); }

  std::array<const proto_parsing::OwningField*, 3> GetFields() const {
    return {&version_, &params_, &key_value_};
  }

 private:
  proto_parsing::Uint32OwningField version_{1};
  proto_parsing::MessageOwningField<ProtoHmacParams> params_{2};
  proto_parsing::OwningBytesField<SecretData> key_value_{3};
};

// TODO: b/451894777 - Remove these structs once the migration to the classes
// above is complete.
struct HmacParamsStruct {
  HashTypeEnum hash = HashTypeEnum::kUnknownHash;
  uint32_t tag_size = 0;

  static crypto::tink::internal::ProtoParser<HmacParamsStruct> CreateParser() {
    return crypto::tink::internal::ProtoParserBuilder<HmacParamsStruct>()
        .AddEnumField(1, &HmacParamsStruct::hash, &HashTypeEnumIsValid)
        .AddUint32Field(2, &HmacParamsStruct::tag_size)
        .BuildOrDie();
  }

  static const crypto::tink::internal::ProtoParser<HmacParamsStruct>&
  GetParser() {
    static const absl::NoDestructor<
        crypto::tink::internal::ProtoParser<HmacParamsStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct HmacKeyFormatStruct {
  HmacParamsStruct params = {};
  uint32_t key_size = 0;
  uint32_t version = 0;

  static crypto::tink::internal::ProtoParser<HmacKeyFormatStruct>
  CreateParser() {
    return crypto::tink::internal::ProtoParserBuilder<HmacKeyFormatStruct>()
        .AddMessageField(1, &HmacKeyFormatStruct::params,
                         HmacParamsStruct::CreateParser())
        .AddUint32Field(2, &HmacKeyFormatStruct::key_size)
        .AddUint32Field(3, &HmacKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const crypto::tink::internal::ProtoParser<HmacKeyFormatStruct>&
  GetParser() {
    static const absl::NoDestructor<
        crypto::tink::internal::ProtoParser<HmacKeyFormatStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_
