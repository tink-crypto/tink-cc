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

#ifndef TINK_AEAD_INTERNAL_AES_CTR_HMAC_PROTO_STRUCTS_H_
#define TINK_AEAD_INTERNAL_AES_CTR_HMAC_PROTO_STRUCTS_H_

#include <array>
#include <cstdint>

#include "absl/strings/string_view.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/mac/internal/hmac_proto_structs.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

class ProtoAesCtrParams : public proto_parsing::Message<ProtoAesCtrParams> {
 public:
  ProtoAesCtrParams() = default;

  uint32_t iv_size() const { return iv_size_.value(); }
  void set_iv_size(uint32_t value) { iv_size_.set_value(value); }

  std::array<const proto_parsing::OwningField*, 1> GetFields() const {
    return {&iv_size_};
  }

 private:
  proto_parsing::Uint32OwningField iv_size_{1};
};

class ProtoAesCtrKeyFormat
    : public proto_parsing::Message<ProtoAesCtrKeyFormat> {
 public:
  ProtoAesCtrKeyFormat() = default;
  ProtoAesCtrParams* mutable_params() { return params_.mutable_value(); }
  const ProtoAesCtrParams& params() const { return params_.value(); }
  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t value) { key_size_.set_value(value); }
  std::array<const proto_parsing::OwningField*, 2> GetFields() const {
    return {&params_, &key_size_};
  }

 private:
  proto_parsing::MessageOwningField<ProtoAesCtrParams> params_{1};
  proto_parsing::Uint32OwningField key_size_{2};
};

class ProtoAesCtrHmacAeadKeyFormat
    : public proto_parsing::Message<ProtoAesCtrHmacAeadKeyFormat> {
 public:
  ProtoAesCtrHmacAeadKeyFormat() = default;
  ProtoAesCtrKeyFormat* mutable_aes_ctr_key_format() {
    return aes_ctr_key_format_.mutable_value();
  }
  const ProtoAesCtrKeyFormat& aes_ctr_key_format() const {
    return aes_ctr_key_format_.value();
  }
  ProtoHmacKeyFormat* mutable_hmac_key_format() {
    return hmac_key_format_.mutable_value();
  }
  const ProtoHmacKeyFormat& hmac_key_format() const {
    return hmac_key_format_.value();
  }
  std::array<const proto_parsing::OwningField*, 2> GetFields() const {
    return {&aes_ctr_key_format_, &hmac_key_format_};
  }
  using Message::SerializeAsString;

 private:
  proto_parsing::MessageOwningField<ProtoAesCtrKeyFormat> aes_ctr_key_format_{
      1};
  proto_parsing::MessageOwningField<ProtoHmacKeyFormat> hmac_key_format_{2};
};

class ProtoAesCtrKey : public proto_parsing::Message<ProtoAesCtrKey> {
 public:
  ProtoAesCtrKey() = default;
  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }
  ProtoAesCtrParams* mutable_params() { return params_.mutable_value(); }
  const ProtoAesCtrParams& params() const { return params_.value(); }
  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) { key_value_.set_value(value); }
  std::array<const proto_parsing::OwningField*, 3> GetFields() const {
    return {&version_, &params_, &key_value_};
  }

 private:
  proto_parsing::Uint32OwningField version_{1};
  proto_parsing::MessageOwningField<ProtoAesCtrParams> params_{2};
  proto_parsing::OwningBytesField<SecretData> key_value_{3};
};

class ProtoAesCtrHmacAeadKey
    : public proto_parsing::Message<ProtoAesCtrHmacAeadKey> {
 public:
  ProtoAesCtrHmacAeadKey() = default;
  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }
  ProtoAesCtrKey* mutable_aes_ctr_key() { return aes_ctr_key_.mutable_value(); }
  const ProtoAesCtrKey& aes_ctr_key() const { return aes_ctr_key_.value(); }
  ProtoHmacKey* mutable_hmac_key() { return hmac_key_.mutable_value(); }
  const ProtoHmacKey& hmac_key() const { return hmac_key_.value(); }
  std::array<const proto_parsing::OwningField*, 3> GetFields() const {
    return {&version_, &aes_ctr_key_, &hmac_key_};
  }

 private:
  proto_parsing::Uint32OwningField version_{1};
  proto_parsing::MessageOwningField<ProtoAesCtrKey> aes_ctr_key_{2};
  proto_parsing::MessageOwningField<ProtoHmacKey> hmac_key_{3};
};

struct AesCtrParamsStruct {
  uint32_t iv_size = 0;

  static crypto::tink::internal::ProtoParser<AesCtrParamsStruct>
  CreateParser() {
    return crypto::tink::internal::ProtoParserBuilder<AesCtrParamsStruct>()
        .AddUint32Field(1, &AesCtrParamsStruct::iv_size)
        .BuildOrDie();
  }
};

struct AesCtrKeyFormatStruct {
  AesCtrParamsStruct params = {};
  uint32_t key_size = 0;
};

struct AesCtrHmacAeadKeyFormatStruct {
  AesCtrKeyFormatStruct aes_ctr_key_format = {};
  HmacKeyFormatStruct hmac_key_format = {};

  static const crypto::tink::internal::ProtoParser<
      AesCtrHmacAeadKeyFormatStruct>&
  GetParser();
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AES_CTR_HMAC_PROTO_STRUCTS_H_
