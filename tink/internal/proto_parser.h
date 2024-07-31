// Copyright 2024 Google LLC
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

#ifndef TINK_INTERNAL_PROTO_PARSER_H_
#define TINK_INTERNAL_PROTO_PARSER_H_

#include <cstdint>
#include <string>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

enum class ProtoFieldType { kUint32, kBytesString, kBytesSecretData };

// A helper class to parse a serialized proto message.  Suppose for example we
// have the a proto such as:
//
// message AesGcmKey {
//   uint32 version_number = 1;
//   uint32 key_size = 2;
//   bytes key = 3;
// }
//
// We could parse it with the following code:
//
// struct AesGcmKeyStruct {
//   uint32_t version_number;
//   uint32_t key_size;
//   crypto::tink::util::SecretData key;
// };
// constexpr int32_t kVersionNumberTag = 1;
// constexpr int32_t kKeySizeTag = 2;
// constexpr int32_t kKeyTag = 3;
// absl::StatusOr<AesGcmKeyStruct> s = ProtoParser()
//     .AddUint32Field(kVersionNumberTag, &AesGcmKeyStruct::version_number)
//     .AddUint32Field(kKeySizeTag, &AesGcmKeyStruct::key_size)
//     .AddBytesSecretDataField(kKeyTag,
//                              &AesGcmKeyStruct::key,
//                              secret_key_access_token)
//     .Parse(serialized_proto);
//
// This will parse the serialized proto and return a struct in which
// version_number, key_size, and key are set accordingly.
//
// If the return value of Parse is an error, variables are in an unspecified
// state. Parse must not be called twice. Fields can be added in any order.
template <typename Struct>
class ProtoParser {
 public:
  ProtoParser() = default;
  // Not movable or copyable.
  ProtoParser(const ProtoParser&) = delete;
  ProtoParser& operator=(const ProtoParser&) = delete;

  ProtoParser& AddUint32Field(int tag, uint32_t Struct::*value);
  ProtoParser& AddBytesStringField(int tag, std::string Struct::*value);
  ProtoParser& AddBytesSecretDataField(
      int tag, crypto::tink::util::SecretData Struct::*value,
      crypto::tink::SecretKeyAccessToken token);

  absl::StatusOr<Struct> Parse(absl::string_view input);

 private:
  struct Field {
    ProtoFieldType type;

    // field.value.index() == static_cast<int>(field.type)
    absl::variant<uint32_t Struct::*, std::string Struct::*,
                  crypto::tink::util::SecretData Struct::*>
        value;
  };

  // Wiretype::kVarint
  absl::Status ConsumeVarintWithTag(absl::string_view& serialized, int tag,
                                    Struct& s);
  absl::Status ConsumeUint32WithField(absl::string_view& serialized,
                                      const Field& field, Struct& s);

  // Wiretype::kLengthDelimited
  absl::Status ConsumeLengthDelimitedWithTag(absl::string_view& serialized,
                                             int tag, Struct& s);
  absl::Status ConsumeBytesToStringWithField(absl::string_view& serialized,
                                             const Field& field, Struct& s);
  absl::Status ConsumeBytesToSecretDataWithField(absl::string_view& serialized,
                                                 const Field& field, Struct& s);

  // Overwrites all fields to their default value (in case they are not
  // explicitly set by the input)
  void ClearAllFields(Struct& s);

  absl::Status permanent_error_;

  absl::btree_map<int, Field> fields_;
};

// Implementation details below ================================================

template <typename Struct>
ProtoParser<Struct>& ProtoParser<Struct>::AddUint32Field(
    int tag, uint32_t Struct::*value) {
  if (!permanent_error_.ok()) {
    return *this;
  }
  Field field;
  field.type = ProtoFieldType::kUint32;
  field.value = value;
  auto result = fields_.insert({tag, field});
  if (!result.second) {
    permanent_error_ = absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " already exists"));
    return *this;
  }
  return *this;
}

template <typename Struct>
ProtoParser<Struct>& ProtoParser<Struct>::AddBytesStringField(
    int tag, std::string Struct::*value) {
  if (!permanent_error_.ok()) {
    return *this;
  }
  Field field;
  field.type = ProtoFieldType::kBytesString;
  field.value = value;
  auto result = fields_.insert({tag, field});
  if (!result.second) {
    permanent_error_ = absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " already exists"));
    return *this;
  }
  return *this;
}

template <typename Struct>
ProtoParser<Struct>& ProtoParser<Struct>::AddBytesSecretDataField(
    int tag, util::SecretData Struct::*value, SecretKeyAccessToken token) {
  if (!permanent_error_.ok()) {
    return *this;
  }
  Field field;
  field.type = ProtoFieldType::kBytesSecretData;
  field.value = value;
  auto result = fields_.insert({tag, field});
  if (!result.second) {
    permanent_error_ = absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " already exists"));
    return *this;
  }
  return *this;
}

template <typename Struct>
absl::StatusOr<Struct> ProtoParser<Struct>::Parse(absl::string_view input) {
  if (!permanent_error_.ok()) {
    return permanent_error_;
  }
  permanent_error_ = absl::FailedPreconditionError("Parse called twice");
  Struct result;
  ClearAllFields(result);
  while (!input.empty()) {
    absl::StatusOr<std::pair<WireType, int>> wiretype_and_tag =
        ConsumeIntoWireTypeAndTag(input);
    if (!wiretype_and_tag.ok()) {
      return wiretype_and_tag.status();
    }
    if (wiretype_and_tag->first == WireType::kVarint) {
      absl::Status s =
          ConsumeVarintWithTag(input, wiretype_and_tag->second, result);
      if (!s.ok()) {
        return s;
      }
    } else if (wiretype_and_tag->first == WireType::kLengthDelimited) {
      absl::Status s = ConsumeLengthDelimitedWithTag(
          input, wiretype_and_tag->second, result);
      if (!s.ok()) {
        return s;
      }
    } else {
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported wire type ", wiretype_and_tag->first));
    }
  }
  return result;
}

template <typename Struct>
absl::Status ProtoParser<Struct>::ConsumeVarintWithTag(
    absl::string_view& serialized, int tag, Struct& s) {
  auto it = fields_.find(tag);
  if (it == fields_.end()) {
    return absl::InternalError(
        absl::StrCat("Tag ", tag, " not found in ConsumeVarintWithTag"));
  }
  if (it->second.type == ProtoFieldType::kUint32) {
    return ConsumeUint32WithField(serialized, it->second, s);
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Tag ", tag, " of unknown type for Varint"));
}

template <typename Struct>
absl::Status ProtoParser<Struct>::ConsumeUint32WithField(
    absl::string_view& serialized, const ProtoParser::Field& field, Struct& s) {
  absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
  if (!result.ok()) {
    return result.status();
  }
  s.*absl::get<uint32_t Struct::*>(field.value) = *result;
  return absl::OkStatus();
}

template <typename Struct>
absl::Status ProtoParser<Struct>::ConsumeLengthDelimitedWithTag(
    absl::string_view& serialized, int tag, Struct& s) {
  auto it = fields_.find(tag);
  if (it == fields_.end()) {
    return absl::InternalError(absl::StrCat(
        "Tag ", tag, " not found in ConsumeLengthDelimitedWithTag"));
  }
  if (it->second.type == ProtoFieldType::kBytesString) {
    return ConsumeBytesToStringWithField(serialized, it->second, s);
  }
  if (it->second.type == ProtoFieldType::kBytesSecretData) {
    return ConsumeBytesToSecretDataWithField(serialized, it->second, s);
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Tag ", tag, " of unknown type for LengthDelimited"));
}

template <typename Struct>
absl::Status ProtoParser<Struct>::ConsumeBytesToStringWithField(
    absl::string_view& serialized, const Field& field, Struct& s) {
  absl::StatusOr<absl::string_view> result_view =
      ConsumeBytesReturnStringView(serialized);
  if (!result_view.ok()) {
    return result_view.status();
  }
  s.*absl::get<std::string Struct::*>(field.value) = std::string(*result_view);
  return absl::OkStatus();
}

template <typename Struct>
absl::Status ProtoParser<Struct>::ConsumeBytesToSecretDataWithField(
    absl::string_view& serialized, const Field& field, Struct& s) {
  absl::StatusOr<absl::string_view> result_view =
      ConsumeBytesReturnStringView(serialized);
  if (!result_view.ok()) {
    return result_view.status();
  }
  s.*absl::get<util::SecretData Struct::*>(field.value) =
      util::SecretDataFromStringView(*result_view);
  return absl::OkStatus();
}

template <typename Struct>
void ProtoParser<Struct>::ClearAllFields(Struct& s) {
  for (auto& pair : fields_) {
    switch (pair.second.type) {
      case ProtoFieldType::kUint32:
        s.*absl::get<uint32_t Struct::*>(pair.second.value) = 0;
        break;
      case ProtoFieldType::kBytesString:
        (s.*absl::get<std::string Struct::*>(pair.second.value)).clear();
        break;
      case ProtoFieldType::kBytesSecretData:
        (s.*
         absl::get<crypto::tink::util::SecretData Struct::*>(pair.second.value))
            .clear();
        break;
    }
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_H_
