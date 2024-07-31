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
#include <memory>
#include <string>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

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
// state. Fields can be added in any order.
template <typename Struct>
class ProtoParser {
 public:
  ProtoParser() = default;
  // Not movable or copyable.
  ProtoParser(const ProtoParser&) = delete;
  ProtoParser& operator=(const ProtoParser&) = delete;

  ProtoParser& AddUint32Field(int tag, uint32_t Struct::*value) {
    return AddField(absl::make_unique<Uint32Field<Struct>>(tag, value));
  }
  ProtoParser& AddBytesStringField(int tag, std::string Struct::*value) {
    return AddField(absl::make_unique<StringBytesField<Struct>>(tag, value));
  }
  ProtoParser& AddBytesSecretDataField(
      int tag, crypto::tink::util::SecretData Struct::*value,
      crypto::tink::SecretKeyAccessToken token) {
    return AddField(
        absl::make_unique<SecretDataBytesField<Struct>>(tag, value));
  }

  absl::StatusOr<Struct> Parse(absl::string_view input) const;

 private:
  ProtoParser& AddField(std::unique_ptr<Field<Struct>> field) {
    if (!permanent_error_.ok()) {
      return *this;
    }
    int tag = field->GetTag();
    auto result = fields_.insert({tag, std::move(field)});
    if (!result.second) {
      permanent_error_ = absl::InvalidArgumentError(
          absl::StrCat("Tag ", tag, " already exists"));
      return *this;
    }
    return *this;
  }

  // Overwrites all fields to their default value (in case they are not
  // explicitly set by the input)
  void ClearAllFields(Struct& s) const;

  absl::Status permanent_error_;

  absl::btree_map<int, std::unique_ptr<Field<Struct>>> fields_;
};

// Implementation details below ================================================

template <typename Struct>
absl::StatusOr<Struct> ProtoParser<Struct>::Parse(
    absl::string_view input) const {
  if (!permanent_error_.ok()) {
    return permanent_error_;
  }
  Struct result;
  ClearAllFields(result);
  while (!input.empty()) {
    absl::StatusOr<std::pair<WireType, int>> wiretype_and_tag =
        ConsumeIntoWireTypeAndTag(input);
    if (!wiretype_and_tag.ok()) {
      return wiretype_and_tag.status();
    }
    auto it = fields_.find(wiretype_and_tag->second);
    if (it == fields_.end()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Unknown field ", wiretype_and_tag->second));
    }
    if (it->second->GetWireType() != wiretype_and_tag->first) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Wrong wire type in serialization ", wiretype_and_tag->first));
    }
    absl::Status status = it->second->ConsumeIntoMember(input, result);
    if (!status.ok()) {
      return status;
    }
  }
  return result;
}

template <typename Struct>
void ProtoParser<Struct>::ClearAllFields(Struct& s) const {
  for (auto& pair : fields_) {
    pair.second->ClearMember(s);
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_H_
