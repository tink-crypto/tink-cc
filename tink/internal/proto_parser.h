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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
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
// absl::StatusOr<ProtoParser<AesGcmKeyStruct>> parser = ProtoParserBuilder()
//     .AddUint32Field(kVersionNumberTag, &AesGcmKeyStruct::version_number)
//     .AddUint32Field(kKeySizeTag, &AesGcmKeyStruct::key_size)
//     .AddBytesSecretDataField(kKeyTag,
//                              &AesGcmKeyStruct::key,
//                              secret_key_access_token)
//     .Build();
// if (!parser.ok()) { /* handle error */ }
//
// Then, to parse a serialized proto, we can do:
// absl::StatusOr<AesGcmKeyStruct> parsed = parser->Parse(serialized_proto);
//
// To serialize a struct back into a string, we can do:
// absl::StatusOr<std::string> serialized = parser->SerializeIntoString(struct);
//
// If the return value of Parse is an error, variables are in an unspecified
// state. Fields can be added in any order.
template <typename Struct>
class ProtoParserBuilder;

template <typename Struct>
class ProtoParser {
 public:
  // Movable, but not copyable.
  ProtoParser(const ProtoParser&) = delete;
  ProtoParser& operator=(const ProtoParser&) = delete;
  ProtoParser(ProtoParser&&) noexcept = default;
  ProtoParser& operator=(ProtoParser&&) noexcept = default;

  absl::StatusOr<Struct> Parse(absl::string_view input) const;

  absl::StatusOr<std::string> SerializeIntoString(const Struct& s) const;
  absl::StatusOr<crypto::tink::util::SecretData> SerializeIntoSecretData(
      const Struct& s) const;

 private:
  friend class ProtoParserBuilder<Struct>;
  explicit ProtoParser(
      absl::btree_map<int, std::unique_ptr<Field<Struct>>> fields)
      : fields_(std::move(fields)) {}

  // Overwrites all fields to their default value (in case they are not
  // explicitly set by the input)
  void ClearAllFields(Struct& s) const;
  size_t GetSerializedSize(const Struct& s) const;
  absl::Status SerializeIntoBuffer(const Struct& s,
                                   absl::Span<char>& out) const;

  absl::btree_map<int, std::unique_ptr<Field<Struct>>> fields_;
};

template <typename Struct>
class ProtoParserBuilder {
 public:
  ProtoParserBuilder() = default;
  // Not movable or copyable.
  ProtoParserBuilder(const ProtoParserBuilder&) = delete;
  ProtoParserBuilder& operator=(const ProtoParserBuilder&) = delete;

  ProtoParserBuilder& AddUint32Field(int tag, uint32_t Struct::*value) {
    fields_.push_back(absl::make_unique<Uint32Field<Struct>>(tag, value));
    return *this;
  }
  ProtoParserBuilder& AddBytesStringField(int tag, std::string Struct::*value) {
    fields_.push_back(absl::make_unique<StringBytesField<Struct>>(tag, value));
    return *this;
  }
  ProtoParserBuilder& AddBytesSecretDataField(
      int tag, crypto::tink::util::SecretData Struct::*value,
      crypto::tink::SecretKeyAccessToken token) {
    fields_.push_back(
        absl::make_unique<SecretDataBytesField<Struct>>(tag, value));
    return *this;
  }
  absl::StatusOr<ProtoParser<Struct>> Build();

 private:
  std::vector<std::unique_ptr<Field<Struct>>> fields_;
};

// Implementation details below ================================================

template <typename Struct>
absl::StatusOr<Struct> ProtoParser<Struct>::Parse(
    absl::string_view input) const {
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
absl::StatusOr<std::string> ProtoParser<Struct>::SerializeIntoString(
    const Struct& s) const {
  size_t size = GetSerializedSize(s);
  std::string result;
  result.resize(size);
  absl::Span<char> output_buffer = absl::MakeSpan(result);
  absl::Status status = SerializeIntoBuffer(s, output_buffer);
  if (!status.ok()) {
    return status;
  }
  if (!output_buffer.empty()) {
    return absl::InternalError("Resulting buffer expected to be empty");
  }
  return result;
}

template <typename Struct>
absl::StatusOr<crypto::tink::util::SecretData>
ProtoParser<Struct>::SerializeIntoSecretData(const Struct& s) const {
  size_t size = GetSerializedSize(s);
  crypto::tink::util::SecretData result;
  result.resize(size);
  absl::Span<char> output_buffer =
      absl::MakeSpan(reinterpret_cast<char*>(result.data()), result.size());
  absl::Status status = SerializeIntoBuffer(s, output_buffer);
  if (!status.ok()) {
    return status;
  }
  if (!output_buffer.empty()) {
    return absl::InternalError("Resulting buffer expected to be empty");
  }
  return result;
}

template <typename Struct>
void ProtoParser<Struct>::ClearAllFields(Struct& s) const {
  for (auto& pair : fields_) {
    pair.second->ClearMember(s);
  }
}

template <typename Struct>
size_t ProtoParser<Struct>::GetSerializedSize(const Struct& s) const {
  size_t result = 0;
  for (const auto& pair : fields_) {
    if (pair.second->RequiresSerialization(s)) {
      result += WireTypeAndTagLength(pair.second->GetWireType(), pair.first);
      result += pair.second->GetSerializedSize(s);
    }
  }
  return result;
}

template <typename Struct>
absl::Status ProtoParser<Struct>::SerializeIntoBuffer(
    const Struct& s, absl::Span<char>& out) const {
  for (const auto& pair : fields_) {
    if (pair.second->RequiresSerialization(s)) {
      absl::Status status =
          SerializeWireTypeAndTag(pair.second->GetWireType(), pair.first, out);
      if (!status.ok()) {
        return status;
      }
      status = pair.second->SerializeInto(out, s);
      if (!status.ok()) {
        return status;
      }
    }
  }
  return absl::OkStatus();
}

template <typename Struct>
absl::StatusOr<ProtoParser<Struct>> ProtoParserBuilder<Struct>::Build() {
  absl::btree_map<int, std::unique_ptr<Field<Struct>>> fields;
  for (auto& field : fields_) {
    auto it = fields.find(field->GetTag());
    if (it != fields.end()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Duplicate field ", field->GetTag()));
    }
    fields.emplace(field->GetTag(), std::move(field));
  }
  return ProtoParser<Struct>(std::move(fields));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_H_
