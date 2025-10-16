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
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/crc/crc32c.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message_field.h"
#include "tink/internal/proto_parser_message_field_with_presence.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_presence_fields.h"
#include "tink/internal/proto_parser_repeated_message_field.h"
#include "tink/internal/proto_parser_repeated_secret_data_field.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parser_uint64_field.h"
#include "tink/internal/proto_parsing_low_level_parser.h"
#include "tink/internal/secret_buffer.h"
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
//     .AddBytesSecretDataField(kKeyTag, &AesGcmKeyStruct::key)
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

  // Parses the input and returns the struct together with the CRC of the input.
  // For fields which support CRCs (e.g. SecretData), the CRC of the field is
  // consistent with the CRC of the output. This enables end-to-end coverage of
  // the CRC computation: if the returned CRC is known to be correct, the CRCs
  // of the individual fields must also be correct.
  absl::StatusOr<
      std::pair<Struct, crypto::tink::util::SecretValue<absl::crc32c_t>>>
  ParseWithCrc(absl::string_view input) const;

  absl::StatusOr<std::string> SerializeIntoString(const Struct& s) const;
  // Serializes the input and returns the serialized value. For fields which
  // support CRCs (e.g. SecretDataField), the data of the field is not
  // considered when computing the overall CRC. Instead, only the CRC of the
  // field is used to compute the result. This enables end-to-end coverage of
  // the CRC computation: if the returned CRC is correct, the CRCs of the fields
  // must have been corrects.
  absl::StatusOr<SecretData> SerializeIntoSecretData(const Struct& s) const;

 private:
  template <typename AnyStruct>
  friend class ProtoParserBuilder;
  explicit ProtoParser(
      absl::btree_map<int, std::unique_ptr<proto_parsing::Field<Struct>>>
          fields)
      : low_level_parser_(std::move(fields)) {}

  proto_parsing::LowLevelParser<Struct> low_level_parser_;
};

template <typename Struct>
class ProtoParserBuilder {
 public:
  ProtoParserBuilder() = default;
  // Not movable or copyable.
  ProtoParserBuilder(const ProtoParserBuilder&) = delete;
  ProtoParserBuilder& operator=(const ProtoParserBuilder&) = delete;

  ProtoParserBuilder& AddUint32Field(
      int tag, uint32_t Struct::* value,
      ProtoFieldOptions options = ProtoFieldOptions::kNone) {
    fields_.push_back(absl::make_unique<proto_parsing::Uint32Field<Struct>>(
        tag, value, options));
    return *this;
  }

  // Adds a uint32_t field for which field presence can be detected. See
  // https://protobuf.dev/programming-guides/field_presence/
  ProtoParserBuilder& AddOptionalUint32Field(
      int tag, absl::optional<uint32_t> Struct::* value) {
    fields_.push_back(
        absl::make_unique<proto_parsing::Uint32FieldWithPresence<Struct>>(
            tag, value));
    return *this;
  }

  ProtoParserBuilder& AddUint64Field(int tag, uint64_t Struct::* value) {
    fields_.push_back(
        absl::make_unique<proto_parsing::Uint64Field<Struct>>(tag, value));
    return *this;
  }

  // Adds an enum field. Note that in C++ one needs to be careful with casting
  // to an enum: [expr.static.cast/10] states that one needs to check dcl.enum
  // to find the correct range of an enum to ensure the static cast is valid.
  // By [dcl.enum/7&8] for enums without underlying type, only the enums listed
  // are valid. Hence the user needs to provide "is_valid" to ensure validity
  // when casting.
  template <typename T>
  ProtoParserBuilder& AddEnumField(
      int tag, T Struct::* value, std::function<bool(uint32_t)> is_valid,
      T default_value = {},
      ProtoFieldOptions options = ProtoFieldOptions::kNone) {
    fields_.push_back(absl::make_unique<proto_parsing::EnumField<Struct, T>>(
        tag, value, std::move(is_valid), default_value, options));
    return *this;
  }
  ProtoParserBuilder& AddBytesStringField(
      int tag, std::string Struct::* value,
      ProtoFieldOptions options = ProtoFieldOptions::kNone) {
    fields_.push_back(
        absl::make_unique<proto_parsing::BytesField<Struct, std::string>>(
            tag, value, options));
    return *this;
  }
  // Adds a Bytes field which maps to a string view. Note: when parsing into a
  // string_view field, no copy is made. Instead, the resulting string_view
  // field will point into the original string/SecretData.
  ProtoParserBuilder& AddBytesStringViewField(
      int tag, absl::string_view Struct::* value) {
    fields_.push_back(
        absl::make_unique<proto_parsing::BytesField<Struct, absl::string_view>>(
            tag, value));
    return *this;
  }

  ProtoParserBuilder& AddBytesSecretDataField(
      int tag, SecretData Struct::* value,
      ProtoFieldOptions options = ProtoFieldOptions::kNone) {
    fields_.push_back(absl::make_unique<proto_parsing::SecretDataField<Struct>>(
        tag, value, options));
    return *this;
  }

  ProtoParserBuilder& AddRepeatedBytesSecretDataField(
      int tag, std::vector<SecretData> Struct::* value) {
    fields_.push_back(
        absl::make_unique<proto_parsing::RepeatedSecretDataField<Struct>>(
            tag, value));
    return *this;
  }

  template <typename InnerStruct>
  ProtoParserBuilder<Struct>& AddMessageField(
      int tag, InnerStruct Struct::* value,
      ProtoParser<InnerStruct> inner_parser) {
    fields_.push_back(
        absl::make_unique<proto_parsing::MessageField<Struct, InnerStruct>>(
            tag, value, std::move(inner_parser.low_level_parser_)));
    return *this;
  }

  template <typename InnerStruct>
  ProtoParserBuilder<Struct>& AddMessageFieldWithPresence(
      int tag, absl::optional<InnerStruct> Struct::* value,
      ProtoParser<InnerStruct> inner_parser) {
    fields_.push_back(
        absl::make_unique<
            proto_parsing::MessageFieldWithPresence<Struct, InnerStruct>>(
            tag, value, std::move(inner_parser.low_level_parser_)));
    return *this;
  }

  template <typename InnerStruct>
  ProtoParserBuilder<Struct>& AddRepeatedMessageField(
      int tag, std::vector<InnerStruct> Struct::* value,
      ProtoParser<InnerStruct> inner_parser) {
    fields_.push_back(absl::make_unique<
                      proto_parsing::RepeatedMessageField<Struct, InnerStruct>>(
        tag, value, std::move(inner_parser.low_level_parser_)));
    return *this;
  }

  ProtoParserBuilder<Struct>& AddField(
      std::unique_ptr<proto_parsing::Field<Struct>> field) {
    fields_.push_back(std::move(field));
    return *this;
  }

  absl::StatusOr<ProtoParser<Struct>> Build();
  ProtoParser<Struct> BuildOrDie();

 private:
  std::vector<std::unique_ptr<proto_parsing::Field<Struct>>> fields_;
};

// Implementation details below ================================================

template <typename Struct>
absl::StatusOr<Struct> ProtoParser<Struct>::Parse(
    absl::string_view input) const {
  Struct result;
  low_level_parser_.ClearAllFields(result);
  proto_parsing::ParsingState parsing_state =
      proto_parsing::ParsingState(input);
  bool parsed = low_level_parser_.ConsumeIntoAllFields(parsing_state, result);
  if (!parsed) {
    return absl::InvalidArgumentError("Parsing input failed");
  }
  return result;
}

template <typename Struct>
absl::StatusOr<std::pair<Struct, util::SecretValue<absl::crc32c_t>>>
ProtoParser<Struct>::ParseWithCrc(absl::string_view input) const {
  std::pair<Struct, crypto::tink::util::SecretValue<absl::crc32c_t>> result;
  result.second.value() = absl::crc32c_t{};

  low_level_parser_.ClearAllFields(result.first);
  proto_parsing::ParsingState parsing_state =
      proto_parsing::ParsingState(input, &result.second.value());
  bool parsed =
      low_level_parser_.ConsumeIntoAllFields(parsing_state, result.first);
  if (!parsed) {
    return absl::InvalidArgumentError("Parsing input failed");
  }
  return result;
}

template <typename Struct>
absl::StatusOr<std::string> ProtoParser<Struct>::SerializeIntoString(
    const Struct& s) const {
  size_t size = low_level_parser_.GetSerializedSize(s);
  std::string result;
  result.resize(size);
  proto_parsing::SerializationState serialization_state =
      proto_parsing::SerializationState(absl::MakeSpan(result));
  absl::Status status = low_level_parser_.SerializeInto(serialization_state, s);
  if (!status.ok()) {
    return status;
  }
  if (!serialization_state.GetBuffer().empty()) {
    return absl::InternalError("Resulting buffer expected to be empty");
  }
  return result;
}

template <typename Struct>
absl::StatusOr<SecretData> ProtoParser<Struct>::SerializeIntoSecretData(
    const Struct& s) const {
  size_t size = low_level_parser_.GetSerializedSize(s);
  crypto::tink::internal::SecretBuffer result_data;
  result_data.resize(size);
  absl::Span<char> buffer = absl::MakeSpan(
      reinterpret_cast<char*>(result_data.data()), result_data.size());
  return CallWithCoreDumpProtection([&]() -> absl::StatusOr<SecretData> {
    absl::crc32c_t result_crc = absl::crc32c_t(0);
    proto_parsing::SerializationState serialization_state =
        proto_parsing::SerializationState(buffer, &result_crc);
    absl::Status status =
        low_level_parser_.SerializeInto(serialization_state, s);
    if (!status.ok()) {
      return status;
    }
    if (!serialization_state.GetBuffer().empty()) {
      return absl::InternalError("Resulting buffer expected to be empty");
    }
#ifdef TINK_CPP_SECRET_DATA_IS_STD_VECTOR
    return util::SecretDataFromStringView(result_data.AsStringView());
#else
    return SecretData(std::move(result_data), result_crc);
#endif
  });
}

template <typename Struct>
absl::StatusOr<ProtoParser<Struct>> ProtoParserBuilder<Struct>::Build() {
  absl::btree_map<int, std::unique_ptr<proto_parsing::Field<Struct>>> fields;
  for (auto& field : fields_) {
    auto it = fields.find(field->GetFieldNumber());
    if (it != fields.end()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Duplicate field ", field->GetFieldNumber()));
    }
    fields.emplace(field->GetFieldNumber(), std::move(field));
  }
  return ProtoParser<Struct>(std::move(fields));
}

template <typename Struct>
ProtoParser<Struct> ProtoParserBuilder<Struct>::BuildOrDie() {
  absl::StatusOr<ProtoParser<Struct>> result = Build();
  CHECK_OK(result);
  return *std::move(result);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_H_
