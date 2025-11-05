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

#ifndef TINK_INTERNAL_PROTO_PARSER_REPEATED_SECRET_DATA_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_REPEATED_SECRET_DATA_FIELD_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// RepeatedSecretDataField is a Field that owns a vector of SecretData.
// It is used to represent a repeated field of SecretData in a proto message.
class RepeatedSecretDataField : public Field {
 public:
  explicit RepeatedSecretDataField(int field_number)
      : Field(field_number, WireType::kLengthDelimited) {}

  // Copyable and movable.
  RepeatedSecretDataField(const RepeatedSecretDataField&) = default;
  RepeatedSecretDataField& operator=(const RepeatedSecretDataField&) = default;
  RepeatedSecretDataField(RepeatedSecretDataField&&) noexcept = default;
  RepeatedSecretDataField& operator=(RepeatedSecretDataField&&) noexcept =
      default;

  void Clear() override { value_.clear(); }

  bool ConsumeIntoMember(ParsingState& parsing_state) override {
    absl::StatusOr<uint32_t> length = ConsumeVarintForSize(parsing_state);
    if (!length.ok()) {
      return false;
    }
    if (*length > parsing_state.RemainingData().size()) {
      return false;
    }
    absl::string_view data = parsing_state.RemainingData().substr(0, *length);
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
    parsing_state.Advance(*length);
    value_.push_back(crypto::tink::util::SecretDataFromStringView(data));
#else
    CallWithCoreDumpProtection([&]() {
      absl::crc32c_t crc = parsing_state.AdvanceAndGetCrc(*length);
      value_.push_back(SecretData(data, crc));
    });
#endif
    return true;
  }

  absl::Status SerializeWithTagInto(
      SerializationState& serialization_state) const override {
    for (const SecretData& secret_data : value_) {
      if (absl::Status result = SerializeWireTypeAndFieldNumber(
              WireType::kLengthDelimited, FieldNumber(), serialization_state);
          !result.ok()) {
        return result;
      }
      absl::string_view data_view = util::SecretDataAsStringView(secret_data);

      if (absl::Status result =
              SerializeVarint(data_view.size(), serialization_state);
          !result.ok()) {
        return result;
      }
      if (serialization_state.GetBuffer().size() < data_view.size()) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Output buffer too small: ", serialization_state.GetBuffer().size(),
            " < ", data_view.size()));
      }
      SafeMemCopy(serialization_state.GetBuffer().data(), data_view.data(),
                  data_view.size());
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
      serialization_state.Advance(data_view.size());
#else
      CallWithCoreDumpProtection([&]() {
        serialization_state.AdvanceWithCrc(data_view.size(),
                                           secret_data.GetCrc32c());
      });
#endif
    }
    return absl::OkStatus();
  }
  size_t GetSerializedSizeIncludingTag() const override {
    size_t total_size = 0;
    for (const SecretData& secret_data : value_) {
      size_t cur_size = secret_data.size();
      total_size += WireTypeAndFieldNumberLength(WireType::kLengthDelimited,
                                                 FieldNumber()) +
                    VarintLength(cur_size) + cur_size;
    }
    return total_size;
  }

  const std::vector<SecretData>& value() const { return value_; }
  std::vector<SecretData>& value() { return value_; }

 private:
  std::vector<SecretData> value_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_REPEATED_SECRET_DATA_FIELD_H_
