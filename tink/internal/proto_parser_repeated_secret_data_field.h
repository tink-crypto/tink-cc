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
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

template <typename Struct>
class RepeatedSecretDataField : public Field<Struct> {
 public:
  explicit RepeatedSecretDataField(
      int field_number,
      std::vector<crypto::tink::util::SecretData> Struct::* data)
      : data_(data), field_number_(field_number) {}
  // Not copyable and movable.
  RepeatedSecretDataField(const RepeatedSecretDataField&) = delete;
  RepeatedSecretDataField& operator=(const RepeatedSecretDataField&) = delete;
  RepeatedSecretDataField(RepeatedSecretDataField&&) noexcept = delete;
  RepeatedSecretDataField& operator=(
      RepeatedSecretDataField&&) noexcept = delete;

  void ClearMember(Struct& s) const override {
    (s.*data_).clear();
  }

  absl::Status ConsumeIntoMember(ParsingState& parsing_state,
                                 Struct& s) const override {
    absl::StatusOr<uint32_t> length = ConsumeVarintForSize(parsing_state);
    if (!length.ok()) {
      return length.status();
    }
    if (*length > parsing_state.RemainingData().size()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Length ", *length, " exceeds remaining input size ",
                       parsing_state.RemainingData().size()));
    }
    absl::string_view data = parsing_state.RemainingData().substr(0, *length);
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
    parsing_state.Advance(*length);
    (s.*data_).push_back(crypto::tink::util::SecretDataFromStringView(data));
#else
    CallWithCoreDumpProtection([&]() {
      absl::crc32c_t crc = parsing_state.AdvanceAndGetCrc(*length);
      (s.*data_).push_back(crypto::tink::util::SecretData(data, crc));
    });
#endif
    return absl::OkStatus();
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
  int GetFieldNumber() const override { return field_number_; }

  absl::Status SerializeWithTagInto(SerializationState& serialization_state,
                                    const Struct& values) const override {
    for (const crypto::tink::util::SecretData& secret_data : values.*data_) {
      absl::Status status = SerializeWireTypeAndFieldNumber(
          GetWireType(), GetFieldNumber(), serialization_state);
      if (!status.ok()) {
        return status;
      }
      absl::string_view data_view = util::SecretDataAsStringView(secret_data);
      absl::Status s = SerializeVarint(data_view.size(), serialization_state);
      if (!s.ok()) {
        return s;
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

  size_t GetSerializedSizeIncludingTag(const Struct& values) const override {
    size_t total_size = 0;
    for (const crypto::tink::util::SecretData& secret_data : values.*data_) {
      size_t cur_size = secret_data.size();
      total_size +=
          WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
          VarintLength(cur_size) + cur_size;
    }
    return total_size;
  }

 private:
  std::vector<crypto::tink::util::SecretData> Struct::* data_;
  int field_number_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_REPEATED_SECRET_DATA_FIELD_H_
