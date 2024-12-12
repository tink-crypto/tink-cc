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

#ifndef TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_WITH_CRC_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_WITH_CRC_FIELD_H_

#include <cstddef>
#include <cstdint>

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
#include "tink/internal/secret_data_with_crc.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

template <typename Struct>
class SecretDataWithCrcField : public Field<Struct> {
 public:
  explicit SecretDataWithCrcField(
      int field_number, SecretDataWithCrc Struct::*data)
      : data_(data), field_number_(field_number) {}
  // Not copyable and movable.
  SecretDataWithCrcField(const SecretDataWithCrcField&) = delete;
  SecretDataWithCrcField& operator=(const SecretDataWithCrcField&) = delete;
  SecretDataWithCrcField(SecretDataWithCrcField&&) noexcept = delete;
  SecretDataWithCrcField& operator=(SecretDataWithCrcField&&) noexcept = delete;

  void ClearMember(Struct& s) const override {
    s.*data_ = SecretDataWithCrc();
  }

  absl::Status ConsumeIntoMember(ParsingState& parsing_state,
                                 Struct& s) const override {
    if (!parsing_state.HasCrc()) {
      // We currently disallow parsing if the parsing_state doesn't
      // have CRC maintenance. This means one cannot serialize a struct which
      // has SecretDataWithCrc fields without CRC computation. It's unclear if
      // this is the best option. I hope it increases the probability of finding
      // bugs. However, if it turns out that often it would be a useful feature
      // to allow this, we can change it.
      return absl::InvalidArgumentError(
          "Can only serialize parse as SecretDataWithCrcField when CRC is "
          "maintained");
    }
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
    util::SecretValue<absl::crc32c_t> crc =
        parsing_state.AdvanceAndGetCrc(*length);
    s.*data_ = SecretDataWithCrc(data, crc);
    return absl::OkStatus();
  }

  bool RequiresSerialization(const Struct& values) const override {
    return (values.*data_).size() > 0;
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
  int GetFieldNumber() const override { return field_number_; }

 protected:
  absl::Status SerializeInto(SerializationState& serialization_state,
                             const Struct& values) const override {
    if (!serialization_state.HasCrc()) {
      // We currently disallow serialization if the serialization_state doesn't
      // have CRC maintenance. This means one cannot serialize a struct which
      // has SecretDataWithCrc fields without CRC computation. It's unclear if
      // this is the best option. I hope it increases the probability of finding
      // bugs. However, if it turns out that often it would be a useful feature
      // to allow this, we can change it.
      return absl::InvalidArgumentError(
          "Can only serialize parse as SecretDataWithCrcField when CRC is "
          "maintained");
    }
    absl::string_view data_view = (values.*data_).AsStringView();
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
    // Note: we checked serialization_state.HasCrc() above.
    CallWithCoreDumpProtection([&]() {
      serialization_state.AdvanceWithCrc(data_view.size(),
                                         (values.*data_).GetCrc32c());
    });
    return absl::OkStatus();
  }

  size_t GetSerializedSize(const Struct& values) const override {
    size_t size = (values.*data_).AsStringView().size();
    return VarintLength(size) + size;
  }

 private:
  SecretDataWithCrc Struct::*data_;
  int field_number_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_WITH_CRC_FIELD_H_
