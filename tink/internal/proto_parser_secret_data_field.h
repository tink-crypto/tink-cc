// Copyright 2025 Google LLC
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
#ifndef TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_OWNING_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_OWNING_FIELD_H_

#include <cstddef>
#include <cstdint>

#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// SecretDataField is a Field that owns a SecretData.
class SecretDataField final : public OwningField {
 public:
  explicit SecretDataField(uint32_t field_number,
                           ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : OwningField(field_number, WireType::kLengthDelimited),
        options_(options) {}
  // Copyable and movable.
  SecretDataField(const SecretDataField&) = default;
  SecretDataField& operator=(const SecretDataField&) = default;
  SecretDataField(SecretDataField&&) noexcept = default;
  SecretDataField& operator=(SecretDataField&&) noexcept = default;

  void Clear() override { value_ = SecretData(); }
  bool ConsumeIntoMember(ParsingState& serialized) override {
    absl::StatusOr<uint32_t> length = ConsumeVarintForSize(serialized);
    if (!length.ok()) {
      return false;
    }
    if (*length > serialized.RemainingData().size()) {
      return false;
    }
    absl::string_view secret_bytes =
        serialized.RemainingData().substr(0, *length);
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
    value_ = util::SecretDataFromStringView(secret_bytes);
    serialized.Advance(*length);
#else
    value_ = CallWithCoreDumpProtection([&]() {
      absl::crc32c_t crc = serialized.AdvanceAndGetCrc(*length);
      return SecretData(secret_bytes, crc);
    });
#endif
    return true;
  }
  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    if (value_.empty() && options_ != ProtoFieldOptions::kAlwaysSerialize) {
      return absl::OkStatus();
    }
    if (absl::Status result = SerializeWireTypeAndFieldNumber(
            WireType::kLengthDelimited, FieldNumber(), out);
        !result.ok()) {
      return result;
    }
    if (absl::Status result = SerializeVarint(value_.size(), out);
        !result.ok()) {
      return result;
    }
    absl::string_view data_view = util::SecretDataAsStringView(value_);
    if (out.GetBuffer().size() < data_view.size()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Output buffer too small: ", out.GetBuffer().size(),
                       " < ", data_view.size()));
    }
    SafeMemCopy(out.GetBuffer().data(), data_view.data(), data_view.size());
#ifdef TINK_CPP_SECRET_DATA_IS_STD_VECTOR
    out.Advance(data_view.size());
#else
    CallWithCoreDumpProtection(
        [&]() { out.AdvanceWithCrc(data_view.size(), value_.GetCrc32c()); });
#endif
    return absl::OkStatus();
  }
  size_t GetSerializedSizeIncludingTag() const override {
    if (value_.empty() && options_ != ProtoFieldOptions::kAlwaysSerialize) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(WireType::kLengthDelimited,
                                        FieldNumber()) +
           VarintLength(value_.size()) + value_.size();
  }

  const SecretData& value() const { return value_; }
  SecretData* mutable_value() { return &value_; }

 private:
  SecretData value_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_OWNING_FIELD_H_
