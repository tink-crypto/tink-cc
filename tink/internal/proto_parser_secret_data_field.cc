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
#include "tink/internal/proto_parser_secret_data_field.h"

#include <cstddef>
#include <cstdint>
#include <optional>

#include "absl/base/no_destructor.h"
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
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

SecretDataField::SecretDataField(uint32_t field_number,
                                 ProtoFieldOptions options)
    : Field(field_number, WireType::kLengthDelimited), options_(options) {
  Clear();
}

void SecretDataField::Clear() {
  if (options_ == ProtoFieldOptions::kAlwaysPresent ||
      options_ == ProtoFieldOptions::kImplicit) {
    value_.emplace();
  } else {
    value_.reset();
  }
}

bool SecretDataField::RequiresSerialization() const {
  switch (options_) {
    case ProtoFieldOptions::kExplicit:
      // With kExplicit, value_ is serialized only if it has a value.
      return value_.has_value();
    case ProtoFieldOptions::kAlwaysPresent:
      // With kAlwaysPresent, value_ is always set and is always serialized.
      return true;
    case ProtoFieldOptions::kImplicit:
      // With kImplicit, value_ is always set and is serialized only if it is
      // not equal to the default value.
      return !util::SecretDataEquals(*value_, default_value());
    default:
      ABSL_DCHECK(false) << "Unknown options: " << static_cast<int>(options_);
      return false;
  }
}

bool SecretDataField::ConsumeIntoMember(ParsingState& serialized) {
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
bool SecretDataField::SerializeWithTagInto(
    SerializationState& out) const {
  if (!RequiresSerialization()) {
    return true;
  }
  if (absl::Status result = SerializeWireTypeAndFieldNumber(
          WireType::kLengthDelimited, FieldNumber(), out);
      !result.ok()) {
    return false;
  }
  const SecretData& value = value_.value();
  if (absl::Status result = SerializeVarint(value.size(), out); !result.ok()) {
    return false;
  }
  absl::string_view data_view = util::SecretDataAsStringView(value);
  if (out.GetBuffer().size() < data_view.size()) {
    return false;
  }
  SafeMemCopy(out.GetBuffer().data(), data_view.data(), data_view.size());
#ifdef TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  out.Advance(data_view.size());
#else
  CallWithCoreDumpProtection(
      [&]() { out.AdvanceWithCrc(data_view.size(), value.GetCrc32c()); });
#endif
  return true;
}
size_t SecretDataField::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  const size_t value_size = value_->size();
  return WireTypeAndFieldNumberLength(WireType::kLengthDelimited,
                                      FieldNumber()) +
         VarintLength(value_size) + value_size;
}

bool SecretDataField::has_value() const { return value_.has_value(); }

const SecretData& SecretDataField::value() const {
  if (!value_.has_value()) {
    return default_value();
  }
  return *value_;
}

SecretData* SecretDataField::mutable_value() {
  if (!value_.has_value()) {
    value_.emplace();
  }
  return &value_.value();
}

const SecretData& SecretDataField::default_value() const {
  static const absl::NoDestructor<SecretData> kDefaultSecretData;
  return *kDefaultSecretData;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
