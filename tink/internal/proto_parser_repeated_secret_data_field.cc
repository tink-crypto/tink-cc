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

#include "tink/internal/proto_parser_repeated_secret_data_field.h"

#include <cstddef>
#include <cstdint>

#include "absl/crc/crc32c.h"
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

RepeatedSecretDataField::RepeatedSecretDataField(int field_number)
    : Field(field_number, WireType::kLengthDelimited) {}

bool RepeatedSecretDataField::ConsumeIntoMember(ParsingState& parsing_state) {
  uint32_t length;
  if (!ConsumeVarintForSize(parsing_state, length)) {
    return false;
  }
  if (length > parsing_state.RemainingData().size()) {
    return false;
  }
  absl::string_view data = parsing_state.RemainingData().substr(0, length);
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  parsing_state.Advance(length);
  value_.push_back(crypto::tink::util::SecretDataFromStringView(data));
#else
  CallWithCoreDumpProtection([&]() {
    absl::crc32c_t crc = parsing_state.AdvanceAndGetCrc(length);
    value_.push_back(SecretData(data, crc));
  });
#endif
  return true;
}

bool RepeatedSecretDataField::SerializeWithTagInto(
    SerializationState& serialization_state) const {
  for (const SecretData& secret_data : value_) {
    if (!SerializeWireTypeAndFieldNumber(WireType::kLengthDelimited,
                                         FieldNumber(), serialization_state)) {
      return false;
    }
    absl::string_view data_view = util::SecretDataAsStringView(secret_data);

    if (!SerializeVarint(data_view.size(), serialization_state)) {
      return false;
    }
    if (serialization_state.GetBuffer().size() < data_view.size()) {
      return false;
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
  return true;
}

size_t RepeatedSecretDataField::GetSerializedSizeIncludingTag() const {
  size_t total_size = 0;
  for (const SecretData& secret_data : value_) {
    size_t cur_size = secret_data.size();
    total_size += WireTypeAndFieldNumberLength(WireType::kLengthDelimited,
                                               FieldNumber()) +
                  VarintLength(cur_size) + cur_size;
  }
  return total_size;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
