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

#include "tink/internal/proto_parser_message.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

bool Message::FieldsAreSorted() const {
  for (size_t i = 1; i < num_fields(); ++i) {
    if (field(i - 1)->FieldNumber() >= field(i)->FieldNumber()) {
      return false;
    }
  }
  return true;
}

const Field* /*absl_nullable - not yet supported*/ Message::FieldWithNumber(uint32_t field_number) {
  // Assumes fields returned by field() are sorted in strictly increasing order
  // of their field number.
  ABSL_DCHECK(FieldsAreSorted())
      << "Fields returned by field() must be sorted in strictly increasing "
         "order of their field number.";
  int low = 0;
  int high = num_fields() - 1;
  while (low <= high) {
    // Invariant: If field_number is in the array, it is in the range [low,
    // high].
    int mid = low + (high - low) / 2;
    const Field* f = field(mid);
    if (f->FieldNumber() == field_number) {
      return f;
    }
    if (f->FieldNumber() < field_number) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  // field_number is not in the array.
  return nullptr;
}

void Message::Clear() {
  for (size_t i = 0; i < num_fields(); ++i) {
    const_cast<Field*>(field(i))->Clear();
  }
}

bool Message::ParseFromStringImpl(absl::string_view in,
                                  absl::crc32c_t* /*absl_nullable - not yet supported*/ result_crc) {
  Clear();
  ParsingState state(in, result_crc);
  if (!Parse(state)) {
    return false;
  }
  ABSL_QCHECK(state.ParsingDone());
  ABSL_QCHECK(state.RemainingData().empty());
  return true;
}

bool Message::ParseFromString(absl::string_view in) {
  return ParseFromStringImpl(in, /*result_crc=*/nullptr);
}

absl::StatusOr<util::SecretValue<absl::crc32c_t>>
Message::ParseFromStringWithCrc(absl::string_view in) {
  auto result_crc = util::SecretValue<absl::crc32c_t>(absl::crc32c_t(0));
  if (!ParseFromStringImpl(in, &result_crc.value())) {
    return absl::InvalidArgumentError("Failed to parse message");
  }
  return result_crc;
}

SecretData Message::SerializeAsSecretData() const {
  SecretBuffer out(ByteSizeLong());
  auto buffer = absl::MakeSpan(reinterpret_cast<char*>(out.data()), out.size());
  return CallWithCoreDumpProtection([&]() -> SecretData {
    absl::crc32c_t result_crc = absl::crc32c_t(0);
    auto serialization_state = SerializationState(buffer, &result_crc);
    ABSL_QCHECK(Serialize(serialization_state));
    ABSL_QCHECK(serialization_state.GetBuffer().empty());
#ifdef TINK_CPP_SECRET_DATA_IS_STD_VECTOR
    return util::SecretDataFromStringView(out.AsStringView());
#else
    return SecretData(std::move(out), result_crc);
#endif
  });
}

std::string Message::SerializeAsString() const {
  std::string out;
  subtle::ResizeStringUninitialized(&out, ByteSizeLong());
  SerializationState serialization_state(
      absl::MakeSpan(reinterpret_cast<char*>(out.data()), out.size()));
  ABSL_QCHECK(Serialize(serialization_state));
  ABSL_QCHECK(serialization_state.GetBuffer().empty());
  return out;
}

bool Message::Serialize(SerializationState& out) const {
  for (size_t i = 0; i < num_fields(); ++i) {
    if (absl::Status result = field(i)->SerializeWithTagInto(out);
        !result.ok()) {
      return false;
    }
  }
  return true;
}

size_t Message::ByteSizeLong() const {
  size_t size = 0;
  for (size_t i = 0; i < num_fields(); ++i) {
    size += field(i)->GetSerializedSizeIncludingTag();
  }
  return size;
}

bool Message::Parse(ParsingState& in) {
  while (!in.ParsingDone()) {
    absl::StatusOr<std::pair<WireType, int>> wiretype_and_field_number =
        ConsumeIntoWireTypeAndFieldNumber(in);
    if (!wiretype_and_field_number.ok()) {
      return false;
    }
    auto [wire_type, field_number] = *wiretype_and_field_number;

    const Field* /*absl_nullable - not yet supported*/ field = FieldWithNumber(field_number);
    if (field == nullptr || field->GetWireType() != wire_type) {
      absl::Status s;
      if (wire_type == WireType::kStartGroup) {
        s = SkipGroup(field_number, in);
      } else {
        s = SkipField(wire_type, in);
      }
      if (!s.ok()) {
        return false;
      }
      continue;
    }
    if (!const_cast<Field*>(field)->ConsumeIntoMember(in)) {
      return false;
    }
  }
  return true;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
