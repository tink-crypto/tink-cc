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
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
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

// Message.

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
    if (!field(i)->SerializeWithTagInto(out)) {
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
    WireType wire_type;
    int field_number;
    if (!ConsumeIntoWireTypeAndFieldNumber(in, wire_type, field_number)) {
      return false;
    }

    const Field* /*absl_nullable - not yet supported*/ field = FieldWithNumber(field_number);
    if (field == nullptr || field->GetWireType() != wire_type) {
      if (wire_type == WireType::kStartGroup) {
        if (!SkipGroup(field_number, in)) {
          return false;
        }
      } else {
        if (!SkipField(wire_type, in)) {
          return false;
        }
      }
      continue;
    }
    if (!const_cast<Field*>(field)->ConsumeIntoMember(in)) {
      return false;
    }
  }
  return true;
}

// MessageFieldBase.

bool MessageFieldBase::ConsumeIntoMember(ParsingState& serialized) {
  uint32_t length;
  if (!ConsumeVarintForSize(serialized, length)) {
    return false;
  }
  if (length > serialized.RemainingData().size()) {
    return false;
  }
  ParsingState submessage_parsing_state =
      serialized.SplitOffSubmessageState(length);
  Message* /*absl_nullable - not yet supported*/ msg = mutable_message();
  ABSL_DCHECK(msg != nullptr);
  if (!msg->Parse(submessage_parsing_state)) {
    return false;
  }
  if (!submessage_parsing_state.ParsingDone()) {
    ABSL_LOG(DFATAL) << "Submessage wasn't parsed correctly";
    return false;
  }
  return true;
}

bool MessageFieldBase::SerializeWithTagInto(
    SerializationState& out) const {
  const Message* /*absl_nullable - not yet supported*/ msg = message();
  if (msg == nullptr) {
    return true;
  }
  if (!SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out)) {
    return false;
  }
  const size_t size = msg->ByteSizeLong();
  if (!SerializeVarint(size, out)) {
    return false;
  }
  if (out.GetBuffer().size() < size) {
    return false;
  }
  // Serialize the msg.
  return msg->Serialize(out);
}

size_t MessageFieldBase::GetSerializedSizeIncludingTag() const {
  const Message* /*absl_nullable - not yet supported*/ msg = message();
  if (msg == nullptr) {
    return 0;
  }
  const size_t size = msg->ByteSizeLong();
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(size) + size;
}

// RepeatedMessageFieldBase.

bool RepeatedMessageFieldBase::ConsumeIntoMember(ParsingState& serialized) {
  uint32_t length;
  if (!ConsumeVarintForSize(serialized, length)) {
    return false;
  }
  if (length > serialized.RemainingData().size()) {
    return false;
  }
  ParsingState submessage_parsing_state =
      serialized.SplitOffSubmessageState(length);
  Message* to_add = add_message();
  if (!to_add->Parse(submessage_parsing_state)) {
    return false;
  }
  if (!submessage_parsing_state.ParsingDone()) {
    ABSL_LOG(DFATAL) << "Submessage wasn't parsed correctly";
    return false;
  }
  return true;
}

bool RepeatedMessageFieldBase::SerializeWithTagInto(
    SerializationState& out) const {
  for (size_t i = 0; i < num_messages(); ++i) {
    const Message& msg = message(i);
    if (!SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out)) {
      return false;
    }
    const size_t size = msg.ByteSizeLong();
    if (!SerializeVarint(size, out)) {
      return false;
    }
    if (out.GetBuffer().size() < size) {
      return false;
    }
    // Serialize the message.
    if (!msg.Serialize(out)) {
      return false;
    }
  }
  return true;
}

size_t RepeatedMessageFieldBase::GetSerializedSizeIncludingTag() const {
  const size_t wire_type_and_field_number_length =
      WireTypeAndFieldNumberLength(GetWireType(), FieldNumber());
  size_t size = 0;
  for (size_t i = 0; i < num_messages(); ++i) {
    const Message& msg = message(i);
    size += msg.ByteSizeLong() + VarintLength(msg.ByteSizeLong()) +
            wire_type_and_field_number_length;
  }
  return size;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
