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
#include <utility>

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

OwningField* Fields::operator[](uint32_t field_number) const {
  auto it = absl::c_lower_bound(
      fields_, field_number, [](const OwningField* a, uint32_t field_number) {
        return a->FieldNumber() < field_number;
      });
  if (it == fields_.end() || (*it)->FieldNumber() != field_number) {
    return nullptr;
  }
  return *it;
}

void Message::Clear() {
  for (OwningField* field : fields_) {
    field->Clear();
  }
}

bool Message::SerializeToSpan(absl::Span<char> out) const {
  if (out.size() < ByteSizeLong()) {
    return false;
  }
  SerializationState state(out);
  return Serialize(state);
}

bool Message::ParseFromString(absl::string_view in) {
  ParsingState state(in);
  return Parse(state);
}

SecretData Message::SerializeAsSecretData() const {
  SecretBuffer out(ByteSizeLong());
  if (!SerializeToSpan(
          absl::MakeSpan(reinterpret_cast<char*>(out.data()), out.size()))) {
    return SecretData();
  }
#ifdef TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  return util::SecretDataFromStringView(out.AsStringView());
#else
  return SecretData(std::move(out));
#endif
}

bool Message::Serialize(SerializationState& out) const {
  for (const OwningField* field : fields_) {
    if (absl::Status result = field->SerializeWithTagInto(out); !result.ok()) {
      return false;
    }
  }
  return true;
}

size_t Message::ByteSizeLong() const {
  size_t size = 0;
  for (const OwningField* field : fields_) {
    size += field->GetSerializedSizeIncludingTag();
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

    OwningField* field = fields_[field_number];
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
    if (!field->ConsumeIntoMember(in)) {
      return false;
    }
  }
  return true;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
