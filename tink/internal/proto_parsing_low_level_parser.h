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

#ifndef TINK_INTERNAL_PROTO_PARSING_LOW_LEVEL_PARSER_H_
#define TINK_INTERNAL_PROTO_PARSING_LOW_LEVEL_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// A proto message parser/serializer as our main parser, but with an API which
// requires fewer dependencies and is more low level, so it can be used in
// fields.
template <typename Struct>
class LowLevelParser {
 public:
  // Creates a new LowLevelParser with the given fields. Behavior is undefined
  // if there are two fields with the same tag or if fields[i]->GetFieldNUmber()
  // != i.
  explicit LowLevelParser(
      absl::btree_map<int, std::unique_ptr<Field<Struct>>> fields)
      : fields_(std::move(fields)) {}

  // Not copyable, movable.
  LowLevelParser(const LowLevelParser&) = delete;
  LowLevelParser& operator=(const LowLevelParser&) = delete;
  LowLevelParser(LowLevelParser&&) noexcept = default;
  LowLevelParser& operator=(LowLevelParser&&) noexcept = default;

  // Clears all (known) fields in the struct.
  void ClearAllFields(Struct& values) const {
    for (auto& pair : fields_) {
      pair.second->ClearMember(values);
    }
  }

  // Parses the serialized message and populates the corresponding fields.
  bool ConsumeIntoAllFields(ParsingState& serialized,
                                    Struct& values) const {
    while (!serialized.ParsingDone()) {
      absl::StatusOr<std::pair<WireType, int>> wiretype_and_field_number =
          ConsumeIntoWireTypeAndFieldNumber(serialized);
      if (!wiretype_and_field_number.ok()) {
        return false;
      }
      auto it = fields_.find(wiretype_and_field_number->second);
      if (it == fields_.end() ||
          it->second->GetWireType() != wiretype_and_field_number->first) {
        absl::Status s;
        if (wiretype_and_field_number->first == WireType::kStartGroup) {
          s = SkipGroup(wiretype_and_field_number->second, serialized);
        } else {
          s = SkipField(wiretype_and_field_number->first, serialized);
        }
        if (!s.ok()) {
          return false;
        }
        continue;
      }
      bool res = it->second->ConsumeIntoMember(serialized, values);
      if (!res) {
        return res;
      }
    }
    return true;
  }

  // Returns true if any field needs to be serialized (i.e. is not the default).
  bool RequiresSerialization(const Struct& values) const {
    return GetSerializedSize(values) > 0;
  }

  // Serializes all fields into |out|, and removes the part which was written
  // to from |out|.
  absl::Status SerializeInto(SerializationState& out,
                             const Struct& values) const {
    for (const auto& pair : fields_) {
      absl::Status status = pair.second->SerializeWithTagInto(out, values);
      if (!status.ok()) {
        return status;
      }
    }
    return absl::OkStatus();
  }

  // Returns the required size for SerializeInto.
  size_t GetSerializedSize(const Struct& values) const {
    size_t result = 0;
    for (const auto& pair : fields_) {
      result += pair.second->GetSerializedSizeIncludingTag(values);
    }
    return result;
  }

 private:
  absl::btree_map<int, std::unique_ptr<Field<Struct>>> fields_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSING_LOW_LEVEL_PARSER_H_
