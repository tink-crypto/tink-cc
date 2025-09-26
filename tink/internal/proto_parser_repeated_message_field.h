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
#ifndef TINK_INTERNAL_PROTO_PARSER_REPEATED_MESSAGE_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_REPEATED_MESSAGE_FIELD_H_
#include <cstddef>
#include <cstdint>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/proto_parsing_low_level_parser.h"
namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// A repeated field in OuterStruct of type InnerStruct.
// class InnerStruct { /* omitted */ };
//
// class OuterStruct {
//   std::vector<InnerStruct> inner_structs;
// };
//
// Note that users of the Tink parser cannot forward declare InnerStruct here.
// This implies that the messages will form a tree, it isn't possible that
// a struct appears as a submessage anywhere when parsing. This is important,
// since this is the only way the Tink parser avoids stack overflow from
// carefully crafted serializations.
template <typename OuterStruct, typename InnerStruct>
class RepeatedMessageField : public Field<OuterStruct> {
 public:
  explicit RepeatedMessageField(int field_number,
                                std::vector<InnerStruct> OuterStruct::* value,
                                LowLevelParser<InnerStruct> low_level_parser)
      : value_(value),
        field_number_(field_number),
        low_level_parser_(std::move(low_level_parser)) {}
  // Not copyable, not movable.
  RepeatedMessageField(const RepeatedMessageField&) = delete;
  RepeatedMessageField& operator=(const RepeatedMessageField&) = delete;
  RepeatedMessageField(RepeatedMessageField&&) noexcept = delete;
  RepeatedMessageField& operator=(RepeatedMessageField&&) noexcept = delete;
  void ClearMember(OuterStruct& s) const override {
    (s.*value_).clear();
  }

  bool ConsumeIntoMember(ParsingState& serialized,
                         OuterStruct& s) const override {
    absl::StatusOr<uint32_t> length = ConsumeVarintForSize(serialized);
    if (!length.ok()) {
      return false;
    }
    if (*length > serialized.RemainingData().size()) {
      return false;
    }
    ParsingState submessage_parsing_state =
        serialized.SplitOffSubmessageState(*length);
    (s.*value_).push_back(InnerStruct());
    return low_level_parser_.ConsumeIntoAllFields(submessage_parsing_state,
                                                  (s.*value_).back());
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
  int GetFieldNumber() const override { return field_number_; }

  absl::Status SerializeWithTagInto(SerializationState& out,
                                    const OuterStruct& values) const override {
    for (const InnerStruct& inner_struct : values.*value_) {
      absl::Status status =
          SerializeWireTypeAndFieldNumber(GetWireType(), GetFieldNumber(), out);
      if (!status.ok()) {
        return status;
      }
      size_t size = low_level_parser_.GetSerializedSize(inner_struct);
      absl::Status s = SerializeVarint(size, out);
      if (!s.ok()) {
        return s;
      }
      if (out.GetBuffer().size() < size) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
      }
      status = low_level_parser_.SerializeInto(out, inner_struct);
      if (!status.ok()) {
        return status;
      }
    }
    return absl::OkStatus();
  }

  size_t GetSerializedSizeIncludingTag(
      const OuterStruct& values) const override {
    size_t total_size = 0;
    for (const InnerStruct& inner_struct : values.*value_) {
      size_t size = low_level_parser_.GetSerializedSize(inner_struct);
      total_size +=
          WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
          VarintLength(size) + size;
    }
    return total_size;
  }

 private:
  std::vector<InnerStruct> OuterStruct::* value_;
  int field_number_;
  LowLevelParser<InnerStruct> low_level_parser_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
#endif  // TINK_INTERNAL_PROTO_PARSER_REPEATED_MESSAGE_FIELD_H_
