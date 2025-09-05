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
#ifndef TINK_INTERNAL_PROTO_PARSER_MESSAGE_FIELD_WITH_PRESENCE_H_
#define TINK_INTERNAL_PROTO_PARSER_MESSAGE_FIELD_WITH_PRESENCE_H_

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/proto_parsing_low_level_parser.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// A field in OuterStruct of type absl::optional<InnerStruct>.
// struct InnerStruct { /* omitted */ };
//
// struct OuterStruct {
//   absl::optional<InnerStruct> inner_struct;
// };
//
// Note that users of the Tink parser cannot forward declare InnerStruct here.
// This implies that the messages will form a tree, it isn't possible that
// a struct appears as a submessage anywhere when parsing. This is important,
// since this is the only way the Tink parser avoids stack overflow from
// carefully crafted serializations.

template <typename OuterStruct, typename InnerStruct>
class MessageFieldWithPresence : public Field<OuterStruct> {
 public:
  explicit MessageFieldWithPresence(
      int field_number, std::optional<InnerStruct> OuterStruct::* value,
      LowLevelParser<InnerStruct> low_level_parser)
      : value_(value),
        field_number_(field_number),
        low_level_parser_(std::move(low_level_parser)) {}
  // Not copyable, not movable.
  MessageFieldWithPresence(const MessageFieldWithPresence&) = delete;
  MessageFieldWithPresence& operator=(const MessageFieldWithPresence&) = delete;
  MessageFieldWithPresence(MessageFieldWithPresence&&) noexcept = delete;
  MessageFieldWithPresence& operator=(MessageFieldWithPresence&&) noexcept =
      delete;

  void ClearMember(OuterStruct& s) const override { (s.*value_).reset(); }

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
    if (!(s.*value_).has_value()) {
      (s.*value_) = InnerStruct();
    }
    return low_level_parser_.ConsumeIntoAllFields(submessage_parsing_state,
                                                  *(s.*value_));
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
  int GetFieldNumber() const override { return field_number_; }

  absl::Status SerializeWithTagInto(SerializationState& out,
                                    const OuterStruct& values) const override {
    if (!(values.*value_).has_value()) {
      return absl::OkStatus();
    }
    if (absl::Status result = SerializeWireTypeAndFieldNumber(
            GetWireType(), GetFieldNumber(), out);
        !result.ok()) {
      return result;
    }
    size_t size = low_level_parser_.GetSerializedSize(*(values.*value_));
    if (absl::Status result = SerializeVarint(size, out); !result.ok()) {
      return result;
    }
    if (out.GetBuffer().size() < size) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
    }
    return low_level_parser_.SerializeInto(out, *(values.*value_));
  }

  size_t GetSerializedSizeIncludingTag(
      const OuterStruct& values) const override {
    if (!(values.*value_).has_value()) {
      return 0;
    }
    size_t size = low_level_parser_.GetSerializedSize(*(values.*value_));
    return WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
           VarintLength(size) + size;
  }

 private:
  absl::optional<InnerStruct> OuterStruct::* value_;
  int field_number_;
  LowLevelParser<InnerStruct> low_level_parser_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
#endif  // TINK_INTERNAL_PROTO_PARSER_MESSAGE_FIELD_WITH_PRESENCE_H_
