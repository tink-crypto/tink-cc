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
#ifndef TINK_INTERNAL_PROTO_PARSER_MESSAGE_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_MESSAGE_FIELD_H_
#include <cstddef>
#include <cstdint>
#include <memory>

#include "absl/container/btree_map.h"
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

// A field in OuterStruct of type InnerStruct.
// class InnerStruct { /* omitted */ };
//
// class OuterStruct {
//   InnerStruct inner_struct;
// };
template <typename OuterStruct, typename InnerStruct>
class MessageField : public Field<OuterStruct> {
 public:
  explicit MessageField(int field_number, InnerStruct OuterStruct::*value,
                        LowLevelParser<InnerStruct> low_level_parser)
      : value_(value),
        field_number_(field_number),
        low_level_parser_(std::move(low_level_parser)) {}
  // Not copyable, not movable.
  MessageField(const MessageField&) = delete;
  MessageField& operator=(const MessageField&) = delete;
  MessageField(MessageField&&) noexcept = delete;
  MessageField& operator=(MessageField&&) noexcept = delete;
  void ClearMember(OuterStruct& s) const override {
    low_level_parser_.ClearAllFields(s.*value_);
  }

  absl::Status ConsumeIntoMember(ParsingState& serialized,
                                 OuterStruct& s) const override {
    absl::StatusOr<uint32_t> length = ConsumeVarintForSize(serialized);
    if (!length.ok()) {
      return length.status();
    }
    if (*length > serialized.RemainingData().size()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Length ", *length, " exceeds remaining input size ",
                       serialized.RemainingData().size()));
    }
    ParsingState submessage_parsing_state =
        serialized.SplitOffSubmessageState(*length);
    return low_level_parser_.ConsumeIntoAllFields(submessage_parsing_state,
                                                  s.*value_);
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
  int GetFieldNumber() const override { return field_number_; }

  absl::Status SerializeWithTagInto(SerializationState& out,
                                    const OuterStruct& values) const {
    if (!RequiresSerialization(values)) {
      return absl::OkStatus();
    }
    absl::Status status =
        SerializeWireTypeAndFieldNumber(GetWireType(), GetFieldNumber(), out);
    if (!status.ok()) {
      return status;
    }
    size_t size = low_level_parser_.GetSerializedSize(values.*value_);
    absl::Status s = SerializeVarint(size, out);
    if (!s.ok()) {
      return s;
    }
    if (out.GetBuffer().size() < size) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
    }
    return low_level_parser_.SerializeInto(out, values.*value_);
  }
  size_t GetSerializedSizeIncludingTag(
      const OuterStruct& values) const override {
    if (!RequiresSerialization(values)) {
      return 0;
    }
    size_t size = low_level_parser_.GetSerializedSize(values.*value_);
    return WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
           VarintLength(size) + size;
  }

 private:
  bool RequiresSerialization(const OuterStruct& values) const {
    return low_level_parser_.RequiresSerialization(values.*value_);
  }

  InnerStruct OuterStruct::*value_;
  int field_number_;
  LowLevelParser<InnerStruct> low_level_parser_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
#endif  // TINK_INTERNAL_PROTO_PARSER_MESSAGE_FIELD_H_
