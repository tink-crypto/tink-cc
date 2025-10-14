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
#ifndef TINK_INTERNAL_PROTO_PARSER_MESSAGE_H_
#define TINK_INTERNAL_PROTO_PARSER_MESSAGE_H_

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/nullability.h"
#include "absl/log/die_if_null.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/secret_data.h"
namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Sorted list of fields by field number.
class Fields final {
 public:
  Fields(std::initializer_list<OwningField*> fields) : fields_(fields) {
    absl::c_sort(fields_, [](const OwningField* a, const OwningField* b) {
      return a->FieldNumber() < b->FieldNumber();
    });
  }
  // Allows iterating over the fields.
  auto begin() const { return fields_.begin(); }
  auto end() const { return fields_.end(); }
  // Returns the field with the given `field_number` or nullptr if not found.
  OwningField* operator[](uint32_t field_number) const;

 private:
  std::vector<OwningField*> fields_;
};

// Forward declaration to allow friend statement in Message.
class MessageOwningFieldBase;

// Represents a proto message.
//
// Usage:
//
// class MyMessage : public Message {
//  public:
//   MyMessage() : Message(&fields_) {}
//   ~MyMessage() = default;
//  private:
//   OwningBytesField<std::string> some_string_{1};
//   OwningBytesField<SecretData> some_other_string_{2};
//   Fields fields_{&some_string_, &some_other_string_};
// };
//
// This class is not thread-safe.
class Message {
 public:
  explicit Message(Fields* /*absl_nonnull - not yet supported*/ fields)
      : fields_(*ABSL_DIE_IF_NULL(fields)) {}
  virtual ~Message() = default;

  // Methods taken from the proto2::Message interface.
  // Clears all fields.
  void Clear();
  bool ParseFromString(absl::string_view in);
  size_t ByteSizeLong() const;

  // Serializes the message as SecretData.
  SecretData SerializeAsSecretData() const;

 private:
  friend class MessageOwningFieldBase;

  // Serializes the message into the given serialization state `out`.
  // Returns true if the serialization was successful.
  bool Serialize(SerializationState& out) const;
  // Parses the message from the given parsing state `in`. Returns true if the
  // parsing was successful.
  bool Parse(ParsingState& in);

  // Serializes the message into the given span of bytes `out`. Returns true if
  // the serialization was successful.
  bool SerializeToSpan(absl::Span<char> out) const;

  Fields& fields_;
};

class MessageOwningFieldBase : public OwningField {
 public:
  explicit MessageOwningFieldBase(int field_number,
                                  Message* /*absl_nonnull - not yet supported*/ message)
      : OwningField(field_number, WireType::kLengthDelimited),
        message_(*ABSL_DIE_IF_NULL(message)) {}
  void Clear() override { message_.Clear(); }

  bool ConsumeIntoMember(ParsingState& serialized) override {
    absl::StatusOr<uint32_t> length = ConsumeVarintForSize(serialized);
    if (!length.ok()) {
      return false;
    }
    if (*length > serialized.RemainingData().size()) {
      return false;
    }
    ParsingState submessage_parsing_state =
        serialized.SplitOffSubmessageState(*length);
    return message_.Parse(submessage_parsing_state);
  }

  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    const size_t size = message_.ByteSizeLong();
    if (size == 0) {
      return absl::OkStatus();
    }
    if (absl::Status res =
            SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
        !res.ok()) {
      return res;
    }
    if (absl::Status res = SerializeVarint(size, out); !res.ok()) {
      return res;
    }
    if (out.GetBuffer().size() < size) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
    }
    // Serialize the message.
    if (!message_.Serialize(out)) {
      return absl::InternalError("Failed to serialize message");
    }
    return absl::OkStatus();
  }

  size_t GetSerializedSizeIncludingTag() const override {
    const size_t message_size = message_.ByteSizeLong();
    if (message_size <= 0) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
           VarintLength(message_size) + message_size;
  }

 private:
  Message& message_;
};

template <typename MessageT>
class MessageOwningField final : public MessageOwningFieldBase {
 public:
  explicit MessageOwningField(int field_number)
      : MessageOwningFieldBase(field_number, &value_) {}

  MessageT& value() { return value_; }
  const MessageT& value() const { return value_; }

  // Copyable and movable.
  MessageOwningField(const MessageOwningField&) = default;
  MessageOwningField& operator=(const MessageOwningField&) = default;
  MessageOwningField(MessageOwningField&&) noexcept = default;
  MessageOwningField& operator=(MessageOwningField&&) noexcept = default;

 private:
  MessageT value_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_MESSAGE_H_
