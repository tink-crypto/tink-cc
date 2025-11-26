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
#include <string>
#include <type_traits>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

ABSL_POINTERS_DEFAULT_NONNULL

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Represents a proto message.
//
// Usage:
//
// class MyMessage : public Message {
//  public:
//   MyMessage() : Message(&fields_) {}
//   ~MyMessage() = default;
//
//  private:
//   size_t num_fields() const override { return 2; }
//   const Field* field(int i) const override {
//     return std::array<const Field*, 2>{&some_string_,
//     &some_other_string_}[i];
//   }
//   BytesField some_string_{1};
//   SecretDataField some_other_string_{2};
// };
//
// This class is not thread-safe.
class Message {
 public:
  Message() = default;
  virtual ~Message() = default;

  // Copyable and movable.
  Message(const Message&) = default;
  Message& operator=(const Message&) = default;
  Message(Message&&) noexcept = default;
  Message& operator=(Message&&) noexcept = default;

  // Methods taken from the proto2::Message interface.
  // Clears all fields.
  void Clear();
  bool ParseFromString(absl::string_view in);
  size_t ByteSizeLong() const;

  // Parses `in` and returns the CRC of the input.
  //
  // For fields that support CRCs (e.g. SecretData), the CRC of the field is
  // consistent with the returned CRC. This enables end-to-end coverage of
  // the CRC computation: if the returned CRC is known to be correct, the CRCs
  // of the individual fields must also be correct.
  absl::StatusOr<util::SecretValue<absl::crc32c_t>> ParseFromStringWithCrc(
      absl::string_view in);
  // Serializes the message as SecretData.
  SecretData SerializeAsSecretData() const;

 protected:
  std::string SerializeAsString() const;

 private:
  friend class MessageFieldBase;
  friend class RepeatedMessageFieldBase;

  bool FieldsAreSorted() const;
  // Returns the field with the given `field_number`, or nullptr if no such
  // field exists.
  const Field* /*absl_nullable - not yet supported*/ FieldWithNumber(uint32_t field_number);
  bool ParseFromStringImpl(absl::string_view in,
                           absl::crc32c_t* /*absl_nullable - not yet supported*/ result_crc);

  // Serializes the message into the given serialization state `out`.
  // Returns true if the serialization was successful.
  bool Serialize(SerializationState& out) const;
  // Parses the message from the given parsing state `in`. Returns true if the
  // parsing was successful.
  bool Parse(ParsingState& in);

 protected:
  // Returns the number of fields in the message.
  virtual size_t num_fields() const = 0;
  // Returns the `i`-th field.
  //
  // Preconditions:
  //   * 0 <= i < num_fields().
  //   * The fields are sorted by field number.
  virtual const Field* field(int i) const = 0;
};

// Base class for RepeatedMessageField.
//
// It implements all methods of `Field` but `Clear`.
class RepeatedMessageFieldBase : public Field {
 public:
  explicit RepeatedMessageFieldBase(int field_number)
      : Field(field_number, WireType::kLengthDelimited) {}

  // Copyable and movable.
  RepeatedMessageFieldBase(const RepeatedMessageFieldBase&) = default;
  RepeatedMessageFieldBase& operator=(const RepeatedMessageFieldBase&) =
      default;
  RepeatedMessageFieldBase(RepeatedMessageFieldBase&&) noexcept = default;
  RepeatedMessageFieldBase& operator=(RepeatedMessageFieldBase&&) noexcept =
      default;

  bool ConsumeIntoMember(ParsingState& serialized) override;
  bool SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

 protected:
  // Returns the i-th message.
  virtual const Message& message(int i) const = 0;
  // Adds a new message and returns a pointer to it.
  virtual Message* add_message() = 0;
  // Returns the number of messages.
  virtual size_t num_messages() const = 0;
};

// Represents a repeated proto message.
//
// Usage:
//
// class MyMessage : public Message {
//  public:
//   MyMessage() : Message(&fields_) {}
//   ~MyMessage() = default;
//  private:
//   RepeatedMessageField<MySubMessage> some_repeated_message_{1};
//   Fields fields_{&some_repeated_message_};
// };
//
// This class is not thread-safe.
template <typename MessageT>
class RepeatedMessageField : public RepeatedMessageFieldBase {
 public:
  explicit RepeatedMessageField(int field_number)
      : RepeatedMessageFieldBase(field_number) {}

  // Copyable and movable.
  RepeatedMessageField(const RepeatedMessageField&) = default;
  RepeatedMessageField& operator=(const RepeatedMessageField&) = default;
  RepeatedMessageField(RepeatedMessageField&&) noexcept = default;
  RepeatedMessageField& operator=(RepeatedMessageField&&) noexcept = default;

  void Clear() override { values_.clear(); }

  // See https://protobuf.dev/reference/cpp/cpp-generated/#repeatedmessage.
  int values_size() const { return values_.size(); }
  const MessageT& values(int index) const { return values_[index]; }
  MessageT* mutable_values(int index) { return &values_[index]; }
  MessageT* add_values() {
    values_.emplace_back();
    return &values_.back();
  }
  const std::vector<MessageT>& values() const { return values_; }
  std::vector<MessageT>* mutable_values() { return &values_; }

 private:
  const Message& message(int i) const override { return values(i); }
  Message* add_message() override { return add_values(); }
  size_t num_messages() const override { return values_size(); }

  std::vector<MessageT> values_;
};

// Base class for MessageField.
//
// It implements all methods of `Field` but `Clear`.
class MessageFieldBase : public Field {
 public:
  explicit MessageFieldBase(int field_number)
      : Field(field_number, WireType::kLengthDelimited) {}

  // Copyable and movable.
  MessageFieldBase(const MessageFieldBase&) = default;
  MessageFieldBase& operator=(const MessageFieldBase&) = default;
  MessageFieldBase(MessageFieldBase&&) noexcept = default;
  MessageFieldBase& operator=(MessageFieldBase&&) noexcept = default;

  bool ConsumeIntoMember(ParsingState& serialized) override;
  bool SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

 protected:
  // Returns the message if it is set, otherwise nullptr.
  virtual const Message* /*absl_nullable - not yet supported*/ message() const = 0;
  // Returns a mutable message, which is guaranteed to be non-null.
  virtual Message* mutable_message() = 0;
};

// Represents a field of type proto message.
//
// Usage:
//
// class MyMessage : public Message {
//  public:
//   MyMessage() : Message(&fields_) {}
//   ~MyMessage() = default;
//
//  private:
//   size_t num_fields() const override { return 2; }
//   const Field* field(int i) const override {
//     return std::array<const Field*, 2>{&some_string_,
//     &some_other_string_}[i];
//   }
//
//   MessageField<MySubMessage> some_message_{1};
//   SecretDataField some_other_string_{2};
// };
//
// Note:
// * if options == ProtoFieldOptions::kAlwaysPresent, then the field is
//   always present (i.e., has_value() never returns false). This forces
//   serialization as well, which is useful if the field is LEGACY_REQUIRED in
//   proto.
// * if options == ProtoFieldOptions::kExplicit, then the field is serialized
//   only if the value is set (even if with a default value).
//
// This class is not thread-safe.
template <typename MessageT>
class MessageField : public MessageFieldBase {
  static_assert(std::is_copy_constructible_v<MessageT>,
                "MessageT must be copy constructible.");
  static_assert(std::is_copy_assignable_v<MessageT>,
                "MessageT must be copy assignable.");
  static_assert(std::is_move_constructible_v<MessageT>,
                "MessageT must be move constructible.");
  static_assert(std::is_move_assignable_v<MessageT>,
                "MessageT must be move assignable.");

 public:
  explicit MessageField(int field_number, ProtoFieldOptions options =
                                              ProtoFieldOptions::kExplicit)
      : MessageFieldBase(field_number), options_(options) {
    ABSL_CHECK(options_ != ProtoFieldOptions::kImplicit)
        << "MessageField does not support kImplicit option.";
    Clear();
  }

  // Copyable and movable.
  MessageField(const MessageField&) = default;
  MessageField& operator=(const MessageField&) = default;
  MessageField(MessageField&&) noexcept = default;
  MessageField& operator=(MessageField&&) noexcept = default;

  // Clears the field.
  //
  // If options_ == ProtoFieldOptions::kAlwaysPresent then the field is set to
  // the default value. Otherwise the optional field is cleared.
  void Clear() override {
    if (options_ == ProtoFieldOptions::kAlwaysPresent) {
      value_.emplace();
    } else {
      value_.reset();
    }
  }

  // APIs. See
  // https://protobuf.dev/reference/cpp/cpp-generated/#embeddedmessage.

  // Returns whether the field has value.
  //
  // If options_ == ProtoFieldOptions::kAlwaysPresent this is always true as the
  // class guarantees that value_ always has a value.
  bool has_value() const { return value_.has_value(); }
  const MessageT& value() const {
    if (value_.has_value()) {
      return *value_;
    }
    return DefaultValue();
  }
  MessageT* mutable_value() {
    if (!value_.has_value()) {
      value_.emplace();
    }
    return &value_.value();
  }

 private:
  const Message* /*absl_nullable - not yet supported*/ message() const override {
    return value_.has_value() ? &*value_ : nullptr;
  }
  Message* mutable_message() override {
    if (!value_.has_value()) {
      value_.emplace();
    }
    return &value_.value();
  }

  ABSL_ATTRIBUTE_NOINLINE
  const MessageT& DefaultValue() const {
    static const absl::NoDestructor<MessageT> default_value;
    return *default_value;
  }

  absl::optional<MessageT> value_ = absl::nullopt;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_MESSAGE_H_
