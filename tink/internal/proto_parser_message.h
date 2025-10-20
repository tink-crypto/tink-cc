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
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/no_destructor.h"
#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Forward declaration to allow friend statement in Message.
template <typename MessageT>
class MessageOwningField;

// Represents a proto message.
//
// Usage:
//
// class MyMessage : public Messag<MyMessage> {
//  public:
//   MyMessage() : Message(&fields_) {}
//   ~MyMessage() = default;
//
//   std::array<const OwningField*, 2> GetFields() const {
//     return {&some_string_, &some_other_string_};
//   }
//
//  private:
//   OwningBytesField<std::string> some_string_{1};
//   OwningBytesField<SecretData> some_other_string_{2};
// };
//
// This class is not thread-safe.
template <typename Derived>
class Message {
 public:
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
  // We declare Derived as a friend and make constructors private. This prevents
  // users from mistakenly giving a wrong template argument:
  // `class AesEaxKeyProto : public Message<AesGcmKeyProto> {...};`
  // will fail to compile.
  friend Derived;
  template <typename MessageT>
  friend class MessageOwningField;
  template <typename MessageT>
  friend class RepeatedMessageOwningField;
  template <typename MessageT>
  friend class MessageOwningFieldWithPresence;

  Message() = default;
  virtual ~Message() = default;

  // Copyable and movable.
  Message(const Message&) = default;
  Message& operator=(const Message&) = default;
  Message(Message&&) noexcept = default;
  Message& operator=(Message&&) noexcept = default;

  const OwningField* /*absl_nullable - not yet supported*/ get_field(uint32_t field_number) {
    auto fields = static_cast<Derived*>(this)->GetFields();
    auto it = absl::c_lower_bound(
        fields, field_number, [](const OwningField* a, uint32_t field_number) {
          return a->FieldNumber() < field_number;
        });
    if (it == fields.end() || (*it)->FieldNumber() != field_number) {
      return nullptr;
    }
    return *it;
  }

  bool ParseFromStringImpl(absl::string_view in,
                           absl::crc32c_t* result_crc);

  // Serializes the message into the given serialization state `out`.
  // Returns true if the serialization was successful.
  bool Serialize(SerializationState& out) const;
  // Parses the message from the given parsing state `in`. Returns true if the
  // parsing was successful.
  bool Parse(ParsingState& in);
};

template <typename Derived>
void Message<Derived>::Clear() {
  for (const OwningField* field : (static_cast<Derived*>(this))->GetFields()) {
    const_cast<OwningField*>(field)->Clear();
  }
}

template <typename Derived>
bool Message<Derived>::ParseFromStringImpl(absl::string_view in,
                                           absl::crc32c_t* result_crc) {
  Clear();
  ParsingState state(in, result_crc);
  if (!Parse(state)) {
    return false;
  }
  QCHECK(state.ParsingDone());
  QCHECK(state.RemainingData().empty());
  return true;
}

template <typename Derived>
bool Message<Derived>::ParseFromString(absl::string_view in) {
  return ParseFromStringImpl(in, /*result_crc=*/nullptr);
}

template <typename Derived>
absl::StatusOr<util::SecretValue<absl::crc32c_t>>
Message<Derived>::ParseFromStringWithCrc(absl::string_view in) {
  auto result_crc = util::SecretValue<absl::crc32c_t>(absl::crc32c_t(0));
  if (!ParseFromStringImpl(in, &result_crc.value())) {
    return absl::InvalidArgumentError("Failed to parse message");
  }
  return result_crc;
}

template <typename Derived>
SecretData Message<Derived>::SerializeAsSecretData() const {
  SecretBuffer out(ByteSizeLong());
  auto buffer = absl::MakeSpan(reinterpret_cast<char*>(out.data()), out.size());
  return CallWithCoreDumpProtection([&]() -> SecretData {
    absl::crc32c_t result_crc = absl::crc32c_t(0);
    auto serialization_state = SerializationState(buffer, &result_crc);
    QCHECK(Serialize(serialization_state));
    QCHECK(serialization_state.GetBuffer().empty());
#ifdef TINK_CPP_SECRET_DATA_IS_STD_VECTOR
    return util::SecretDataFromStringView(out.AsStringView());
#else
    return SecretData(std::move(out), result_crc);
#endif
  });
}

template <typename Derived>
std::string Message<Derived>::SerializeAsString() const {
  std::string out;
  subtle::ResizeStringUninitialized(&out, ByteSizeLong());
  SerializationState serialization_state(
      absl::MakeSpan(reinterpret_cast<char*>(out.data()), out.size()));
  QCHECK(Serialize(serialization_state));
  QCHECK(serialization_state.GetBuffer().empty());
  return out;
}

template <typename Derived>
bool Message<Derived>::Serialize(SerializationState& out) const {
  for (const OwningField* field :
       static_cast<const Derived*>(this)->GetFields()) {
    if (absl::Status result = field->SerializeWithTagInto(out); !result.ok()) {
      return false;
    }
  }
  return true;
}

template <typename Derived>
size_t Message<Derived>::ByteSizeLong() const {
  size_t size = 0;
  for (const OwningField* field :
       static_cast<const Derived*>(this)->GetFields()) {
    size += field->GetSerializedSizeIncludingTag();
  }
  return size;
}

template <typename Derived>
bool Message<Derived>::Parse(ParsingState& in) {
  while (!in.ParsingDone()) {
    absl::StatusOr<std::pair<WireType, int>> wiretype_and_field_number =
        ConsumeIntoWireTypeAndFieldNumber(in);
    if (!wiretype_and_field_number.ok()) {
      return false;
    }
    auto [wire_type, field_number] = *wiretype_and_field_number;

    const OwningField* field = get_field(field_number);
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
    if (!const_cast<OwningField*>(field)->ConsumeIntoMember(in)) {
      return false;
    }
  }
  return true;
}

// Represents a proto message that is owned by the MessageOwningField.
//
// Usage:
//
// class MyMessage : public Messag<MyMessage> {
//  public:
//   MyMessage() : Message(&fields_) {}
//   ~MyMessage() = default;
//
//   std::array<const OwningField*, 2> GetFields() const {
//     return {&some_message_, &some_other_string_};
//   }
//
//  private:
//   MessageOwningField<MySubMessage> some_message_{1};
//   OwningBytesField<SecretData> some_other_string_{2};
// };
//
// This class is not thread-safe.
template <typename MessageT>
class MessageOwningField : public OwningField {
 public:
  static_assert(std::is_copy_constructible<MessageT>::value,
                "MessageT must be copy constructible.");
  static_assert(std::is_copy_assignable<MessageT>::value,
                "MessageT must be copy assignable.");
  static_assert(std::is_move_constructible<MessageT>::value,
                "MessageT must be move constructible.");
  static_assert(std::is_move_assignable<MessageT>::value,
                "MessageT must be move assignable.");

  explicit MessageOwningField(int field_number)
      : OwningField(field_number, WireType::kLengthDelimited) {}

  // Copyable and movable.
  MessageOwningField(const MessageOwningField&) = default;
  MessageOwningField& operator=(const MessageOwningField&) = default;
  MessageOwningField(MessageOwningField&&) noexcept = default;
  MessageOwningField& operator=(MessageOwningField&&) noexcept = default;

  void Clear() override { value_.Clear(); }

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
    return value_.Parse(submessage_parsing_state);
  }

  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    const size_t size = value_.ByteSizeLong();
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
    if (!value_.Serialize(out)) {
      return absl::InternalError("Failed to serialize message");
    }
    return absl::OkStatus();
  }

  size_t GetSerializedSizeIncludingTag() const override {
    const size_t message_size = value_.ByteSizeLong();
    if (message_size <= 0) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
           VarintLength(message_size) + message_size;
  }

  MessageT& value() { return value_; }
  const MessageT& value() const { return value_; }

 private:
  MessageT value_;
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
//   RepeatedMessageOwningField<MySubMessage> some_repeated_message_{1};
//   Fields fields_{&some_repeated_message_};
// };
//
// This class is not thread-safe.
template <typename MessageT>
class RepeatedMessageOwningField : public OwningField {
 public:
  explicit RepeatedMessageOwningField(int field_number)
      : OwningField(field_number, WireType::kLengthDelimited) {}

  // Copyable and movable.
  RepeatedMessageOwningField(const RepeatedMessageOwningField&) = default;
  RepeatedMessageOwningField& operator=(const RepeatedMessageOwningField&) =
      default;
  RepeatedMessageOwningField(RepeatedMessageOwningField&&) noexcept = default;
  RepeatedMessageOwningField& operator=(RepeatedMessageOwningField&&) noexcept =
      default;

  void Clear() override { values_.clear(); }

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
    MessageT parsed_message;
    if (!parsed_message.Parse(submessage_parsing_state)) {
      return false;
    }
    QCHECK(submessage_parsing_state.ParsingDone());
    values_.push_back(std::move(parsed_message));
    return true;
  }

  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    for (const MessageT& message : values_) {
      if (absl::Status res = SerializeWireTypeAndFieldNumber(
              GetWireType(), FieldNumber(), out);
          !res.ok()) {
        return res;
      }
      const size_t size = message.ByteSizeLong();
      if (absl::Status res = SerializeVarint(size, out); !res.ok()) {
        return res;
      }
      if (out.GetBuffer().size() < size) {
        return absl::InvalidArgumentError(absl::StrCat(
            "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
      }
      // Serialize the message.
      if (!message.Serialize(out)) {
        return absl::InternalError("Failed to serialize message");
      }
    }
    return absl::OkStatus();
  }

  size_t GetSerializedSizeIncludingTag() const override {
    const size_t wire_type_and_field_number_length =
        WireTypeAndFieldNumberLength(GetWireType(), FieldNumber());
    return absl::c_accumulate(
        values_, 0,
        [wire_type_and_field_number_length](size_t sum,
                                            const MessageT& message) {
          const size_t message_size = message.ByteSizeLong();
          return sum + message_size + VarintLength(message_size) +
                 wire_type_and_field_number_length;
        });
  }

  const std::vector<MessageT>& values() const { return values_; }
  std::vector<MessageT>& values() { return values_; }

 private:
  std::vector<MessageT> values_;
};

template <typename MessageT>
class MessageOwningFieldWithPresence : public OwningField {
 public:
  explicit MessageOwningFieldWithPresence(int field_number)
      : OwningField(field_number, WireType::kLengthDelimited) {}

  // Copyable and movable.
  MessageOwningFieldWithPresence(const MessageOwningFieldWithPresence&) =
      default;
  MessageOwningFieldWithPresence& operator=(
      const MessageOwningFieldWithPresence&) = default;
  MessageOwningFieldWithPresence(MessageOwningFieldWithPresence&&) noexcept =
      default;
  MessageOwningFieldWithPresence& operator=(
      MessageOwningFieldWithPresence&&) noexcept = default;

  void Clear() override { value_.reset(); }

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
    if (!value_.has_value()) {
      value_.emplace();
    }
    return value_->Parse(submessage_parsing_state);
  }

  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    if (!value_.has_value()) {
      return absl::OkStatus();
    }
    if (absl::Status result =
            SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
        !result.ok()) {
      return result;
    }
    const size_t size = value_->ByteSizeLong();
    if (absl::Status result = SerializeVarint(size, out); !result.ok()) {
      return result;
    }
    if (out.GetBuffer().size() < size) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
    }
    // Serialize the message.
    if (!value_->Serialize(out)) {
      return absl::InternalError("Failed to serialize message");
    }
    return absl::OkStatus();
  }

  size_t GetSerializedSizeIncludingTag() const override {
    if (!value_.has_value()) {
      return 0;
    }
    const size_t size = value_->ByteSizeLong();
    return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
           VarintLength(size) + size;
  }

  // See https://protobuf.dev/reference/cpp/cpp-generated/#embeddedmessage.
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
    return &*value_;
  }

 private:
  absl::optional<MessageT> value_ = absl::nullopt;

  const MessageT& DefaultValue() const {
    static const absl::NoDestructor<MessageT> default_value;
    return *default_value;
  }
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_MESSAGE_H_
