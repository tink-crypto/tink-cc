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

#ifndef TINK_INTERNAL_PROTO_PARSER_FIELDS_H_
#define TINK_INTERNAL_PROTO_PARSER_FIELDS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Methods to parse a field in a proto message into some member in the struct
// "Struct".
//
// A Fields<Struct> has a method ConsumeIntoMember which populates exactly one
// member variable of the struct and some helper methods to facilitate this.
template <typename Struct>
class Field {
 public:
  virtual ~Field() = default;

  // Clears the field.
  virtual void ClearMember(Struct& values) const = 0;

  // Parse the serialization into the member managed by this field.
  //
  // The passed in |serialization| contains always data
  // after the initial bytes describing the "wire type and tag". If the wire
  // type is kLengthDelimited, "serialized" contains only the data of the
  // field. Otherwise, it contains all the data of the remaining serialized
  // message. The processed data needs to be removed.
  virtual absl::Status ConsumeIntoMember(absl::string_view& serialized,
                                         Struct& values) const = 0;

  // Returns true if the field needs to be serialized (i.e. is not the default).
  virtual bool RequiresSerialization(const Struct& values) const = 0;
  // Serializes the member into out, and removes the part which was written
  // on from out.
  virtual absl::Status SerializeInto(absl::Span<char>& out,
                                     const Struct& values) const = 0;
  // Returns the required size for SerializeInto.
  virtual size_t GetSerializedSize(const Struct& values) const = 0;

  virtual WireType GetWireType() const = 0;
  virtual int GetTag() const = 0;
};

// A field where the member variable is a uint32_t and the wire type is
// kVarint.
template <typename Struct>
class Uint32Field : public Field<Struct> {
 public:
  explicit Uint32Field(int tag, uint32_t Struct::*value,
                       ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : value_(value), tag_(tag), options_(options) {}

  // Not copyable, not movable.
  Uint32Field(const Uint32Field&) = delete;
  Uint32Field& operator=(const Uint32Field&) = delete;
  Uint32Field(Uint32Field&&) noexcept = delete;
  Uint32Field& operator=(Uint32Field&&) noexcept = delete;

  void ClearMember(Struct& s) const override { s.*value_ = 0; }

  absl::Status ConsumeIntoMember(absl::string_view& serialized,
                                 Struct& s) const override {
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
    if (!result.ok()) {
      return result.status();
    }
    s.*value_ = *result;
    return absl::OkStatus();
  }

  bool RequiresSerialization(const Struct& values) const override {
    return options_ == ProtoFieldOptions::kAlwaysSerialize ||
           values.*value_ != 0;
  }

  absl::Status SerializeInto(absl::Span<char>& out,
                             const Struct& values) const override {
    return SerializeVarint(values.*value_, out);
  }

  size_t GetSerializedSize(const Struct& values) const override {
    return VarintLength(values.*value_);
  }

  WireType GetWireType() const override { return WireType::kVarint; }
  int GetTag() const override { return tag_; }

 private:
  uint32_t Struct::*value_;
  int tag_;
  ProtoFieldOptions options_;
};

// A field where the member variable is a std::string and the wire type is
// kLengthDelimited.
template <typename Struct>
class StringBytesField : public Field<Struct> {
 public:
  explicit StringBytesField(
      int tag, std::string Struct::*value,
      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : value_(value), tag_(tag), options_(options) {}
  // Not copyable and movable.
  StringBytesField(const StringBytesField&) = delete;
  StringBytesField& operator=(const StringBytesField&) = delete;
  StringBytesField(StringBytesField&&) noexcept = delete;
  StringBytesField& operator=(StringBytesField&&) noexcept = delete;

  void ClearMember(Struct& s) const override { s.*value_ = ""; }

  absl::Status ConsumeIntoMember(absl::string_view& serialized,
                                 Struct& s) const override {
    absl::StatusOr<absl::string_view> result =
        ConsumeBytesReturnStringView(serialized);
    if (!result.ok()) {
      return result.status();
    }
    s.*value_ = std::string(*result);
    return absl::OkStatus();
  }

  bool RequiresSerialization(const Struct& values) const override {
    return options_ == ProtoFieldOptions::kAlwaysSerialize ||
           !(values.*value_).empty();
  }

  absl::Status SerializeInto(absl::Span<char>& out,
                             const Struct& values) const override {
    size_t size = (values.*value_).size();
    absl::Status s = SerializeVarint(size, out);
    if (!s.ok()) {
      return s;
    }
    if (out.size() < size) {
      return absl::InvalidArgumentError(
          absl::StrCat("Output buffer too small: ", out.size(), " < ", size));
    }
    memcpy(out.data(), (values.*value_).data(), size);
    out.remove_prefix(size);
    return absl::OkStatus();
  }

  size_t GetSerializedSize(const Struct& values) const override {
    size_t size = (values.*value_).size();
    return VarintLength(size) + size;
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
  int GetTag() const override { return tag_; }

 private:
  std::string Struct::*value_;
  int tag_;
  ProtoFieldOptions options_;
};

// A field where the member variable is a SecretData and the wire type is
// kLengthDelimited.
template <typename Struct>
class SecretDataBytesField : public Field<Struct> {
 public:
  explicit SecretDataBytesField(
      int tag, crypto::tink::util::SecretData Struct::*value,
      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : value_(value), tag_(tag), options_(options) {}
  // Copyable and movable.
  SecretDataBytesField(const SecretDataBytesField&) = default;
  SecretDataBytesField& operator=(const SecretDataBytesField&) = default;
  SecretDataBytesField(SecretDataBytesField&&) noexcept = default;
  SecretDataBytesField& operator=(SecretDataBytesField&&) noexcept = default;

  void ClearMember(Struct& s) const override {
    s.*value_ = crypto::tink::util::SecretData();
  }

  absl::Status ConsumeIntoMember(absl::string_view& serialized,
                                 Struct& s) const override {
    absl::StatusOr<absl::string_view> result =
        ConsumeBytesReturnStringView(serialized);
    if (!result.ok()) {
      return result.status();
    }
    s.*value_ = crypto::tink::util::SecretDataFromStringView(*result);
    return absl::OkStatus();
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
  int GetTag() const override { return tag_; }

  bool RequiresSerialization(const Struct& values) const override {
    return options_ == ProtoFieldOptions::kAlwaysSerialize ||
           !(values.*value_).empty();
  }

  absl::Status SerializeInto(absl::Span<char>& out,
                             const Struct& values) const override {
    size_t size = (values.*value_).size();
    absl::Status s = SerializeVarint(size, out);
    if (!s.ok()) {
      return s;
    }
    if (out.size() < size) {
      return absl::InvalidArgumentError(
          absl::StrCat("Output buffer too small: ", out.size(), " < ", size));
    }
    SafeMemCopy(out.data(), (values.*value_).data(), size);
    out.remove_prefix(size);
    return absl::OkStatus();
  }

  size_t GetSerializedSize(const Struct& values) const override {
    size_t size = (values.*value_).size();
    return VarintLength(size) + size;
  }

 private:
  crypto::tink::util::SecretData Struct::*value_;
  int tag_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_FIELDS_H_
