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

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/big_integer.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// To implement a BytesField storing in a "StringType", one needs to implement
// the following functions:
//  * void ClearStringLikeValue(StringType& s);
//  * void CopyIntoStringLikeValue(string_view from, StringType& to);
//  * size_t SizeOfStringLikeValue(const StringType& s);
//  * void SerializeStringLikeValue(const StringType& s, absl::Span<char> o);
// After this, one can use BytesField<Struct, StringType>.

// Clears the value.
void ClearStringLikeValue(std::string& s);
void ClearStringLikeValue(SecretData& s);
void ClearStringLikeValue(absl::string_view& b);

// Copies the first argument into the second.
void CopyIntoStringLikeValue(absl::string_view sv, std::string& s);
void CopyIntoStringLikeValue(absl::string_view sv, SecretData& s);
void CopyIntoStringLikeValue(absl::string_view sv, absl::string_view& dest);

// Returns the size of the string like value.
size_t SizeOfStringLikeValue(const std::string& s);
size_t SizeOfStringLikeValue(const SecretData& s);
size_t SizeOfStringLikeValue(absl::string_view b);

// Serialize the string from the first argument into the second.
// Behavior in case that first.size() > second.size() is unimportant -- it will
// never be called like this.
void SerializeStringLikeValue(const std::string& s, absl::Span<char> o);
void SerializeStringLikeValue(const SecretData& s, absl::Span<char> o);
void SerializeStringLikeValue(absl::string_view s, absl::Span<char> o);

// Methods to parse a field in a proto message into some member in the struct
// "Struct".
//
// A Fields<Struct> has a method ConsumeIntoMember which populates exactly one
// member variable of the struct and some helper methods to facilitate this.
template <typename Struct>
class Field {
 public:
  Field() = default;
  virtual ~Field() = default;

  // Copyable and movable.
  Field(const Field&) = default;
  Field& operator=(const Field&) = default;
  Field(Field&&) noexcept = default;
  Field& operator=(Field&&) noexcept = default;

  // Clears the field.
  virtual void ClearMember(Struct& values) const = 0;

  // Parse the serialization into the member managed by this field.
  //
  // The passed in |serialization| contains always data
  // after the initial bytes describing the "wire type and tag". If the wire
  // type is kLengthDelimited, "serialized" contains only the data of the
  // field. Otherwise, it contains all the data of the remaining serialized
  // message. The processed data needs to be removed.
  //
  // Returns true on success.
  ABSL_MUST_USE_RESULT
  virtual bool ConsumeIntoMember(ParsingState& serialized,
                                 Struct& values) const = 0;

  // Serializes the member into out, and removes the part which was written
  // on from out. Includes the tag of the field (the encoded wiretype/field
  // number). This is different from the parsing function "ConsumeIntoMember".
  virtual absl::Status SerializeWithTagInto(SerializationState& out,
                                            const Struct& values) const = 0;

  // Returns the required size for SerializeWithTagInto.
  virtual size_t GetSerializedSizeIncludingTag(const Struct& values) const = 0;
  virtual WireType GetWireType() const = 0;
  virtual int GetFieldNumber() const = 0;
};



}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_FIELDS_H_
