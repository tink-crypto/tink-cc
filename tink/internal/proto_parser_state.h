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

#ifndef TINK_INTERNAL_PROTO_PARSER_STATE_H_
#define TINK_INTERNAL_PROTO_PARSER_STATE_H_

#include <cstddef>
#include <cstdint>

#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/call_with_core_dump_protection.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Maintains the current state of parsing (except for the data that can already
// be written into the resulting struct).
//
// It maintains the data being parsed plus optionally a CRC32C of all the data
// that was parsed.
class ParsingState final {
 public:
  explicit ParsingState(absl::string_view serialization_to_parse)
      : remaining_view_to_parse_(serialization_to_parse),
        crc_to_update_(nullptr) {}

  // Creates a new parsing state which maintains the crc of the parsed data.
  // Whenever Advance or AdvanceGetCrc is called, `crc_to_update` is
  // updated with it. This is done consistently with the value of AdvanceGetCrc.
  // All the CRC calculations are done within a CallWithCoreDumpProtection.
  explicit ParsingState(absl::string_view serialization_to_parse,
                        absl::crc32c_t* /*absl_nonnull - not yet supported*/ crc_to_update)
      : remaining_view_to_parse_(serialization_to_parse),
        crc_to_update_(crc_to_update) {}

  // Returns true if there is no more data to be parsed.
  bool ParsingDone() const { return remaining_view_to_parse_.empty(); }

  // Returns the remaining data to be parsed.
  absl::string_view RemainingData() const { return remaining_view_to_parse_; }

  // Removes the next `length` bytes from the data to be parsed. Updates the
  // internal CRC if any.
  void Advance(size_t length) {
    if (crc_to_update_ != nullptr) {
      CallWithCoreDumpProtection([&]() {
        *crc_to_update_ = absl::ConcatCrc32c(
            *crc_to_update_,
            absl::ComputeCrc32c(remaining_view_to_parse_.substr(0, length)),
            length);
      });
    }
    remaining_view_to_parse_.remove_prefix(length);
  }

  // Returns true if this ParsingState maintains a CRC on every call to Advance
  // and AdvanceAndGetCrc.
  bool HasCrc() const { return crc_to_update_ != nullptr; }

  // Removes the next `length` bytes from the data to be parsed and returns
  // their CRC. Updates the internal CRC, if any.
  // NOTE:
  //  *  The returned CRC is in a register or on the stack, and hence this
  //     method should only be called in CallWithCoreDumpProtection in case the
  //     CRC is sensitive.
  absl::crc32c_t AdvanceAndGetCrc(size_t length);

  // Returns the next byte without removing it from the data to be parsed.
  // Must not be called if |ParsingDone|.
  uint8_t PeekByte() const {
    return static_cast<uint8_t>(*remaining_view_to_parse_.begin());
  }

  // Splits off a state for a `length` bytes prefix that represent a
  // submessage.
  //
  // Parsing of the submessage state *must* be finished before any other
  // function of this state can be called: the submessage state shares the
  // computed CRC with this state, and the CRC is only updated correctly if
  // the parsing happens in order.
  ParsingState SplitOffSubmessageState(size_t length) {
    ParsingState result = ParsingState(
        remaining_view_to_parse_.substr(0, length), crc_to_update_);
    remaining_view_to_parse_.remove_prefix(length);
    return result;
  }

 private:
  absl::string_view remaining_view_to_parse_;
  absl::crc32c_t* /*absl_nullable - not yet supported*/ crc_to_update_;
};

// Maintains the current state when serializing a struct.
//
// This maintains a Span<char> which contains the remaining buffer to write into
// when serializing a struct.
class SerializationState final {
 public:
  explicit SerializationState(absl::Span<char> output_buffer)
      : output_buffer_(output_buffer), crc_to_update_(nullptr) {}

  // Creates a new serialization state which maintains the CRC of the parsed
  // data. Whenever Advance or AdvanceWithCrc is called, `crc_to_update_` is
  // updated, if not nullptr. For AdvanceWithCrc, the passed in CRC is used.
  // All the CRC calculations are done within a CallWithCoreDumpProtection.
  explicit SerializationState(absl::Span<char> output_buffer,
                              absl::crc32c_t* /*absl_nonnull - not yet supported*/ crc_to_update)
      : output_buffer_(output_buffer), crc_to_update_(crc_to_update) {}

  // Returns the remaining data to be parsed.
  absl::Span<char> GetBuffer() { return output_buffer_; }

  // Returns true if this ParsingState maintains a CRC on every call to Advance
  // and AdvanceWithCrc.
  bool HasCrc() const { return crc_to_update_ != nullptr; }

  // Removes the next `length` bytes from the data to be parsed. Updates the
  // internal CRC if any.
  void Advance(size_t length) {
    if (crc_to_update_ == nullptr) {
      output_buffer_.remove_prefix(length);
      return;
    }
    CallWithCoreDumpProtection([&]() {
      absl::crc32c_t crc =
          absl::ComputeCrc32c(absl::string_view(output_buffer_.data(), length));
      AdvanceWithCrc(length, crc);
    });
  }

  // Removes the next `length` bytes from the data to be parsed and updates the
  // internal CRC, if any, with `crc`.
  //
  // NOTE:
  //  *  This method does not compute the actual CRC of the removed data, only
  //     uses `crc`.
  //  *  This passes the CRC in a register or on the stack, and hence should
  //     only be called in CallWithCoreDumpProtection in case the CRC is
  //     sensitive.
  void AdvanceWithCrc(size_t length, absl::crc32c_t crc);

 private:
  absl::Span<char> output_buffer_;
  absl::crc32c_t* /*absl_nullable - not yet supported*/ crc_to_update_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_STATE_H_
