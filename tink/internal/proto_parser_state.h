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
#include "tink/util/secret_data.h"

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
                        absl::Nonnull<absl::crc32c_t*> crc_to_update)
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

  // Removes the next `length` bytes from the data to be parsed and returns
  // their CRC. Updates the internal CRC, if any.
  util::SecretValue<absl::crc32c_t> AdvanceAndGetCrc(size_t length);

  // Returns the next byte without removing it from the data to be parsed.
  // Must not be called if |ParsingDone|.
  uint8_t PeekByte() const {
    return static_cast<uint8_t>(*remaining_view_to_parse_.begin());
  }

 private:
  absl::string_view remaining_view_to_parse_;
  absl::Nullable<absl::crc32c_t*> crc_to_update_;
};

// Maintains the current state when serializing a struct.
//
// This maintains a Span<char> which contains the remaining buffer to write into
// when serializing a struct.
class SerializationState final {
 public:
  explicit SerializationState(absl::Span<char> output_buffer)
      : output_buffer_(output_buffer) {}

  // Returns the remaining data to be parsed.
  absl::Span<char> GetBuffer() { return output_buffer_; }

  // Removes the next `length` bytes from the data to be parsed. Updates the
  // internal CRC if any.
  void Advance(size_t length) {
    output_buffer_.remove_prefix(length);
  }

 private:
  absl::Span<char> output_buffer_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_STATE_H_
