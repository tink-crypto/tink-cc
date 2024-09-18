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

#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Maintains the current state of parsing (except for the data which can already
// be written into the resulting struct).
//
// Currently, this means we just maintain what data still needs to be parsed.
class ParsingState final {
 public:
  explicit ParsingState(absl::string_view serialization_to_parse)
      : remaining_view_to_parse_(serialization_to_parse) {}

  // Returns true if there is no more data to be parsed.
  bool ParsingDone() const { return remaining_view_to_parse_.empty(); }

  // Returns the remaining data to be parsed.
  absl::string_view RemainingData() const { return remaining_view_to_parse_; }

  // Removes the next s bytes from the data to be parsed.
  void Advance(size_t s) { remaining_view_to_parse_.remove_prefix(s); }

  // Returns the next byte without removing it from the data to be parsed.
  // Must not be called if |ParsingDone|.
  uint8_t PeekByte() const {
    return static_cast<uint8_t>(*remaining_view_to_parse_.begin());
  }

 private:
  absl::string_view remaining_view_to_parse_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_STATE_H_
