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

#ifndef TINK_INTERNAL_PROTO_PARSER_STRING_LIKE_HELPERS_H_
#define TINK_INTERNAL_PROTO_PARSER_STRING_LIKE_HELPERS_H_

#include <algorithm>
#include <cstddef>
#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"

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
inline void ClearStringLikeValue(std::string& s) { s.clear(); }
inline void ClearStringLikeValue(absl::string_view& b) {
  b = absl::string_view("");
}

// Copies the first argument into the second.
inline void CopyIntoStringLikeValue(absl::string_view sv, std::string& s) {
  s = std::string(sv);
}
inline void CopyIntoStringLikeValue(absl::string_view sv,
                                    absl::string_view& dest) {
  dest = sv;
}

// Returns the size of the string like value.
inline size_t SizeOfStringLikeValue(const std::string& s) { return s.size(); }
inline size_t SizeOfStringLikeValue(absl::string_view b) { return b.size(); }

// Serialize the string from the first argument into the second.
// Behavior in case that first.size() > second.size() is unimportant -- it will
// never be called like this.
inline void SerializeStringLikeValue(const std::string& s, absl::Span<char> o) {
  s.copy(o.data(), std::min(s.size(), o.size()));
}
inline void SerializeStringLikeValue(absl::string_view s, absl::Span<char> o) {
  s.copy(o.data(), std::min(s.size(), o.size()));
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_STRING_LIKE_HELPERS_H_
