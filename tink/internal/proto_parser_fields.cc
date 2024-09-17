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

#include "tink/internal/proto_parser_fields.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/restricted_big_integer.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

void ClearStringLikeValue(std::string& s) { s.clear(); }
void ClearStringLikeValue(util::SecretData& s) { s.clear(); }
void ClearStringLikeValue(absl::string_view& b) { b = absl::string_view(""); }

void CopyIntoStringLikeValue(absl::string_view sv, std::string& s) {
  s = std::string(sv);
}

void CopyIntoStringLikeValue(absl::string_view sv, util::SecretData& s) {
  s = util::SecretDataFromStringView(sv);
}

void CopyIntoStringLikeValue(absl::string_view sv, absl::string_view& dest) {
  dest = sv;
}

size_t SizeOfStringLikeValue(const std::string& s) { return s.size(); }
size_t SizeOfStringLikeValue(const util::SecretData& s) { return s.size(); }
size_t SizeOfStringLikeValue(const absl::string_view& b) { return b.size(); }

void SerializeStringLikeValue(const std::string& s, absl::Span<char> o) {
  memcpy(o.data(), s.data(), std::min(s.size(), o.size()));
}
void SerializeStringLikeValue(const util::SecretData& s, absl::Span<char> o) {
  SafeMemCopy(o.data(), s.data(), std::min(s.size(), o.size()));
}
void SerializeStringLikeValue(const absl::string_view& s, absl::Span<char> o) {
  memcpy(o.data(), s.data(), std::min(s.size(), o.size()));
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
