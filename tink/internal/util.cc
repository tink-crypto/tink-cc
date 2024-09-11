// Copyright 2021 Google LLC
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
#include "tink/internal/util.h"

#include <iterator>
#include <functional>

#include "absl/strings/ascii.h"
#include "absl/log/log.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace internal {

absl::string_view EnsureStringNonNull(absl::string_view str) {
  if (str.empty() && str.data() == nullptr) {
    return absl::string_view("");
  }
  return str;
}

bool BuffersOverlap(absl::string_view first, absl::string_view second) {
  // first begins within second's buffer.
  const bool first_begins_in_second = first.data() >= second.data() && first.data() < second.data() + second.size();

  // second begins within first's buffer.
  const bool second_begins_in_first = second.data() >= first.data() && second.data() < first.data() + first.size();

  return first_begins_in_second || second_begins_in_first;
}

bool BuffersAreIdentical(absl::string_view first, absl::string_view second) {
  return !first.empty() && !second.empty() && first.data() == second.data() && first.size() == second.size();
}

bool IsPrintableAscii(absl::string_view input) {
  for (char c : input) {
    if (!absl::ascii_isprint(c) || absl::ascii_isspace(c)) {
      return false;
    }
  }
  return true;
}

void LogFatal(absl::string_view msg) {
  LOG(FATAL) <<  msg;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
