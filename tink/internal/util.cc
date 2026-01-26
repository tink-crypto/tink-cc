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

#include <functional>
#include <iterator>
#include <utility>

#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/string_view.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

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
  const bool first_begins_in_second =
      std::greater_equal<const char*>{}(first.data(), second.data()) &&
      std::less<const char*>{}(first.data(), second.data() + second.size());

  // second begins within first's buffer.
  const bool second_begins_in_first =
      std::greater_equal<const char*>{}(second.data(), first.data()) &&
      std::less<const char*>{}(second.data(), first.data() + first.size());

  return first_begins_in_second || second_begins_in_first;
}

bool BuffersAreIdentical(absl::string_view first, absl::string_view second) {
  return !first.empty() && !second.empty() &&
         std::equal_to<const char*>{}(first.data(), second.data()) &&
         first.size() == second.size();
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
  ABSL_LOG(FATAL) <<  msg;
}

absl::StatusOr<SecretData> ParseBigIntToFixedLength(absl::string_view val,
                                                    int length) {
  if (length >= val.size()) {
    int start = length - val.size();
    SecretBuffer buffer(length, 0);
    SafeMemCopy(buffer.data() + start, val.data(), val.size());
    return util::internal::AsSecretData(std::move(buffer));
  } else {
    // val is longer than what we have room -- we need to check that val starts
    // with zeros. We use SafeCryptoMemEquals to minimize leakage in case it
    // does not.
    int to_truncate = val.size() - length;
    SecretBuffer zeros(to_truncate, 0);
    if (!SafeCryptoMemEquals(zeros.data(), val.data(), zeros.size())) {
      return absl::InvalidArgumentError("Integer too large");
    }
    val.remove_prefix(to_truncate);
    return util::SecretDataFromStringView(val);
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
