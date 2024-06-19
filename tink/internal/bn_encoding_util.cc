// Copyright 2023 Google LLC
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
#include "tink/internal/bn_encoding_util.h"

#include <cstring>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/internal/safe_stringops.h"
#include "tink/restricted_big_integer.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<std::string> GetValueOfFixedLength(
    absl::string_view big_integer_encoding, int length) {
  if (big_integer_encoding.size() == length) {
    return std::string(big_integer_encoding);
  }

  if (big_integer_encoding.size() > length) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "Value too large for the given length. Expected %d, got %d", length,
            big_integer_encoding.size()));
  }

  std::string padded_string(length - big_integer_encoding.size(), 0);
  return absl::StrCat(padded_string, big_integer_encoding);
}

util::StatusOr<util::SecretData> GetSecretValueOfFixedLength(
    const RestrictedBigInteger& big_integer, int length,
    SecretKeyAccessToken token) {
  if (big_integer.SizeInBytes() == length) {
    return util::SecretDataFromStringView(big_integer.GetSecret(token));
  }

  if (big_integer.SizeInBytes() > length) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "Value too large for the given length. Expected %d, got %d", length,
            big_integer.SizeInBytes()));
  }

  util::SecretData padded(length, 0);
  crypto::tink::internal::SafeMemCopy(
      padded.data() + length - big_integer.SizeInBytes(),
      big_integer.GetSecret(token).data(), big_integer.GetSecret(token).size());
  return padded;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
