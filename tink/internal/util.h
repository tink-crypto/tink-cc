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
#ifndef TINK_INTERNAL_UTIL_H_
#define TINK_INTERNAL_UTIL_H_

#include <memory>

#include "absl/base/attributes.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/key.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

// Performs a DynamicCast on the input to an "S" and returns the unique pointer.
// If the input is null or not of dynamic type S, returns an error.
// This exists because when calling dynamic_cast on a unique pointer one needs
// to be careful to not leak memory in case the dynamic cast fails.
// TODO(b/480880036): Add source location to the error message.
template <typename S, typename T>
absl::StatusOr<std::unique_ptr<S>> DynamicCast(std::unique_ptr<T> in) {
  S* out = dynamic_cast<S*>(in.get());
  if (out == nullptr) {
    return absl::InternalError(
        absl::StrCat("Unable to perform CastOrError, passed in value is ",
                     (in == nullptr ? "null" : typeid(*in).name())));
  }
  in.release();
  return absl::WrapUnique(out);
}

// Clone a key of type T. May die if T::Clone doesn't return a T -- guaranteed
// to never happen for Tink implementations.
template <typename T>
std::unique_ptr<T> CloneKeyOrDie(const T& key) {
  static_assert(std::is_convertible_v<T*, Key*>);
  absl::StatusOr<std::unique_ptr<T>> result = DynamicCast<T>(key.Clone());
  ABSL_CHECK_OK(result);
  return std::move(*result);
}

// Return an empty string if str.data() is nullptr; otherwise return str.
absl::string_view EnsureStringNonNull(absl::string_view str);

// Returns true if `first` overlaps with `second`.
bool BuffersOverlap(absl::string_view first, absl::string_view second);

// Returns true if `first` fully overlaps with `second`.
bool BuffersAreIdentical(absl::string_view first, absl::string_view second);

// Returns true if `input` only contains printable ASCII characters (whitespace
// is not allowed).
bool IsPrintableAscii(absl::string_view input);

// Returns true if built on Windows; false otherwise.
inline bool IsWindows() {
#if defined(_WIN32)
  return true;
#else
  return false;
#endif
}

// Wraps Abseil's LOG(FATAL) macro and sets the [noreturn] attribute, which is
// useful for avoiding false positive [-Werror=return-type] compiler errors.
ABSL_ATTRIBUTE_NORETURN void LogFatal(absl::string_view msg);

// Converts a serialized big integer to a data of fixed length, padding or
// truncating leading zeros if needed. Returns an error if the integer encoded
// by `val` does not fit into a SecretData of length `length`. Otherwise,
// returns a SecretData of `length` bytes.
absl::StatusOr<SecretData> ParseBigIntToFixedLength(absl::string_view val,
                                                    int length);

// Remove all leading zeros of the input.
absl::string_view WithoutLeadingZeros(absl::string_view val);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_UTIL_H_
