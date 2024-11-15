// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_SECRET_DATA_WITH_CRC_H_
#define TINK_INTERNAL_SECRET_DATA_WITH_CRC_H_

#include <cstddef>
#include <utility>

#include "absl/crc/crc32c.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

// A wrapper around a SecretData with a CRC32C.
//
// This class is thread-compatible.
class SecretDataWithCrc final {
 public:
  // Copyable and movable.
  SecretDataWithCrc() = default;
  SecretDataWithCrc(const SecretDataWithCrc&) = default;
  SecretDataWithCrc& operator=(const SecretDataWithCrc&) = default;
  SecretDataWithCrc(SecretDataWithCrc&& other) = default;
  SecretDataWithCrc& operator=(SecretDataWithCrc&& other) noexcept = default;

  // Creates a new SecretDataWithCrc and computes the CRC (in a
  // CallWithCoreDumpProtection).
  static SecretDataWithCrc WithComputedCrc(absl::string_view data);

  // Creates a new SecretDataWithCrc and computes the CRC (in a
  // CallWithCoreDumpProtection).
  // Note: this overload will eventually be removed (as users should instead)
  // call "ComputeAndSetCrc()".
  static SecretDataWithCrc WithComputedCrc(crypto::tink::util::SecretData data);

  // Creates a new SecretDataWithCrc.
  // If an adversary can control the provided crc, they might be able to obtain
  // information about the secret (since they can provide a wrong CRC and some
  // call will fail). The caller needs to ensure that this is not the case.
  explicit SecretDataWithCrc(
      absl::string_view data,
      absl::optional<crypto::tink::util::SecretValue<absl::crc32c_t>> crc =
          absl::nullopt);
  // Creates a new SecretDataWithCrc.
  // If an adversary can control the provided crc, they might be able to obtain
  // information about the secret (since they can provide a wrong CRC and some
  // call will fail). The caller needs to ensure that this is not the case.
  explicit SecretDataWithCrc(
      crypto::tink::util::SecretData data,
      absl::optional<crypto::tink::util::SecretValue<absl::crc32c_t>> crc =
          absl::nullopt);

  // Verifies the CRC32C of the data before returning it.
  absl::StatusOr<absl::string_view> data() const;

  // Returns the data without verifying the CRC32C.
  absl::string_view UncheckedData() const;

  // Returns the data without verifying the CRC32C. Leaves the object in an
  // invalid state.
  crypto::tink::util::SecretData UncheckedAsSecretData() && {
    return std::move(data_);
  }

  const crypto::tink::util::SecretData& UncheckedAsSecretData() const& {
    return data_;
  }

  crypto::tink::util::SecretValue<absl::crc32c_t> SecretCrc() const {
    return crc_;
  }
  size_t size() const { return data_.size(); }

 private:
  crypto::tink::util::SecretData data_;
  crypto::tink::util::SecretValue<absl::crc32c_t> crc_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SECRET_DATA_WITH_CRC_H_
