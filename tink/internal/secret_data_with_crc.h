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
#include <cstdint>
#include <utility>

#include "absl/base/macros.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_data_internal_class.h"

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

  // Creates a new SecretDataWithCrc computing the CRC of the `data`.
  //
  // The CRC is computed in a CallWithCoreDumpProtection.
  //
  // Complexity: O(n) -- must make a string copy
  explicit SecretDataWithCrc(absl::string_view data) : data_(data) {}
  explicit SecretDataWithCrc(crypto::tink::util::SecretData data)
      : data_(std::move(data)) {}

  // Creates a new SecretDataWithCrc.
  // If an adversary can control the provided crc, they might be able to obtain
  // information about the secret (since they can provide a wrong CRC and some
  // call will fail). The caller needs to ensure that this is not the case.
  //
  // Should only be called within CallWithCoreDumpProtection, as it passes
  // the CRC on the stack.
  //
  // Complexity: O(n) -- must make a string copy
  explicit SecretDataWithCrc(absl::string_view data, absl::crc32c_t crc)
      : data_(data, crc) {}
  // Complexity: O(n) -- if `buffer` is a copied. Otherwise, O(1).
  explicit SecretDataWithCrc(SecretBuffer buffer, absl::crc32c_t crc)
      : data_(std::move(buffer), crc) {}

  // Creates a new SecretDataWithCrc.
  // If an adversary can control the provided crc, they might be able to obtain
  // information about the secret (since they can provide a wrong CRC and some
  // call will fail). The caller needs to ensure that this is not the case.
  explicit SecretDataWithCrc(
      crypto::tink::util::SecretData data,
      crypto::tink::util::SecretValue<absl::crc32c_t> crc) {
    crypto::tink::internal::CallWithCoreDumpProtection([&]() {
      data_ = crypto::tink::util::internal::SecretDataInternalClass(
          util::internal::AsSecretBuffer(std::move(data)), crc.value());
    });
  }

  // Returns the data without verifying the CRC32C.
  absl::string_view AsStringView() const { return data_.AsStringView(); }

  const uint8_t& operator[](size_t pos) const { return data_[pos]; }
  const uint8_t* data() const { return data_.data(); }

  // Returns the currently stored CRC.
  // Should only be called within CallWithCoreDumpProtection (as it passes
  // secret data -- the CRC -- on the stack or in the register).
  // Runtime: O(1)
  absl::crc32c_t GetCrc32c() const { return data_.GetCrc32c(); }
  ABSL_DEPRECATE_AND_INLINE()
  absl::Status ValidateCrc() const { return ValidateCrc32c(); }
  absl::Status ValidateCrc32c() const { return data_.ValidateCrc32c(); }

  bool empty() const { return data_.empty(); }
  size_t size() const { return data_.size(); }

  bool operator==(const SecretDataWithCrc& other) const {
    return data_ == other.data_;
  }
  bool operator!=(const SecretDataWithCrc& other) const {
    return !(*this == other);
  }

 private:
  crypto::tink::util::internal::SecretDataInternalClass data_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SECRET_DATA_WITH_CRC_H_
