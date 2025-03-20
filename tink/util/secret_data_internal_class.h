// Copyright 2025 Google LLC
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

#ifndef TINK_UTIL_SECRET_DATA_INTERNAL_CLASS_H_
#define TINK_UTIL_SECRET_DATA_INTERNAL_CLASS_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

#include "absl/base/internal/endian.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/secret_buffer.h"

namespace crypto {
namespace tink {
namespace util {

namespace internal {

// Forward-declarations for the friend declaration below.
class SecretDataInternalClass;
SecretDataInternalClass SecretDataInternalClassFromStringView(
    absl::string_view secret);

// SecretData stores data which should not be leaked in core dumps.
// Within Google, we achieve this by hooking into core dump collection.
// In OSS Tink, SecretData overwrites the memory contents when the destructor
// is invoked.
class SecretDataInternalClass {
 public:
  using value_type = uint8_t;
  using const_reference = const uint8_t&;
  using const_iterator = const uint8_t*;

  static constexpr size_t kMaxCount = std::numeric_limits<size_t>::max();

  SecretDataInternalClass() = default;
  explicit SecretDataInternalClass(size_t size, uint8_t value = 0)
      : SecretDataInternalClass(
            crypto::tink::internal::SecretBuffer(size, value)) {}
  SecretDataInternalClass(const SecretDataInternalClass& other) {
    *this = other;
  }
  SecretDataInternalClass(SecretDataInternalClass&& other) noexcept {
    *this = std::move(other);
  }
  SecretDataInternalClass& operator=(const SecretDataInternalClass& other) {
    if (this != &other) {
      buffer_ = other.buffer_;
      if (!buffer_.empty()) {
        crypto::tink::internal::SafeMemCopy(crc32c_data(), other.crc32c_data(),
                                            sizeof(uint32_t));
      }
    }
    return *this;
  }
  SecretDataInternalClass& operator=(SecretDataInternalClass&& other) noexcept {
    swap(other);
    return *this;
  }

  explicit SecretDataInternalClass(absl::string_view view)
      : SecretDataInternalClass(crypto::tink::internal::SecretBuffer(view)) {}

  explicit SecretDataInternalClass(absl::Span<const uint8_t> span)
      : SecretDataInternalClass(crypto::tink::internal::SecretBuffer(span)) {}

  explicit SecretDataInternalClass(crypto::tink::internal::SecretBuffer other)
      : buffer_(std::move(other)) {
    if (!buffer_.empty()) {
      crypto::tink::internal::CallWithCoreDumpProtection([this] {
        absl::crc32c_t crc = absl::ComputeCrc32c(AsStringView());
        absl::big_endian::Store32(crc32c_data(), static_cast<uint32_t>(crc));
      });
    }
  }

  // Constructs a SecretDataInternalClass with the given `view` and `crc32c`.
  //
  // NOTE:
  //  * This is not core-dump-safe as the CRC32C may leak; it should only be
  //  called within a CallWithCoreDumpProtection.
  //  * if `view` is empty, `crc32c` is ignored and always considered to be 0.
  explicit SecretDataInternalClass(absl::string_view view,
                                   absl::crc32c_t crc32c)
      : SecretDataInternalClass(crypto::tink::internal::SecretBuffer(view),
                                crc32c) {}
  // Constructs a SecretDataInternalClass with the given `span` and `crc32c`.
  //
  // NOTE:
  //  * This is not core-dump-safe as the CRC32C may leak; it should only be
  //  called within a CallWithCoreDumpProtection.
  //  * if `span` is empty, `crc32c` is ignored and always considered to be 0.
  explicit SecretDataInternalClass(absl::Span<const uint8_t> span,
                                   absl::crc32c_t crc32c)
      : SecretDataInternalClass(crypto::tink::internal::SecretBuffer(span),
                                crc32c) {}
  // Constructs a SecretDataInternalClass with the given `buffer` and `crc32c`.
  //
  // NOTE:
  //  * This is not core-dump-safe as the CRC32C may leak; it should only be
  //  called within a CallWithCoreDumpProtection.
  //  * if `buffer` is empty, `crc32c` is ignored and always considered to be 0.
  explicit SecretDataInternalClass(crypto::tink::internal::SecretBuffer buffer,
                                   absl::crc32c_t crc32c)
      : buffer_(std::move(buffer)) {
    if (!buffer_.empty()) {
      absl::big_endian::Store32(crc32c_data(), static_cast<uint32_t>(crc32c));
    }
  }

  ~SecretDataInternalClass() = default;

  const uint8_t& operator[](size_t pos) const { return buffer_[pos]; }

  const uint8_t* data() const { return buffer_.data(); }

  const_iterator begin() const { return buffer_.data(); }
  const_iterator end() const { return buffer_.data() + buffer_.size(); }

  absl::string_view AsStringView() const { return buffer_.AsStringView(); }

  bool empty() const { return buffer_.empty(); }
  size_t size() const { return buffer_.size(); }
  size_t max_size() const { return kMaxCount; }
  size_t capacity() const { return buffer_.capacity(); }
  void clear() { buffer_.clear(); }

  void swap(SecretDataInternalClass& other) noexcept {
    using std::swap;
    swap(buffer_, other.buffer_);
  }

  crypto::tink::internal::SecretBuffer AsSecretBuffer() const& {
    return buffer_;
  }

  crypto::tink::internal::SecretBuffer AsSecretBuffer() && {
    crypto::tink::internal::SecretBuffer res = std::move(buffer_);
    return res;
  }

  // Returns the CRC32C of the data.
  //
  // NOTE: This function is not core-dump-safe as the CRC32C may leak. It should
  // only be called within a CallWithCoreDumpProtection.
  absl::crc32c_t GetCrc32c() const {
    if (crc32c_data() == nullptr) {
      return absl::crc32c_t(0);
    }
    return absl::crc32c_t(absl::big_endian::Load32(crc32c_data()));
  }

  absl::Status ValidateCrc32c() const {
    return crypto::tink::internal::CallWithCoreDumpProtection([this]() {
      absl::crc32c_t crc = absl::ComputeCrc32c(buffer_.AsStringView());
      absl::crc32c_t stored_crc = GetCrc32c();
      if (crc != stored_crc) {
        return absl::DataLossError("CRC32C mismatch");
      }
      return absl::OkStatus();
    });
  }

  // Compares the first `size()` bytes + the CRC32C. Ignores the capacity of the
  // buffers.
  bool operator==(const SecretDataInternalClass& other) const {
    if (empty() && other.empty()) {
      return true;
    }
    if (size() != other.size()) {
      return false;
    }
    return crypto::tink::internal::SafeCryptoMemEquals(
        data(), other.data(), size() + sizeof(uint32_t));
  }
  bool operator!=(const SecretDataInternalClass& other) const {
    return !(*this == other);
  }

  friend void swap(SecretDataInternalClass& lhs,
                   SecretDataInternalClass& rhs) noexcept {
    lhs.swap(rhs);
  }

 private:
  friend SecretDataInternalClass SecretDataInternalClassFromStringView(
      absl::string_view secret);

  uint8_t* crc32c_data() {
    if (buffer_.empty()) {
      return nullptr;
    }
    return buffer_.data() + buffer_.size();
  }
  const uint8_t* crc32c_data() const {
    if (buffer_.empty()) {
      return nullptr;
    }
    return buffer_.data() + buffer_.size();
  }

  crypto::tink::internal::SecretBuffer buffer_;
};

inline SecretDataInternalClass SecretDataInternalClassFromStringView(
    absl::string_view secret) {
  return SecretDataInternalClass(secret);
}

}  // namespace internal
}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_SECRET_DATA_INTERNAL_CLASS_H_
