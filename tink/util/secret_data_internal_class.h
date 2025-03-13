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

#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/sanitizing_allocator.h"
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
      *this = SecretDataInternalClass(other.AsStringView());
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

  explicit SecretDataInternalClass(
      crypto::tink::internal::SecretBuffer other) noexcept {
    using std::swap;
    swap(data_, other.data_);
    swap(size_, other.size_);
    swap(capacity_, other.capacity_);
  }

  ~SecretDataInternalClass() {
    if (data_ != nullptr) {
      internal::SanitizingAllocator<uint8_t>().deallocate(data_, capacity_);
    }
  }

  const uint8_t& operator[](size_t pos) const {
    CHECK(pos < size_) << "SecretData::operator[] pos out of bounds";
    return data_[pos];
  }

  const uint8_t* data() const { return data_; }

  const_iterator begin() const { return data_; }
  const_iterator end() const { return data_ + size_; }

  absl::string_view AsStringView() const {
    return absl::string_view(reinterpret_cast<const char*>(data()), size());
  }

  bool empty() const { return size_ == 0; }
  size_t size() const { return size_; }
  size_t max_size() const { return kMaxCount; }
  void reserve(size_t new_cap) {
    if (new_cap <= capacity_) {
      return;
    }
    uint8_t* new_data =
        internal::SanitizingAllocator<uint8_t>().allocate(new_cap);
    CHECK(new_data != nullptr);
    if (data_ != nullptr) {
      ::crypto::tink::internal::SafeMemCopy(new_data, data_, size_);
      internal::SanitizingAllocator<uint8_t>().deallocate(data_, capacity_);
    }
    data_ = new_data;
    capacity_ = new_cap;
  }
  size_t capacity() const { return capacity_; }

  void clear() { size_ = 0; }
  void resize(size_t size, uint8_t val = 0) {
    if (size > size_) {
      reserve(size);
      memset(data_ + size_, val, size - size_);
    }
    size_ = size;
  }
  void swap(SecretDataInternalClass& other) noexcept {
    using std::swap;
    swap(data_, other.data_);
    swap(size_, other.size_);
    swap(capacity_, other.capacity_);
  }

  ::crypto::tink::internal::SecretBuffer AsSecretBuffer() const& {
    return ::crypto::tink::internal::SecretBuffer(AsStringView());
  }

  ::crypto::tink::internal::SecretBuffer AsSecretBuffer() && {
    ::crypto::tink::internal::SecretBuffer result;
    using std::swap;
    swap(result.data_, data_);
    swap(result.size_, size_);
    swap(result.capacity_, capacity_);
    return result;
  }

  bool operator==(const SecretDataInternalClass& other) const {
    return size_ == other.size_ &&
           ::crypto::tink::internal::SafeCryptoMemEquals(data_, other.data_,
                                                         size_);
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

  uint8_t* data_ = nullptr;
  size_t size_ = 0;
  size_t capacity_ = 0;
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
