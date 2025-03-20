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

#ifndef TINK_INTERNAL_SECRET_BUFFER_H_
#define TINK_INTERNAL_SECRET_BUFFER_H_

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

namespace crypto {
namespace tink {

namespace util {
namespace internal {
class SecretDataInternalClass;
}  // namespace internal
}  // namespace util

namespace internal {

// SecretBuffer stores data which can be mutated and should not be leaked in
// core dumps. Within Google, we achieve this by hooking into core dump
// collection. In OSS Tink, SecretBuffer overwrites the memory contents when the
// destructor is invoked.
class SecretBuffer {
 public:
  SecretBuffer() = default;
  SecretBuffer(const SecretBuffer& other) { *this = other; }
  SecretBuffer(SecretBuffer&& other) noexcept { *this = std::move(other); }
  SecretBuffer& operator=(const SecretBuffer& other) {
    if (this != &other) {
      reserve(other.size_);
      ::crypto::tink::internal::SafeMemCopy(data_, other.data_, other.size_);
      size_ = other.size_;
    }
    return *this;
  }
  SecretBuffer& operator=(SecretBuffer&& other) noexcept {
    swap(other);
    return *this;
  }

  explicit SecretBuffer(size_t size, uint8_t value = 0) {
    reserve(size);
    memset(data_, value, size);
    size_ = size;
  }

  explicit SecretBuffer(absl::string_view in) {
    reserve(in.size());
    SafeMemCopy(data_, in.data(), in.size());
    size_ = in.size();
  }

  explicit SecretBuffer(absl::Span<const uint8_t> in) {
    reserve(in.size());
    SafeMemCopy(data_, in.data(), in.size());
    size_ = in.size();
  }

  ~SecretBuffer() {
    if (data_ != nullptr) {
      crypto::tink::util::internal::SanitizingAllocator<uint8_t>().deallocate(
          data_, buffer_size());
    }
  }

  uint8_t& operator[](size_t pos) {
    CHECK(pos < size_) << "SecretBuffer::operator[] pos out of bounds";
    return data_[pos];
  }

  const uint8_t& operator[](size_t pos) const {
    CHECK(pos < size_) << "SecretBuffer::operator[] pos out of bounds";
    return data_[pos];
  }

  uint8_t* data() { return data_; }
  const uint8_t* data() const { return data_; }

  absl::string_view AsStringView() const {
    return absl::string_view(reinterpret_cast<const char*>(data_), size());
  }

  size_t size() const { return size_; }
  bool empty() const { return size() == 0; }
  size_t capacity() const { return capacity_; }
  void clear() { SecretBuffer().swap(*this); }

  void resize(size_t size, uint8_t val = 0) {
    if (size > size_) {
      reserve(size);
      memset(data_ + size_, val, size - size_);
    }
    size_ = size;
  }

  void reserve(size_t new_cap) {
    if (new_cap <= capacity_) {
      return;
    }
    // Add 4 extra bytes to store the CRC32C of the data. This is going to be
    // populated in SecretDataInternalClass.
    uint8_t* new_data =
        crypto::tink::util::internal::SanitizingAllocator<uint8_t>().allocate(
            new_cap + sizeof(uint32_t));
    CHECK(new_data != nullptr);
    if (data_ != nullptr) {
      ::crypto::tink::internal::SafeMemCopy(new_data, data_, size_);
      crypto::tink::util::internal::SanitizingAllocator<uint8_t>().deallocate(
          data_, buffer_size());
    }
    data_ = new_data;
    capacity_ = new_cap;
  }

  void swap(SecretBuffer& other) noexcept {
    using std::swap;
    swap(data_, other.data_);
    swap(size_, other.size_);
    swap(capacity_, other.capacity_);
  }

  SecretBuffer& append(absl::Span<const uint8_t> other) {
    reserve(size_ + other.size());
    crypto::tink::internal::SafeMemCopy(data_ + size_, other.data(),
                                        other.size());
    size_ += other.size();
    return *this;
  }

  SecretBuffer& append(absl::string_view other) {
    reserve(size_ + other.size());
    crypto::tink::internal::SafeMemCopy(data_ + size_, other.data(),
                                        other.size());
    size_ += other.size();
    return *this;
  }

  SecretBuffer substr(
      size_t pos, size_t count = std::numeric_limits<size_t>::max()) const& {
    CHECK(pos <= size());
    count = std::min(count, size() - pos);
    return SecretBuffer(AsStringView().substr(pos, count));
  }

  SecretBuffer substr(size_t pos,
                      size_t count = std::numeric_limits<size_t>::max()) && {
    CHECK(pos <= size());
    count = std::min(count, size() - pos);
    SecretBuffer result;
    result.swap(*this);
    if (pos != 0) {
      crypto::tink::internal::SafeMemMove(result.data(), result.data() + pos,
                                          count);
    }
    result.resize(count);
    return result;
  }

  bool operator==(const SecretBuffer& other) const {
    if (size() != other.size()) {
      return false;
    }
    return SafeCryptoMemEquals(data(), other.data(), size());
  }

  bool operator!=(const SecretBuffer& other) const { return !(*this == other); }

 private:
  friend class ::crypto::tink::util::internal::SecretDataInternalClass;

  size_t buffer_size() const { return capacity_ + sizeof(uint32_t); }

  // Pointer to a buffer of size `buffer_size()`.
  uint8_t* data_ = nullptr;
  size_t size_ = 0;
  size_t capacity_ = 0;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SECRET_BUFFER_H_
