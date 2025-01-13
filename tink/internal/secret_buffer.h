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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>

#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/sanitizing_allocator.h"

namespace crypto {
namespace tink {
namespace internal {

// SecretBuffer stores data which can be mutated and should not be leaked in
// core dumps. Within Google, we achieve this by hooking into core dump
// collection. In OSS Tink, SecretBuffer overwrites the memory contents when the
// destructor is invoked.
class SecretBuffer {
 public:
  SecretBuffer() = default;
  ~SecretBuffer() {
    if (data_ != nullptr) {
      crypto::tink::util::internal::SanitizingAllocator<uint8_t>().deallocate(
          data_, capacity_);
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

  size_t size() const { return size_; }

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
    uint8_t* new_data =
        crypto::tink::util::internal::SanitizingAllocator<uint8_t>().allocate(
            new_cap);
    CHECK(new_data != nullptr);
    if (data_ != nullptr) {
      ::crypto::tink::internal::SafeMemCopy(new_data, data_, size_);
      crypto::tink::util::internal::SanitizingAllocator<uint8_t>().deallocate(
          data_, capacity_);
    }
    data_ = new_data;
    capacity_ = new_cap;
  }

 private:
  uint8_t* data_ = nullptr;
  size_t size_ = 0;
  size_t capacity_ = 0;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SECRET_BUFFER_H_