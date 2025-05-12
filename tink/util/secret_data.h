// Copyright 2020 Google LLC
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

#ifndef TINK_UTIL_SECRET_DATA_H_
#define TINK_UTIL_SECRET_DATA_H_

#include <cstddef>
#include <cstdint>  // IWYU pragma: keep
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/crypto.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/sanitizing_allocator.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data_internal_class.h"  // IWYU pragma: export

namespace crypto {
namespace tink {
namespace util {
namespace internal {

template <typename T>
struct SanitizingDeleter {
  void operator()(T* ptr) {
    ptr->~T();  // Invoke destructor. Must do this before sanitize.
    SanitizingAllocator<T>().deallocate(ptr, 1);
  }
};

}  // namespace internal

using SecretData ABSL_DEPRECATE_AND_INLINE() = ::crypto::tink::SecretData;

// Constant-time comparison for SecretData
// SecretDataEquals should be used instead of regular operator== in most cases.
inline bool SecretDataEquals(const crypto::tink::SecretData& lhs,
                             const crypto::tink::SecretData& rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  return ::crypto::tink::internal::SafeCryptoMemEquals(lhs.data(), rhs.data(),
                                                       lhs.size());
}

// Stores secret (sensitive) object and makes sure it's marked as such and
// destroyed in a safe way.
// SecretUniquePtr MUST be constructed using MakeSecretUniquePtr function.
// Generally SecretUniquePtr should be used iff SecretData is unsuitable.
//
// Example:
// class MyCryptoPrimitive {
//  public:
//   MyEncryptionPrimitive(absl::string_view key_value) {
//     AES_set_encrypt_key(key_value.data(), key_value.size() * 8, key_.get());
//   }
//   [...]
//  private:
//   util::SecretUniquePtr<AES_KEY> key_ = util::MakeSecretUniquePtr<AES_KEY>();
// }
//
// NOTE: SecretUniquePtr<T> will only protect the data which is stored in the
// memory which a T object takes on the stack. In particular, std::string and
// std::vector SHOULD NOT be used as arguments of T: they allocate memory
// on the heap, and hence the data stored in them will NOT be protected.
template <typename T>
class SecretUniquePtr {
 private:
  using Value = std::unique_ptr<T, internal::SanitizingDeleter<T>>;

 public:
  using pointer = typename Value::pointer;
  using element_type = typename Value::element_type;
  using deleter_type = typename Value::deleter_type;

  SecretUniquePtr() = default;

  pointer get() const { return value_.get(); }
  deleter_type& get_deleter() { return value_.get_deleter(); }
  const deleter_type& get_deleter() const { return value_.get_deleter(); }
  void swap(SecretUniquePtr& other) noexcept { value_.swap(other.value_); }
  void reset() { value_.reset(); }

  typename std::add_lvalue_reference<T>::type operator*() const {
    return value_.operator*();
  }
  pointer operator->() const { return value_.operator->(); }
  explicit operator bool() const { return value_.operator bool(); }

 private:
  template <typename S, typename... Args>
  friend SecretUniquePtr<S> MakeSecretUniquePtr(Args&&... args);
  explicit SecretUniquePtr(Value&& value) : value_(std::move(value)) {}
  Value value_;
};

template <typename T, typename... Args>
SecretUniquePtr<T> MakeSecretUniquePtr(Args&&... args) {
  T* ptr = internal::SanitizingAllocator<T>().allocate(1);
  new (ptr)
      T(std::forward<Args>(args)...);  // Invoke constructor "placement new"
  return SecretUniquePtr<T>({ptr, internal::SanitizingDeleter<T>()});
}

// Convenience conversion functions
inline absl::string_view SecretDataAsStringView(
    const ::crypto::tink::SecretData& secret) {
  return {reinterpret_cast<const char*>(secret.data()), secret.size()};
}

inline ::crypto::tink::SecretData SecretDataFromStringView(
    absl::string_view secret) {
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  return {secret.begin(), secret.end()};
#else
  return internal::SecretDataInternalClassFromStringView(secret);
#endif
}

inline ::crypto::tink::SecretData SecretDataFromSpan(
    absl::Span<const uint8_t> span) {
  return SecretDataFromStringView(absl::string_view(
      reinterpret_cast<const char*>(span.data()), span.size()));
}

namespace internal {

// This function is needed within Tink because the open source implementation
// of Tink uses TINK_CPP_SECRET_DATA_IS_STD_VECTOR. Within Google, use
// SecretData(buffer);
inline crypto::tink::SecretData AsSecretData(
    const ::crypto::tink::internal::SecretBuffer& buffer) {
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  return SecretDataFromStringView(buffer.AsStringView());
#else
  return crypto::tink::SecretData(buffer);
#endif
}

// This function is needed within Tink because the open source implementation
// of Tink uses TINK_CPP_SECRET_DATA_IS_STD_VECTOR. Within Google, use
// SecretData(std::move(buffer));
inline crypto::tink::SecretData AsSecretData(
    ::crypto::tink::internal::SecretBuffer&& buffer) {
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  // This needs to make a copy since we cannot give a vector an already
  // allocated slice.
  return SecretDataFromStringView(buffer.AsStringView());
#else
  return crypto::tink::SecretData(std::move(buffer));
#endif
}

// This function is needed within Tink because the open source implementation
// of Tink uses TINK_CPP_SECRET_DATA_IS_STD_VECTOR. Within Google, use
// data.AsSecretBuffer()
inline crypto::tink::internal::SecretBuffer AsSecretBuffer(
    const crypto::tink::SecretData& data) {
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  return crypto::tink::internal::SecretBuffer(SecretDataAsStringView(data));
#else
  return data.AsSecretBuffer();
#endif
}

// This function is needed within Tink because the open source implementation
// of Tink uses TINK_CPP_SECRET_DATA_IS_STD_VECTOR. Within Google, use
// std::move(data).AsSecretBuffer()
inline crypto::tink::internal::SecretBuffer AsSecretBuffer(
    crypto::tink::SecretData&& data) {
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  // This needs to make a copy since we cannot steal the data from a vector
  return crypto::tink::internal::SecretBuffer(SecretDataAsStringView(data));
#else
  return std::move(data).AsSecretBuffer();
#endif
}

}  // namespace internal

// The same as SecretUniquePtr, but with value semantics.
//
// NOTE: SecretValue<T> will only protect the data which is stored in the
// memory which a T object takes on the stack. In particular, std::string and
// std::vector SHOULD NOT be used as arguments of T: they allocate memory
// on the heap, and hence the data stored in them will NOT be protected.
template <typename T>
class SecretValue {
 public:
  explicit SecretValue(T t = T())
      : ptr_(MakeSecretUniquePtr<T>(std::move(t))) {}

  SecretValue(SecretValue&& other) noexcept : ptr_(MakeSecretUniquePtr<T>()) {
    ptr_.swap(other.ptr_);
  }

  SecretValue& operator=(SecretValue&& other) noexcept {
    ptr_.swap(other.ptr_);
    return *this;
  }

  SecretValue(const SecretValue& other) {
    if constexpr (std::is_trivially_copyable_v<T>) {
      if (this != &other) {
        ptr_ = MakeSecretUniquePtr<T>();
        crypto::tink::internal::SafeMemCopy(ptr_.get(), other.ptr_.get(),
                                            sizeof(T));
      }
    } else {
      crypto::tink::internal::CallWithCoreDumpProtection(
          [&]() { ptr_ = MakeSecretUniquePtr<T>(*other.ptr_); });
    }
  }

  SecretValue& operator=(const SecretValue& other) {
    if constexpr (std::is_trivially_copyable_v<T>) {
      if (this != &other) {
        crypto::tink::internal::SafeMemCopy(ptr_.get(), other.ptr_.get(),
                                            sizeof(T));
      }
    } else {
      crypto::tink::internal::CallWithCoreDumpProtection(
          [&]() { *ptr_ = *other.ptr_; });
    }
    return *this;
  }

  T& value() { return *ptr_; }
  const T& value() const { return *ptr_; }

 private:
  SecretUniquePtr<T> ptr_;
};

inline void SafeZeroMemory(void* ptr, std::size_t size) {
  OPENSSL_cleanse(ptr, size);
}

inline void SafeZeroString(std::string* str) {
  SafeZeroMemory(&(*str)[0], str->size());
}

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_SECRET_DATA_H_
