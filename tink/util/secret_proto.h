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

#ifndef TINK_UTIL_SECRET_PROTO_H_
#define TINK_UTIL_SECRET_PROTO_H_

#include <cstddef>
#include <memory>
#include <utility>

#include "google/protobuf/arena.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

namespace internal {

inline google::protobuf::ArenaOptions SecretArenaOptions() {
  google::protobuf::ArenaOptions options;
  options.block_alloc = [](size_t sz) {
    return SanitizingAllocator<void>().allocate(sz);
  };
  options.block_dealloc = [](void* ptr, size_t sz) {
    return SanitizingAllocator<void>().deallocate(ptr, sz);
  };
  return options;
}

}  // namespace internal

// Stores secret (sensitive) protobuf and makes sure it's marked as such and
// destroyed in a safe way.
//
// Note: Currently does not protect fields of type "string" and "bytes"
// (depends on https://github.com/protocolbuffers/protobuf/issues/1896).
template <typename T>
class SecretProto {
 public:
  static StatusOr<SecretProto<T>> ParseFromSecretData(
      const ::crypto::tink::SecretData& data) {
    SecretProto<T> proto;
    bool parsed = crypto::tink::internal::CallWithCoreDumpProtection([&] {
      return proto->ParseFromArray(data.data(), data.size());
    });
    if (!parsed) {
      return absl::Status(absl::StatusCode::kInternal, "Could not parse proto");
    }
    return proto;
  }

  SecretProto() = default;

  SecretProto(const SecretProto& other) { *value_ = *other.value_; }

  SecretProto(SecretProto&& other) noexcept { *this = std::move(other); }

  explicit SecretProto(const T& value) { *value_ = value; }

  SecretProto& operator=(const SecretProto& other) {
    crypto::tink::internal::CallWithCoreDumpProtection([&] {
      *value_ = *other.value_;
    });
    return *this;
  }

  SecretProto& operator=(SecretProto&& other) noexcept {
    using std::swap;
    swap(arena_, other.arena_);
    swap(value_, other.value_);
    return *this;
  }

  inline T* get() { return value_; }

  // Accessors to the underlying message.
  inline T* operator->() { return value_; }
  inline const T* operator->() const { return value_; }

  inline T& operator*() { return *value_; }
  inline const T& operator*() const { return *value_; }

  absl::StatusOr<::crypto::tink::SecretData> SerializeAsSecretData() const {
    crypto::tink::internal::SecretBuffer buffer(value_->ByteSizeLong());
    bool serialized = crypto::tink::internal::CallWithCoreDumpProtection(
        [&] { return value_->SerializeToArray(buffer.data(), buffer.size()); });
    if (!serialized) {
      return absl::Status(absl::StatusCode::kInternal,
                          "Could not serialize proto");
    }
    return internal::AsSecretData(std::move(buffer));
  }

 private:
  std::unique_ptr<google::protobuf::Arena> arena_ =
      absl::make_unique<google::protobuf::Arena>(internal::SecretArenaOptions());
  T* value_ = google::protobuf::Arena::Create<T>(arena_.get());
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_SECRET_PROTO_H_
