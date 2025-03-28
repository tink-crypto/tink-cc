// Copyright 2018 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_KEYSET_WRAPPER_STORE_H_
#define TINK_INTERNAL_KEYSET_WRAPPER_STORE_H_

#include <memory>
#include <type_traits>
#include <typeindex>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/internal/configuration_helper.h"
#include "tink/internal/keyset_wrapper.h"
#include "tink/internal/keyset_wrapper_impl.h"
#include "tink/key.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Stores KeysetWrappers constructed from their PrimitiveWrapper. This is used
// by the Configuration and Registry classes.
//
// Once inserted, elements in Info, which include the PrimitiveWrapper, must not
// be replaced.
//
// Example:
//  KeysetWrapperStore store;
//  absl::Status status = store.Add<Aead, Aead>(
//      absl::make_unique<AeadWrapper>(), std::move(primitive_getter));
//  absl::StatusOr<const KeysetWrapper<Aead>*> wrapper =
//      store.Get<Aead>();
class KeysetWrapperStore {
 public:
  KeysetWrapperStore() = default;

  // Movable, but not copyable.
  KeysetWrapperStore(KeysetWrapperStore&& other) = default;
  KeysetWrapperStore& operator=(KeysetWrapperStore&& other) = default;

  // Adds a crypto::tink::PrimitiveWrapper and two `primitive_getter` functions
  // (one using the legacy KeyData API and one using the key objects) to
  // KeysetWrapperStore. The wrapper would first check the key objects API, and
  // if that fails, it would fall back to the using KeyData.
  template <class P, class Q>
  absl::Status Add(std::unique_ptr<PrimitiveWrapper<P, Q>> wrapper,
                   absl::AnyInvocable<absl::StatusOr<std::unique_ptr<P>>(
                       const google::crypto::tink::KeyData& key_data) const>
                       primitive_getter,
                   PrimitiveGetterFn<P, Key> primitive_getter_from_key);

  // Gets the PrimitiveWrapper that produces primitive P. This is a legacy
  // function.
  template <class P>
  absl::StatusOr<const PrimitiveWrapper<P, P>*> GetPrimitiveWrapper() const;

  // Gets the KeysetWrapper that produces primitive Q.
  template <class Q>
  absl::StatusOr<const KeysetWrapper<Q>*> Get() const;

  bool IsEmpty() const { return primitive_to_info_.empty(); }

 private:
  class Info {
   public:
    template <typename P, typename Q>
    explicit Info(std::unique_ptr<PrimitiveWrapper<P, Q>> wrapper,
                  absl::AnyInvocable<absl::StatusOr<std::unique_ptr<P>>(
                      const google::crypto::tink::KeyData& key_data) const>
                      primitive_getter,
                  PrimitiveGetterFn<P, Key> primitive_getter_from_key)
        : is_same_primitive_wrapping_(std::is_same<P, Q>::value),
          wrapper_type_index_(std::type_index(typeid(*wrapper))),
          q_type_index_(std::type_index(typeid(Q))) {
      keyset_wrapper_ = absl::make_unique<KeysetWrapperImpl<P, Q>>(
          wrapper.get(), std::move(primitive_getter),
          std::move(primitive_getter_from_key));
      original_wrapper_ = std::move(wrapper);
    }

    template <typename Q>
    absl::StatusOr<const KeysetWrapper<Q>*> Get() const {
      if (q_type_index_ != std::type_index(typeid(Q))) {
        return absl::Status(
            absl::StatusCode::kInternal,
            "RegistryImpl::KeysetWrapper() called with wrong type");
      }
      return static_cast<KeysetWrapper<Q>*>(keyset_wrapper_.get());
    }

    // TODO(b/171021679): Deprecate this and upstream functions.
    template <typename P>
    absl::StatusOr<const PrimitiveWrapper<P, P>*> GetPrimitiveWrapper() const {
      if (!is_same_primitive_wrapping_) {
        // This happens if a user uses a legacy method (like Registry::Wrap)
        // directly or has a custom key manager for a primitive which has a
        // PrimitiveWrapper<P,Q> with P != Q.
        return absl::Status(
            absl::StatusCode::kFailedPrecondition,
            absl::StrCat("Cannot use primitive type ", typeid(P).name(),
                         " with a custom key manager."));
      }
      if (q_type_index_ != std::type_index(typeid(P))) {
        return absl::Status(
            absl::StatusCode::kInternal,
            "RegistryImpl::LegacyWrapper() called with wrong type");
      }
      return static_cast<const PrimitiveWrapper<P, P>*>(
          original_wrapper_.get());
    }

    // Returns true if the PrimitiveWrapper is the same class as the one used
    // to construct this Info.
    template <typename P, typename Q>
    bool HasSameType(const PrimitiveWrapper<P, Q>& wrapper) {
      return wrapper_type_index_ == std::type_index(typeid(wrapper));
    }

   private:
    bool is_same_primitive_wrapping_;
    // dynamic std::type_index of the actual PrimitiveWrapper<P,Q> class for
    // which this key was inserted.
    std::type_index wrapper_type_index_;
    // dynamic std::type_index of Q, when PrimitiveWrapper<P,Q> was inserted.
    std::type_index q_type_index_;
    // The primitive_wrapper passed in. We use a shared_ptr because
    // unique_ptr<void> is invalid.
    std::shared_ptr<void> original_wrapper_;
    // The keyset_wrapper_. We use a shared_ptr because unique_ptr<void> is
    // invalid.
    std::shared_ptr<void> keyset_wrapper_;
  };

  // Map from primitive type_index to Info.
  absl::flat_hash_map<std::type_index, Info> primitive_to_info_;
};

template <class P, class Q>
absl::Status KeysetWrapperStore::Add(
    std::unique_ptr<PrimitiveWrapper<P, Q>> wrapper,
    absl::AnyInvocable<absl::StatusOr<std::unique_ptr<P>>(
        const google::crypto::tink::KeyData& key_data) const>
        primitive_getter,
    PrimitiveGetterFn<P, Key> primitive_getter_from_key) {
  if (wrapper == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Parameter 'wrapper' must be non-null.");
  }
  auto it = primitive_to_info_.find(std::type_index(typeid(Q)));
  if (it != primitive_to_info_.end()) {
    if (!it->second.HasSameType(*wrapper)) {
      return absl::Status(absl::StatusCode::kAlreadyExists,
                          "A wrapper named for this primitive already exists.");
    }
    return absl::OkStatus();
  }

  primitive_to_info_.insert(
      {std::type_index(typeid(Q)),
       Info(std::move(wrapper), std::move(primitive_getter),
            std::move(primitive_getter_from_key))});

  return absl::OkStatus();
}

template <class P>
absl::StatusOr<const PrimitiveWrapper<P, P>*>
KeysetWrapperStore::GetPrimitiveWrapper() const {
  auto it = primitive_to_info_.find(std::type_index(typeid(P)));
  if (it == primitive_to_info_.end()) {
    return absl::Status(
        absl::StatusCode::kNotFound,
        absl::StrCat("No wrapper registered for type ", typeid(P).name()));
  }
  return it->second.GetPrimitiveWrapper<P>();
}

template <class P>
absl::StatusOr<const KeysetWrapper<P>*> KeysetWrapperStore::Get() const {
  auto it = primitive_to_info_.find(std::type_index(typeid(P)));
  if (it == primitive_to_info_.end()) {
    return absl::Status(
        absl::StatusCode::kNotFound,
        absl::StrCat("No wrapper registered for type ", typeid(P).name()));
  }
  return it->second.Get<P>();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEYSET_WRAPPER_STORE_H_
