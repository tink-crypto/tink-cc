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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_REGISTRY_IMPL_H_
#define TINK_INTERNAL_REGISTRY_IMPL_H_

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/input_stream.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/internal/monitoring.h"
#include "tink/key.h"
#include "tink/key_manager.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class RegistryImpl {
 public:
  static RegistryImpl& GlobalInstance() {
    static RegistryImpl* instance = new RegistryImpl();
    return *instance;
  }

  RegistryImpl() = default;
  RegistryImpl(const RegistryImpl&) = delete;
  RegistryImpl& operator=(const RegistryImpl&) = delete;
  ~RegistryImpl() { Reset(); }

  // Registers the given 'manager' for the key type 'manager->get_key_type()'.
  // Takes ownership of 'manager', which must be non-nullptr. KeyManager is the
  // legacy/internal version of KeyTypeManager.
  template <class P>
  absl::Status RegisterKeyManager(KeyManager<P>* manager,
                                  bool new_key_allowed = true)
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Takes ownership of 'manager', which must be non-nullptr.
  template <class KeyProto, class KeyFormatProto, class PrimitiveList>
  absl::Status RegisterKeyTypeManager(
      std::unique_ptr<KeyTypeManager<KeyProto, KeyFormatProto, PrimitiveList>>
          manager,
      bool new_key_allowed) ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Takes ownership of 'private_manager' and 'public_manager'. Both must be
  // non-nullptr.
  template <class PrivateKeyProto, class KeyFormatProto, class PublicKeyProto,
            class PrivatePrimitivesList, class PublicPrimitivesList>
  absl::Status RegisterAsymmetricKeyManagers(
      PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                            PrivatePrimitivesList>* private_manager,
      KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
          public_manager,
      bool new_key_allowed) ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  absl::StatusOr<const KeyManager<P>*> get_key_manager(
      absl::string_view type_url) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Takes ownership of 'wrapper', which must be non-nullptr.
  template <class P, class Q>
  absl::Status RegisterPrimitiveWrapper(PrimitiveWrapper<P, Q>* wrapper)
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  absl::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>> NewKeyData(
      const google::crypto::tink::KeyTemplate& key_template) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view type_url,
                   absl::string_view serialized_private_key) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  absl::StatusOr<std::unique_ptr<P>> Wrap(
      std::unique_ptr<PrimitiveSet<P>> primitive_set) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Wraps a `keyset` and annotates it with `annotations`.
  template <class P>
  absl::StatusOr<std::unique_ptr<P>> WrapKeyset(
      const google::crypto::tink::Keyset& keyset,
      const absl::flat_hash_map<std::string, std::string>& annotations) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  absl::StatusOr<google::crypto::tink::KeyData> DeriveKey(
      const google::crypto::tink::KeyTemplate& key_template,
      InputStream* randomness) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  void Reset() ABSL_LOCKS_EXCLUDED(maps_mutex_, monitoring_factory_mutex_);

  absl::Status RestrictToFipsIfEmpty() const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Registers a `monitoring_factory`. Only one factory can be registered,
  // subsequent calls to this method will return a kAlreadyExists error.
  absl::Status RegisterMonitoringClientFactory(
      std::unique_ptr<crypto::tink::internal::MonitoringClientFactory>
          monitoring_factory) ABSL_LOCKS_EXCLUDED(monitoring_factory_mutex_);

  // Returns a pointer to the registered monitoring factory if any, and nullptr
  // otherwise.
  crypto::tink::internal::MonitoringClientFactory* GetMonitoringClientFactory()
      const {
    return monitoring_factory_.load(std::memory_order_acquire);
  }

 private:
  // Returns the key type info for a given type URL. Since we never replace
  // key type infos, the pointers will stay valid for the lifetime of the
  // binary.
  absl::StatusOr<const KeyTypeInfoStore::Info*> get_key_type_info(
      absl::string_view type_url) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  mutable absl::Mutex maps_mutex_;
  // Stores information about key types constructed from their KeyTypeManager or
  // KeyManager.
  // Once inserted, KeyTypeInfoStore::Info objects must remain valid for the
  // lifetime of the binary, and the Info object's pointer stability is
  // required. Elements in Info, which include the KeyTypeManager or KeyManager,
  // must not be replaced.
  KeyTypeInfoStore key_type_info_store_ ABSL_GUARDED_BY(maps_mutex_);
  // Stores information about keyset wrappers constructed from their
  // PrimitiveWrapper.
  KeysetWrapperStore keyset_wrapper_store_ ABSL_GUARDED_BY(maps_mutex_);

  // Mutex to protect writes to `monitoring_factory_`.
  mutable absl::Mutex monitoring_factory_mutex_;
  // Owned.
  std::atomic<crypto::tink::internal::MonitoringClientFactory*>
      monitoring_factory_{nullptr};
};

template <class P>
absl::Status RegistryImpl::RegisterKeyManager(KeyManager<P>* manager,
                                              bool new_key_allowed) {
  auto owned_manager = absl::WrapUnique(manager);
  if (manager == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Parameter 'manager' must be non-null.");
  }
  absl::MutexLock lock(&maps_mutex_);
  return key_type_info_store_.AddKeyManager(std::move(owned_manager),
                                            new_key_allowed);
}

template <class KeyProto, class KeyFormatProto, class PrimitiveList>
absl::Status RegistryImpl::RegisterKeyTypeManager(
    std::unique_ptr<KeyTypeManager<KeyProto, KeyFormatProto, PrimitiveList>>
        manager,
    bool new_key_allowed) {
  if (manager == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Parameter 'manager' must be non-null.");
  }
  absl::MutexLock lock(&maps_mutex_);
  return key_type_info_store_.AddKeyTypeManager(std::move(manager),
                                                new_key_allowed);
}

template <class PrivateKeyProto, class KeyFormatProto, class PublicKeyProto,
          class PrivatePrimitivesList, class PublicPrimitivesList>
absl::Status RegistryImpl::RegisterAsymmetricKeyManagers(
    PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                          PrivatePrimitivesList>* private_manager,
    KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>* public_manager,
    bool new_key_allowed) ABSL_LOCKS_EXCLUDED(maps_mutex_) {
  auto owned_private_manager = absl::WrapUnique(private_manager);
  auto owned_public_manager = absl::WrapUnique(public_manager);

  if (private_manager == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Parameter 'private_manager' must be non-null.");
  }
  if (public_manager == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Parameter 'public_manager' must be non-null.");
  }

  absl::MutexLock lock(&maps_mutex_);
  return key_type_info_store_.AddAsymmetricKeyTypeManagers(
      std::move(owned_private_manager), std::move(owned_public_manager),
      new_key_allowed);
}

template <class P, class Q>
absl::Status RegistryImpl::RegisterPrimitiveWrapper(
    PrimitiveWrapper<P, Q>* wrapper) {
  if (wrapper == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Parameter 'wrapper' must be non-null.");
  }
  std::unique_ptr<PrimitiveWrapper<P, Q>> owned_wrapper(wrapper);

  absl::MutexLock lock(&maps_mutex_);
  absl::AnyInvocable<absl::StatusOr<std::unique_ptr<P>>(
      const google::crypto::tink::KeyData& key_data) const>
      primitive_getter = [this](const google::crypto::tink::KeyData& key_data) {
        return this->GetPrimitive<P>(key_data);
      };

  absl::AnyInvocable<absl::StatusOr<std::unique_ptr<P>>(const Key& key) const>
      always_failing_primitive_getter = [](const Key& key) {
        return absl::Status(
            absl::StatusCode::kNotFound,
            "Primitive getter not available in global registry mode.");
      };

  return keyset_wrapper_store_.Add(std::move(owned_wrapper),
                                   std::move(primitive_getter),
                                   std::move(always_failing_primitive_getter));
}

// TODO: b/284059638 - Remove this and upstream functions from the public API.
template <class P>
absl::StatusOr<const KeyManager<P>*> RegistryImpl::get_key_manager(
    absl::string_view type_url) const {
  absl::StatusOr<const crypto::tink::internal::KeyTypeInfoStore::Info*> info =
      get_key_type_info(type_url);
  if (!info.ok()) {
    return info.status();
  }
  return (*info)->get_key_manager<P>(type_url);
}

template <class P>
absl::StatusOr<std::unique_ptr<P>> RegistryImpl::GetPrimitive(
    const google::crypto::tink::KeyData& key_data) const {
  absl::StatusOr<const crypto::tink::internal::KeyTypeInfoStore::Info*> info =
      get_key_type_info(key_data.type_url());
  if (!info.ok()) {
    return info.status();
  }
  return (*info)->GetPrimitive<P>(key_data);
}

template <class P>
absl::StatusOr<std::unique_ptr<P>> RegistryImpl::Wrap(
    std::unique_ptr<PrimitiveSet<P>> primitive_set) const {
  if (primitive_set == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Parameter 'primitive_set' must be non-null.");
  }
  const PrimitiveWrapper<P, P>* wrapper = nullptr;
  {
    absl::MutexLock lock(&maps_mutex_);
    absl::StatusOr<const PrimitiveWrapper<P, P>*> wrapper_status =
        keyset_wrapper_store_.GetPrimitiveWrapper<P>();
    if (!wrapper_status.ok()) {
      return wrapper_status.status();
    }
    wrapper = *wrapper_status;
  }
  return wrapper->Wrap(std::move(primitive_set));
}

template <class P>
absl::StatusOr<std::unique_ptr<P>> RegistryImpl::WrapKeyset(
    const google::crypto::tink::Keyset& keyset,
    const absl::flat_hash_map<std::string, std::string>& annotations) const {
  const KeysetWrapper<P>* keyset_wrapper = nullptr;
  {
    absl::MutexLock lock(&maps_mutex_);
    absl::StatusOr<const KeysetWrapper<P>*> keyset_wrapper_status =
        keyset_wrapper_store_.Get<P>();
    if (!keyset_wrapper_status.ok()) {
      return keyset_wrapper_status.status();
    }
    keyset_wrapper = *keyset_wrapper_status;
  }
  // `maps_mutex_` must be released before calling Wrap or this will deadlock,
  // as Wrap calls get_key_manager.
  return keyset_wrapper->Wrap(keyset, annotations);
}

inline absl::Status RegistryImpl::RestrictToFipsIfEmpty() const {
  absl::MutexLock lock(&maps_mutex_);
  // If we are already in FIPS mode, then do nothing..
  if (IsFipsModeEnabled()) {
    return absl::OkStatus();
  }
  if (key_type_info_store_.IsEmpty()) {
    SetFipsRestricted();
    return absl::OkStatus();
  }
  return absl::Status(absl::StatusCode::kInternal,
                      "Could not set FIPS only mode. Registry is not empty.");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_REGISTRY_IMPL_H_
