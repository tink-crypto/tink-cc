// Copyright 2017 Google LLC
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

#ifndef TINK_REGISTRY_H_
#define TINK_REGISTRY_H_

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/registry_impl.h"
#include "tink/key_manager.h"
#include "tink/primitive_set.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Registry for KeyMangers and PrimitiveWrappers.
//
// It is essentially a big container (map) that for each supported key type
// holds a corresponding KeyManager object, which "understands" the key type
// (i.e. the KeyManager can instantiate the primitive corresponding to given
// key, or can generate new keys of the supported key type).  It holds also
// a so-called PrimitiveWrapper for each supported primitive, so that it can
// wrap a set of primitives (corresponding to a keyset) into a single primitive.
//
// Registry is initialized at startup, and is later used to instantiate
// primitives for given keys or keysets.  Keeping KeyManagers for all primitives
// in a single Registry (rather than having a separate KeyManager per primitive)
// enables modular construction of compound primitives from "simple" ones, e.g.,
// AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC.
//
// Note that regular users will usually not work directly with Registry, but
// rather via KeysetHandle::GetPrimitive()-methods, which in the background
// query the Registry for specific KeyManagers and PrimitiveWrappers.
// Registry is public though, to enable configurations with custom primitives
// and KeyManagers.
class Registry {
 public:
  // Registers the given 'manager' for the key type 'manager->get_key_type()'.
  template <class ConcreteKeyManager>
  static absl::Status RegisterKeyManager(
      std::unique_ptr<ConcreteKeyManager> manager, bool new_key_allowed) {
    return internal::RegistryImpl::GlobalInstance().RegisterKeyManager(
        manager.release(), new_key_allowed);
  }

  template <class KTManager>
  static absl::Status RegisterKeyTypeManager(std::unique_ptr<KTManager> manager,
                                             bool new_key_allowed) {
    return internal::RegistryImpl::GlobalInstance()
        .RegisterKeyTypeManager<typename KTManager::KeyProto,
                                typename KTManager::KeyFormatProto,
                                typename KTManager::PrimitiveList>(
            std::move(manager), new_key_allowed);
  }

  template <class PrivateKeyTypeManager, class KeyTypeManager>
  static absl::Status RegisterAsymmetricKeyManagers(
      std::unique_ptr<PrivateKeyTypeManager> private_key_manager,
      std::unique_ptr<KeyTypeManager> public_key_manager,
      bool new_key_allowed) {
    return internal::RegistryImpl::GlobalInstance()
        .RegisterAsymmetricKeyManagers(private_key_manager.release(),
                                       public_key_manager.release(),
                                       new_key_allowed);
  }

  template <class ConcretePrimitiveWrapper>
  static absl::Status RegisterPrimitiveWrapper(
      std::unique_ptr<ConcretePrimitiveWrapper> wrapper) {
    return internal::RegistryImpl::GlobalInstance().RegisterPrimitiveWrapper(
        wrapper.release());
  }

  // Returns a key manager for the given type_url (if any found).
  // Keeps the ownership of the manager. Returned key_managers are guaranteed
  // to stay valid for the lifetime of the binary (with the exception of a user
  // calling Reset()).
  // TODO(tholenst): Remove Reset() from the interface, as it could violate this
  // but should be test only anyhow.
  template <class P>
  static absl::StatusOr<const KeyManager<P>*> get_key_manager(
      absl::string_view type_url) {
    return internal::RegistryImpl::GlobalInstance().get_key_manager<P>(
        type_url);
  }

  // Convenience method for creating a new primitive for the key given
  // in 'key_data'.  It looks up a KeyManager identified by key_data.type_url,
  // and calls manager's GetPrimitive(key_data)-method.
  template <class P>
  static absl::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) {
    return internal::RegistryImpl::GlobalInstance().GetPrimitive<P>(key_data);
  }

  // Generates a new KeyData for the specified 'key_template'.
  // It looks up a KeyManager identified by key_template.type_url,
  // and calls KeyManager::NewKeyData.
  // This method should be used solely for key management.
  static absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(const google::crypto::tink::KeyTemplate& key_template) {
    return internal::RegistryImpl::GlobalInstance().NewKeyData(key_template);
  }

  // Convenience method for extracting the public key data from the
  // private key given in serialized_private_key.
  // It looks up a KeyManager identified by type_url, whose KeyFactory must be
  // a PrivateKeyFactory, and calls PrivateKeyFactory::GetPublicKeyData.
  static absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view type_url,
                   absl::string_view serialized_private_key) {
    return internal::RegistryImpl::GlobalInstance().GetPublicKeyData(
        type_url, serialized_private_key);
  }

  // Looks up the globally registered PrimitiveWrapper for this primitive
  // and wraps the given PrimitiveSet with it.
  template <class P>
  static absl::StatusOr<std::unique_ptr<P>> Wrap(
      std::unique_ptr<PrimitiveSet<P>> primitive_set) {
    return internal::RegistryImpl::GlobalInstance().Wrap<P>(
        std::move(primitive_set));
  }

  // Resets the registry.
  // After reset the registry is empty, i.e. it contains neither catalogues
  // nor key managers. This method is intended for testing only.
  static void Reset() {
    return internal::RegistryImpl::GlobalInstance().Reset();
  }
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_REGISTRY_H_
