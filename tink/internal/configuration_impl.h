// Copyright 2023 Google LLC
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

#ifndef TINK_INTERNAL_CONFIGURATION_IMPL_H_
#define TINK_INTERNAL_CONFIGURATION_IMPL_H_

#include <functional>
#include <memory>
#include <tuple>
#include <typeindex>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_helper.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key.h"
#include "tink/key_manager.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr absl::string_view kConfigurationImplErr =
    "Use crypto::tink::Registry instead when in global registry mode.";

class ConfigurationImpl {
 public:
  template <class PW>
  static absl::Status AddPrimitiveWrapper(std::unique_ptr<PW> wrapper,
                                          crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          kConfigurationImplErr);
    }

    // `primitive_getter` must be defined here, as PW::InputPrimitive is not
    // accessible later.
    // TODO(b/284084337): Move primitive getter out of key manager.
    std::function<absl::StatusOr<std::unique_ptr<typename PW::InputPrimitive>>(
        const google::crypto::tink::KeyData& key_data)>
        primitive_getter =
            [&config](const google::crypto::tink::KeyData& key_data)
        -> absl::StatusOr<std::unique_ptr<typename PW::InputPrimitive>> {
      absl::StatusOr<const crypto::tink::internal::KeyTypeInfoStore::Info*>
          info = config.key_type_info_store_.Get(key_data.type_url());
      if (!info.ok()) {
        return info.status();
      }
      return (*info)->GetPrimitive<typename PW::InputPrimitive>(key_data);
    };

    PrimitiveGetterFn<typename PW::InputPrimitive, Key>
        primitive_getter_from_key = [&config](const Key& key)
        -> absl::StatusOr<std::unique_ptr<typename PW::InputPrimitive>> {
      auto it = config.primitive_getter_fn_map_.find(
          std::tuple<std::type_index, std::type_index>(
              std::type_index(typeid(typename PW::InputPrimitive)),
              std::type_index(typeid(key))));
      if (it != config.primitive_getter_fn_map_.end()) {
        const TypeErasedPrimitiveGetterFn& fn = it->second;
        absl::StatusOr<void*> value = fn(reinterpret_cast<const void*>(&key));
        if (!value.ok()) {
          return value.status();
        }
        auto* p = reinterpret_cast<typename PW::InputPrimitive*>(*value);
        // Restore the pointer ownership that was "released" when converting to
        // a `void*`.
        return std::unique_ptr<typename PW::InputPrimitive>(p);
      } else {
        // No matching primitive getter is found.
        return absl::Status(
            absl::StatusCode::kNotFound,
            absl::StrCat("Primitive getter for (",
                         typeid(typename PW::InputPrimitive).name(), ",",
                         typeid(key).name(), ") not found."));
      }
    };

    return config.keyset_wrapper_store_
        .Add<typename PW::InputPrimitive, typename PW::Primitive>(
            std::move(wrapper), primitive_getter,
            std::move(primitive_getter_from_key));
  }

  template <class P, class K>
  static absl::Status AddPrimitiveGetter(
      PrimitiveGetterFn<P, K> primitive_getter_fn,
      crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          kConfigurationImplErr);
    }

    auto it = config.primitive_getter_fn_map_.find(
        std::tuple<std::type_index, std::type_index>(
            std::type_index(typeid(P)), std::type_index(typeid(K))));
    if (it != config.primitive_getter_fn_map_.end()) {
      return absl::Status(absl::StatusCode::kAlreadyExists,
                          absl::StrCat("Primitive getter for ",
                                       typeid(P).name(), " already exists."));
    }

    TypeErasedPrimitiveGetterFn wrapper_fn =
        [primitive_getter_fn = std::move(primitive_getter_fn)](
            const void* key) -> absl::StatusOr<void*> {
      absl::StatusOr<std::unique_ptr<P>> value =
          primitive_getter_fn(*reinterpret_cast<const K*>(key));
      if (!value.ok()) {
        return value.status();
      }
      // Release ownership, so that `value` doesn't destroy the pointed-to
      // object when it goes out of scope here. Callsite must re-acquire.
      return reinterpret_cast<void*>(value->release());
    };

    // Creates a pair to be inserted in the map.
    std::pair<std::tuple<std::type_index, std::type_index>,
              TypeErasedPrimitiveGetterFn>
        map_entry{std::tuple<std::type_index, std::type_index>(
                      std::type_index(typeid(P)), std::type_index(typeid(K))),
                  std::move(wrapper_fn)};

    config.primitive_getter_fn_map_.insert(std::move(map_entry));
    return absl::OkStatus();
  }

  template <class KM>
  static absl::Status AddKeyTypeManager(std::unique_ptr<KM> key_manager,
                                        crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          kConfigurationImplErr);
    }
    return config.key_type_info_store_.AddKeyTypeManager(
        std::move(key_manager), /*new_key_allowed=*/true);
  }

  template <class PrivateKM, class PublicKM>
  static absl::Status AddAsymmetricKeyManagers(
      std::unique_ptr<PrivateKM> private_key_manager,
      std::unique_ptr<PublicKM> public_key_manager,
      crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          kConfigurationImplErr);
    }
    return config.key_type_info_store_.AddAsymmetricKeyTypeManagers(
        std::move(private_key_manager), std::move(public_key_manager),
        /*new_key_allowed=*/true);
  }

  template <class P>
  static absl::Status AddLegacyKeyManager(
      std::unique_ptr<KeyManager<P>> key_manager,
      crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          kConfigurationImplErr);
    }
    return config.key_type_info_store_.AddKeyManager(std::move(key_manager),
                                                     /*new_key_allowed=*/true);
  }

  static absl::StatusOr<const crypto::tink::internal::KeyTypeInfoStore*>
  GetKeyTypeInfoStore(const crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          kConfigurationImplErr);
    }
    return &config.key_type_info_store_;
  }

  static absl::StatusOr<const crypto::tink::internal::KeysetWrapperStore*>
  GetKeysetWrapperStore(const crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          kConfigurationImplErr);
    }
    return &config.keyset_wrapper_store_;
  }

  // `config` can be set to global registry mode only if empty.
  static absl::Status SetGlobalRegistryMode(
      crypto::tink::Configuration& config) {
    if (!config.key_type_info_store_.IsEmpty() ||
        !config.keyset_wrapper_store_.IsEmpty()) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          "Using the global registry is only "
                          "allowed when Configuration is empty.");
    }
    config.global_registry_mode_ = true;
    return absl::OkStatus();
  }

  static bool IsInGlobalRegistryMode(
      const crypto::tink::Configuration& config) {
    return config.global_registry_mode_;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_CONFIGURATION_IMPL_H_
