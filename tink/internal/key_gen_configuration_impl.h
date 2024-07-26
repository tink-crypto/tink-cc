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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_KEY_GEN_CONFIGURATION_IMPL_H_
#define TINK_INTERNAL_KEY_GEN_CONFIGURATION_IMPL_H_

#include <memory>
#include <typeindex>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_manager.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr absl::string_view kKeyGenConfigurationImplErr =
    "Use crypto::tink::Registry instead when in global registry mode.";

class KeyGenConfigurationImpl {
 public:
  template <class KM>
  static crypto::tink::util::Status AddKeyTypeManager(
      std::unique_ptr<KM> key_manager,
      crypto::tink::KeyGenConfiguration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kKeyGenConfigurationImplErr);
    }
    return config.key_type_info_store_.AddKeyTypeManager(
        std::move(key_manager), /*new_key_allowed=*/true);
  }

  template <class PrivateKM, class PublicKM>
  static crypto::tink::util::Status AddAsymmetricKeyManagers(
      std::unique_ptr<PrivateKM> private_key_manager,
      std::unique_ptr<PublicKM> public_key_manager,
      crypto::tink::KeyGenConfiguration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kKeyGenConfigurationImplErr);
    }
    return config.key_type_info_store_.AddAsymmetricKeyTypeManagers(
        std::move(private_key_manager), std::move(public_key_manager),
        /*new_key_allowed=*/true);
  }

  template <class P>
  static crypto::tink::util::Status AddLegacyKeyManager(
      std::unique_ptr<KeyManager<P>> key_manager,
      crypto::tink::KeyGenConfiguration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kKeyGenConfigurationImplErr);
    }
    return config.key_type_info_store_.AddKeyManager(std::move(key_manager),
                                                     /*new_key_allowed=*/true);
  }

  template <class P>
  static crypto::tink::util::Status AddKeyCreator(
      KeyCreatorFn<P> key_creator_fn,
      crypto::tink::KeyGenConfiguration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kKeyGenConfigurationImplErr);
    }
    // Check if the key creator already exists.
    auto it = config.key_creator_fn_map_.find(std::type_index(typeid(P)));
    if (it != config.key_creator_fn_map_.end()) {
      return util::Status(absl::StatusCode::kUnimplemented,
                          absl::StrCat("Key creator for ", typeid(P).name(),
                                       " already exists."));
    }

    KeyCreatorFn<Parameters> wrapped_fn =
        [key_creator_fn = std::move(key_creator_fn)](
            const Parameters& params, absl::optional<int> key_template_index)
        -> util::StatusOr<std::unique_ptr<Key>> {
      const P* p = dynamic_cast<const P*>(&params);
      if (p) {
        return key_creator_fn(*p, key_template_index);
      } else {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "Failed to cast Parameters to P");
      }
    };

    config.key_creator_fn_map_.insert(
        {std::type_index(typeid(P)), std::move(wrapped_fn)});
    return crypto::tink::util::OkStatus();
  }

  static crypto::tink::util::StatusOr<
      const crypto::tink::internal::KeyTypeInfoStore*>
  GetKeyTypeInfoStore(const crypto::tink::KeyGenConfiguration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kKeyGenConfigurationImplErr);
    }
    return &config.key_type_info_store_;
  }

  // Creates a new key from `parameters` using `config`'s `key_creator_fn_map_`.
  // Only works for key types added to `config` via `AddKeyCreator`.
  static crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::Key>>
  CreateKey(const crypto::tink::Parameters& parameters,
            absl::optional<int> id_requirement,
            const crypto::tink::KeyGenConfiguration& config) {
    auto it =
        config.key_creator_fn_map_.find(std::type_index(typeid(parameters)));
    if (it == config.key_creator_fn_map_.end()) {
      return util::Status(absl::StatusCode::kUnimplemented,
                          absl::StrCat("Key creator not found for ",
                                       typeid(parameters).name()));
    }
    return it->second(parameters, id_requirement);
  }

  // `config` can be set to global registry mode only if empty.
  static crypto::tink::util::Status SetGlobalRegistryMode(
      crypto::tink::KeyGenConfiguration& config) {
    if (!config.key_type_info_store_.IsEmpty()) {
      return crypto::tink::util::Status(
          absl::StatusCode::kFailedPrecondition,
          "Using the global registry is only allowed when KeyGenConfiguration "
          "is empty.");
    }
    config.global_registry_mode_ = true;
    return crypto::tink::util::OkStatus();
  }

  static bool IsInGlobalRegistryMode(
      const crypto::tink::KeyGenConfiguration& config) {
    return config.global_registry_mode_;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_GEN_CONFIGURATION_IMPL_H_
