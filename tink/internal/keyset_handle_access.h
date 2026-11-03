// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_KEYSET_HANDLE_ACCESS_H_
#define TINK_INTERNAL_KEYSET_HANDLE_ACCESS_H_

#include <cstdint>
#include <memory>
#include <typeindex>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "tink/annotations.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/util/secret_proto.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Gives Tink-internal code access to the private members of `KeysetHandle`.
class KeysetHandleAccess {
 public:
  // Returns the keyset held by `keyset_handle`.
  static const google::crypto::tink::Keyset& GetKeyset(
      const KeysetHandle& keyset_handle) {
    return keyset_handle.get_keyset();
  }

  // Creates the list of `KeysetHandle::Entry` entries derived from `keyset`,
  // in order.
  static absl::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
  GetEntriesFromKeyset(const google::crypto::tink::Keyset& keyset) {
    return KeysetHandle::GetEntriesFromKeyset(keyset);
  }

  // Generates a key from `key_template` and adds it to `keyset`, possibly
  // making it the primary key if `as_primary` is true. Returns the
  // key ID of the added key.
  static absl::StatusOr<uint32_t> AddToKeyset(
      const google::crypto::tink::KeyTemplate& key_template, bool as_primary,
      const KeyGenConfiguration& config, google::crypto::tink::Keyset* keyset) {
    return KeysetHandle::AddToKeyset(key_template, as_primary, config, keyset);
  }

  // Creates a `KeysetHandle` that contains the given `keyset`.
  static KeysetHandle Create(
      util::SecretProto<google::crypto::tink::Keyset> keyset) {
    return KeysetHandle(std::move(keyset));
  }

  // Creates a `KeysetHandle` that contains the given `keyset` and `entries`.
  static KeysetHandle Create(
      util::SecretProto<google::crypto::tink::Keyset> keyset,
      std::vector<std::shared_ptr<const KeysetHandle::Entry>> entries) {
    return KeysetHandle(std::move(keyset), std::move(entries));
  }

  // Creates a `KeysetHandle` that contains the given `keyset`, `entries`, and
  // `annotations`.
  static KeysetHandle Create(
      util::SecretProto<google::crypto::tink::Keyset> keyset,
      std::vector<std::shared_ptr<const KeysetHandle::Entry>> entries,
      absl::flat_hash_map<std::type_index, std::unique_ptr<Annotations>>
          annotations) {
    return KeysetHandle(std::move(keyset), std::move(entries),
                        std::move(annotations));
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEYSET_HANDLE_ACCESS_H_
