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

#ifndef TINK_INTERNAL_LEGACY_KEY_MANAGER_IMPL_H_
#define TINK_INTERNAL_LEGACY_KEY_MANAGER_IMPL_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/key_manager.h"
#include "tink/parameters.h"
#include "tink/util/protobuf_helper.h"

namespace crypto {
namespace tink {
namespace internal {

// TODO(guillaumee): Migrate proto messages to SecretProto.
// TODO(guillaumee): Add support for symmetric keys.
//
// Helper class to encode how to create a legacy PrivateKeyFactory from the
// modern proto-less API.
//
// Important: This class is only suitable for asymmetric private keys, and
// several implementation details currently assume that the key is
// asymmetric-private.
class LegacyPrivateKeyFactoryAdaptor {
 public:
  virtual ~LegacyPrivateKeyFactoryAdaptor() = default;

  // Returns the proto type name part of the KeyFormat URL, for example
  // "google.crypto.tink.MlDsaKeyFormat".
  virtual absl::string_view GetKeyFormatTypeName() const = 0;

  // Returns the proto type name part of the PrivateKey URL, for example
  // "google.crypto.tink.MlDsaPrivateKey".
  virtual absl::string_view GetPrivateKeyTypeName() const = 0;

  // Returns the proto type name part of the PublicKey URL, for example
  // "google.crypto.tink.MlDsaPublicKey".
  virtual absl::string_view GetPublicKeyTypeName() const = 0;

  // Returns a default instance of the KeyFormat proto, for example
  // google::crypto::tink::MlDsaKeyFormat.
  virtual std::unique_ptr<portable_proto::MessageLite>
  GetKeyFormatProtoDefaultInstance() const = 0;

  // Returns a default instance of the PrivateKey proto, for example
  // google::crypto::tink::MlDsaPrivateKey.
  virtual std::unique_ptr<portable_proto::MessageLite>
  GetPrivateKeyProtoDefaultInstance() const = 0;

  // Creates a new key using the given parameters (or returns an error if the
  // parameters are of the wrong type or invalid).
  virtual absl::StatusOr<std::unique_ptr<Key>> CreateKey(
      const Parameters& parameters) const = 0;
};

// TODO(guillaumee): Migrate proto messages to SecretProto.
// TODO(guillaumee): Add support for symmetric keys.
//
// This class provides an implementation of the PrivateKeyFactory interface
// based on the given adaptor.
//
// This allows implementing the legacy PrivateKeyFactory API from the modern
// proto-less API based on key classes.
//
// Important: This class is only suitable for asymmetric private keys, and
// several implementation details currently assume that the key is
// asymmetric-private.
class LegacyPrivateKeyFactoryImpl : public PrivateKeyFactory {
 public:
  // Creates a PrivateKeyFactory using the implementation defined by the given
  // adaptor.
  explicit LegacyPrivateKeyFactoryImpl(
      std::unique_ptr<LegacyPrivateKeyFactoryAdaptor> adaptor)
      : adaptor_(std::move(adaptor)) {}

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> NewKey(
      const portable_proto::MessageLite& key_format) const final;

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> NewKey(
      absl::string_view serialized_key_format) const final;

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>> NewKeyData(
      absl::string_view serialized_key_format) const final;

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view serialized_private_key) const final;

 private:
  std::unique_ptr<LegacyPrivateKeyFactoryAdaptor> adaptor_;
};

// TODO(guillaumee): Migrate proto messages to SecretProto.
//
// Helper class to encode how to create a legacy KeyManager from the modern
// proto-less API.
class LegacyKeyManagerBaseAdaptor {
 public:
  virtual ~LegacyKeyManagerBaseAdaptor() = default;

  // Returns the type URL that this key manager supports, e.g.
  // "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey".
  virtual const std::string& GetKeyType() const = 0;

  // Returns the key material type of that this manager supports.
  virtual KeyMaterialTypeTP GetKeyMaterialType() const = 0;

  // Returns the key factory to create keys of the type supported by this
  // manager.
  virtual const KeyFactory& GetKeyFactory() const = 0;

  // Obtains a key from the given key data proto (or returns an error if the
  // data contains a key of the wrong type or is invalid).
  absl::StatusOr<std::unique_ptr<Key>> GetKey(
      const google::crypto::tink::KeyData& key_data) const;

  // Obtains a key from the given key proto (or returns an error if the proto
  // contains a key of the wrong type or is invalid).
  absl::StatusOr<std::unique_ptr<Key>> GetKey(
      const portable_proto::MessageLite& key_proto) const;
};

// This class extends the base adaptor interface with methods that depend on the
// associated primitive class.
template <class Primitive>
class LegacyKeyManagerAdaptor : public LegacyKeyManagerBaseAdaptor {
 public:
  // Returns a primitive for the given key (or returns an error if the key has
  // the wrong type or is invalid).
  virtual absl::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const Key& key) const = 0;
};

// TODO(guillaumee): Migrate proto messages to SecretProto.
//
// This class provides an implementation of the KeyManager interface based on
// the given adaptor.
//
// This allows implementing the legacy KeyManager API from the modern proto-less
// API based on key classes.
template <class Primitive>
class LegacyKeyManagerImpl : public KeyManager<Primitive> {
 public:
  // Creates a KeyManager using the implementation defined by the given adaptor.
  explicit LegacyKeyManagerImpl(
      std::unique_ptr<LegacyKeyManagerAdaptor<Primitive>> adaptor)
      : adaptor_(std::move(adaptor)) {};

  const std::string& get_key_type() const final {
    return adaptor_->GetKeyType();
  }

  const KeyFactory& get_key_factory() const final {
    return adaptor_->GetKeyFactory();
  }

  uint32_t get_version() const final { return 0; }

  absl::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const final {
    absl::StatusOr<std::unique_ptr<Key>> key = adaptor_->GetKey(key_data);
    if (!key.ok()) {
      return key.status();
    }

    return adaptor_->GetPrimitive(**key);
  }

  absl::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const portable_proto::MessageLite& key_proto) const final {
    absl::StatusOr<std::unique_ptr<Key>> key = adaptor_->GetKey(key_proto);
    if (!key.ok()) {
      return key.status();
    }

    return adaptor_->GetPrimitive(**key);
  }

 private:
  std::unique_ptr<LegacyKeyManagerAdaptor<Primitive>> adaptor_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_LEGACY_KEY_MANAGER_IMPL_H_
