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

#include "tink/internal/legacy_key_manager_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/private_key.h"
#include "tink/restricted_data.h"
#include "tink/util/constants.h"
#include "tink/util/protobuf_helper.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
LegacyPrivateKeyFactoryImpl::NewKey(
    const portable_proto::MessageLite& key_format) const {
  if (key_format.GetTypeName() != adaptor_->GetKeyFormatTypeName()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key format proto '", key_format.GetTypeName(),
                     "' is not supported by this key manager."));
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      parameters_serialization = internal::ProtoParametersSerialization::Create(
          absl::StrCat(kTypeGoogleapisCom, adaptor_->GetPrivateKeyTypeName()),
          OutputPrefixTypeTP::kRaw, key_format.SerializeAsString());
  if (!parameters_serialization.ok()) {
    return parameters_serialization.status();
  }

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *parameters_serialization);
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<std::unique_ptr<Key>> private_key =
      adaptor_->CreateKey(**parameters);
  if (!private_key.ok()) {
    return private_key.status();
  }

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              **private_key, GetInsecureSecretKeyAccessInternal());
  if (!serialization.ok()) {
    return serialization.status();
  }

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  if (proto_serialization == nullptr) {
    return absl::InternalError(
        "Expected a ProtoKeySerialization but got another serialization "
        "type.");
  }

  std::unique_ptr<portable_proto::MessageLite> proto_key =
      adaptor_->GetPrivateKeyProtoDefaultInstance();
  if (!proto_key->ParseFromString(
          proto_serialization->SerializedKeyProto().GetSecret(
              GetInsecureSecretKeyAccessInternal()))) {
    return absl::InternalError(
        absl::StrCat("Failed to parse private key as proto '",
                     adaptor_->GetPrivateKeyTypeName(), "'."));
  }
  return std::move(proto_key);
}

absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
LegacyPrivateKeyFactoryImpl::NewKey(
    absl::string_view serialized_key_format) const {
  std::unique_ptr<portable_proto::MessageLite> key_format =
      adaptor_->GetKeyFormatProtoDefaultInstance();
  if (!key_format->ParseFromString(serialized_key_format)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Could not parse the passed string as proto '",
                     adaptor_->GetKeyFormatTypeName(), "'."));
  }
  return NewKey(*key_format);
}

absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
LegacyPrivateKeyFactoryImpl::NewKeyData(
    absl::string_view serialized_key_format) const {
  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> new_key =
      NewKey(serialized_key_format);
  if (!new_key.ok()) {
    return new_key.status();
  }

  auto key_data = absl::make_unique<google::crypto::tink::KeyData>();
  key_data->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, adaptor_->GetPrivateKeyTypeName()));
  key_data->set_value((*new_key)->SerializeAsString());
  key_data->set_key_material_type(
      google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE);
  return std::move(key_data);
}

absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
LegacyPrivateKeyFactoryImpl::GetPublicKeyData(
    absl::string_view serialized_private_key) const {
  RestrictedData serialized_key = RestrictedData(
      serialized_private_key, GetInsecureSecretKeyAccessInternal());
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          absl::StrCat(kTypeGoogleapisCom, adaptor_->GetPrivateKeyTypeName()),
          serialized_key, KeyMaterialTypeTP::kAsymmetricPrivate,
          OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/absl::nullopt);
  if (!serialization.ok()) {
    return serialization.status();
  }

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, GetInsecureSecretKeyAccessInternal());
  if (!key.ok()) {
    return key.status();
  }

  const PrivateKey* private_key = dynamic_cast<const PrivateKey*>(key->get());
  if (private_key == nullptr) {
    return absl::InternalError("Unexpected key type: not a private key.");
  }
  const Key& public_key = private_key->GetPublicKey();

  absl::StatusOr<std::unique_ptr<Serialization>> public_key_serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              public_key, GetInsecureSecretKeyAccessInternal());
  if (!public_key_serialization.ok()) {
    return public_key_serialization.status();
  }

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          public_key_serialization->get());
  if (proto_serialization == nullptr) {
    return absl::InternalError(
        "Expected a ProtoKeySerialization but got another serialization "
        "type.");
  }

  auto key_data = absl::make_unique<google::crypto::tink::KeyData>();
  key_data->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, adaptor_->GetPublicKeyTypeName()));
  key_data->set_value(proto_serialization->SerializedKeyProto().GetSecret(
      GetInsecureSecretKeyAccessInternal()));
  key_data->set_key_material_type(
      google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC);
  return std::move(key_data);
}

absl::StatusOr<std::unique_ptr<Key>> LegacyKeyManagerBaseAdaptor::GetKey(
    const google::crypto::tink::KeyData& key_data) const {
  if (key_data.type_url() != GetKeyType()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Key type '", key_data.type_url(),
                     "' is not supported by this key manager."));
  }

  RestrictedData serialized_key =
      RestrictedData(key_data.value(), GetInsecureSecretKeyAccessInternal());
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(GetKeyType(), serialized_key,
                                              GetKeyMaterialType(),
                                              OutputPrefixTypeTP::kRaw,
                                              /*id_requirement=*/absl::nullopt);
  if (!serialization.ok()) {
    return serialization.status();
  }

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, GetInsecureSecretKeyAccessInternal());
  return key;
}

absl::StatusOr<std::unique_ptr<Key>> LegacyKeyManagerBaseAdaptor::GetKey(
    const portable_proto::MessageLite& key_proto) const {
  std::string key_type =
      absl::StrCat(kTypeGoogleapisCom, key_proto.GetTypeName());
  if (key_type != GetKeyType()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Key type '", key_type, "' is not supported by this key manager."));
  }

  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), GetInsecureSecretKeyAccessInternal());
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(GetKeyType(), serialized_key,
                                              GetKeyMaterialType(),
                                              OutputPrefixTypeTP::kRaw,
                                              /*id_requirement=*/absl::nullopt);
  if (!serialization.ok()) {
    return serialization.status();
  }

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, GetInsecureSecretKeyAccessInternal());
  return key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
