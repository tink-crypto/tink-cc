// Copyright 2022 Google LLC
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

#include "tink/internal/keyset_handle_builder_entry.h"

#include <cstdint>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_status_util.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/parameters.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

SecretProto<Keyset::Key> ToKeysetKey(
    int id, KeyStatusType status, const ProtoKeySerialization& serialization) {
  SecretProto<Keyset::Key> key;
  key->set_status(status);
  key->set_key_id(id);
  key->set_output_prefix_type(serialization.GetOutputPrefixType());
  KeyData* key_data = key->mutable_key_data();
  key_data->set_type_url(std::string(serialization.TypeUrl()));
  internal::CallWithCoreDumpProtection([&]() {
    key_data->set_value(serialization.SerializedKeyProto().GetSecret(
        InsecureSecretKeyAccess::Get()));
  });
  key_data->set_key_material_type(serialization.KeyMaterialType());
  return key;
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const Parameters& params) {
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(params);
  if (!serialization.ok()) return serialization.status();

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  if (proto_serialization == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto parameters.");
  }

  return *proto_serialization;
}

util::StatusOr<ProtoParametersSerialization> SerializeLegacyParameters(
    const Parameters* params) {
  const LegacyProtoParameters* proto_params =
      dynamic_cast<const LegacyProtoParameters*>(params);
  if (proto_params == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to serialize legacy proto parameters.");
  }
  return proto_params->Serialization();
}

util::StatusOr<ProtoParametersSerialization> GetProtoParametersSerialization(
    const Parameters& params) {
  util::StatusOr<ProtoParametersSerialization> serialization =
      SerializeParameters(params);
  // TODO(b/359489205): Make sure that this excludes kNotFound error
  // potentially returned by registered classes.
  if (serialization.status().code() == absl::StatusCode::kNotFound) {
    // Fallback to legacy proto parameters.
    serialization = SerializeLegacyParameters(&params);
  }

  return serialization;
}

util::StatusOr<SecretProto<Keyset::Key>>
CreateKeysetKeyFromProtoParametersSerialization(
    const ProtoParametersSerialization& serialization, int id,
    KeyStatusType status, const KeyGenConfiguration& config) {
  // TODO(tholenst): ensure this doesn't leak.
  // Create KeyData from KeyTemplate and KeyTypeManagers.
  util::StatusOr<std::unique_ptr<KeyData>> key_data;
  if (internal::KeyGenConfigurationImpl::IsInGlobalRegistryMode(config)) {
    key_data = Registry::NewKeyData(serialization.GetKeyTemplate());
  } else {
    util::StatusOr<const internal::KeyTypeInfoStore*> key_type_info_store =
        internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    if (!key_type_info_store.ok()) {
      return key_type_info_store.status();
    }
    util::StatusOr<const internal::KeyTypeInfoStore::Info*> key_type_info =
        (*key_type_info_store)->Get(serialization.GetKeyTemplate().type_url());
    if (!key_type_info.ok()) {
      return key_type_info.status();
    }
    key_data = (*key_type_info)
                   ->key_factory()
                   .NewKeyData(serialization.GetKeyTemplate().value());
  }
  if (!key_data.ok()) {
    return key_data.status();
  }

  SecretProto<Keyset::Key> key;
  key->set_status(status);
  key->set_key_id(id);
  key->set_output_prefix_type(
      serialization.GetKeyTemplate().output_prefix_type());
  *key->mutable_key_data() = **key_data;
  return key;
}

// Creates Keyset::Key from KeyTemplate stored in serialized `parameters`.
util::StatusOr<SecretProto<Keyset::Key>> CreateKeysetKeyFromParameters(
    const Parameters& parameters, int id, KeyStatusType status,
    const KeyGenConfiguration& config) {
  util::StatusOr<ProtoParametersSerialization> serialization =
      GetProtoParametersSerialization(parameters);
  if (!serialization.ok()) {
    return serialization.status();
  }

  return CreateKeysetKeyFromProtoParametersSerialization(*serialization, id,
                                                         status, config);
}

util::StatusOr<ProtoKeySerialization> SerializeKey(const Key& key) {
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<ProtoKeySerialization>(key,
                                               InsecureSecretKeyAccess::Get());
  if (!serialization.ok()) return serialization.status();

  const ProtoKeySerialization* serialized_proto_key =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  if (serialized_proto_key == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto key.");
  }

  return *serialized_proto_key;
}

util::StatusOr<ProtoKeySerialization> SerializeLegacyKey(const Key* key) {
  const LegacyProtoKey* proto_key = dynamic_cast<const LegacyProtoKey*>(key);
  if (proto_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to serialize legacy proto key.");
  }
  util::StatusOr<const ProtoKeySerialization*> serialized_key =
      proto_key->Serialization(InsecureSecretKeyAccess::Get());
  if (!serialized_key.ok()) return serialized_key.status();

  return **serialized_key;
}

util::StatusOr<ProtoKeySerialization> GetProtoKeySerialization(const Key& key) {
  util::StatusOr<ProtoKeySerialization> serialization = SerializeKey(key);
  // TODO(b/359489205): Make sure that this excludes kNotFound error
  // potentially returned by registered classes.
  if (serialization.status().code() == absl::StatusCode::kNotFound) {
    // Fallback to legacy proto key.
    serialization = SerializeLegacyKey(&key);
  }

  return serialization;
}

util::StatusOr<SecretProto<Keyset::Key>>
CreateKeysetKeyFromProtoKeySerialization(const ProtoKeySerialization& key,
                                         int id, KeyStatusType status) {
  absl::optional<int> id_requirement = key.IdRequirement();
  if (id_requirement.has_value() && *id_requirement != id) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong ID set for key with ID requirement.");
  }
  return ToKeysetKey(id, status, key);
}

util::StatusOr<SecretProto<Keyset::Key>> CreateKeysetKeyFromKey(
    const Key& key, int id, KeyStatusType status) {
  util::StatusOr<ProtoKeySerialization> serialization =
      GetProtoKeySerialization(key);
  if (!serialization.ok()) {
    return serialization.status();
  }

  return CreateKeysetKeyFromProtoKeySerialization(*serialization, id, status);
}

}  // namespace

void KeysetHandleBuilderEntry::SetFixedId(int id) {
  strategy_.strategy = KeyIdStrategyEnum::kFixedId;
  strategy_.id_requirement = id;
}

void KeysetHandleBuilderEntry::SetRandomId() {
  strategy_.strategy = KeyIdStrategyEnum::kRandomId;
  strategy_.id_requirement = absl::nullopt;
}

// `config` is not used by KeyEntry, which does not generate new key material.
// However, CreateKeysetKey is defined in the parent KeysetHandleBuilderEntry,
// which both KeyEntry and ParametersEntry inherit from, so `config` must be
// part of this function signature.
util::StatusOr<SecretProto<Keyset::Key>> KeyEntry::CreateKeysetKey(
    int32_t id, const KeyGenConfiguration& /*config*/) {
  util::StatusOr<KeyStatusType> key_status = ToKeyStatusType(key_status_);
  if (!key_status.ok()) return key_status.status();

  if (GetKeyIdRequirement().has_value() && GetKeyIdRequirement() != id) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Requested id does not match id requirement.");
  }

  return CreateKeysetKeyFromKey(*key_, id, *key_status);
}

util::StatusOr<SecretProto<Keyset::Key>> ParametersEntry::CreateKeysetKey(
    int32_t id, const KeyGenConfiguration& config) {
  util::StatusOr<KeyStatusType> key_status = ToKeyStatusType(key_status_);
  if (!key_status.ok()) return key_status.status();

  if (GetKeyIdRequirement().has_value() && GetKeyIdRequirement() != id) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Requested id does not match id requirement.");
  }

  // Try to create a Key from Parameters using the KeyGenConfiguration. If
  // successful, create the keyset key from the proto key serialization. If in
  // global registry mode or the Parameters to KeyCreatorFn is not stored in the
  // passed config, continue and try to create the key from the proto parameters
  // serialization.
  if (!internal::KeyGenConfigurationImpl::IsInGlobalRegistryMode(config)) {
    absl::optional<int> id_requirement = parameters_->HasIdRequirement()
                                             ? absl::make_optional(id)
                                             : absl::nullopt;
    util::StatusOr<std::unique_ptr<Key>> key =
        internal::KeyGenConfigurationImpl::CreateKey(*parameters_,
                                                     id_requirement, config);

    if (!key.status().ok() &&
        key.status().code() != absl::StatusCode::kUnimplemented) {
      // Key creator function was found, but failed to create the key
      return key.status();
    } else if (key.status().ok()) {
      // Key creation successful
      return CreateKeysetKeyFromKey(**key, id, *key_status);
    }
  }

  // Global registry mode or KeyCreatorFn was not found; fall back to creating
  // the key from the KeyTemplate stored in Parameters.
  return CreateKeysetKeyFromParameters(*parameters_, id, *key_status, config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
