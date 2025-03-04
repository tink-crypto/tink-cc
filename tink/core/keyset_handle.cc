// Copyright 2017 Google Inc.
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

#include "tink/keyset_handle.h"

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_info.h"
#include "tink/internal/key_status_util.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_manager.h"
#include "tink/key_status.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/private_key.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/util/errors.h"
#include "tink/util/keyset_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using ::crypto::tink::util::SecretProto;
using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeysetInfo;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

namespace {

absl::StatusOr<std::unique_ptr<EncryptedKeyset>> Encrypt(
    const Keyset& keyset, const Aead& master_key_aead,
    absl::string_view associated_data) {
  auto encrypt_result =
      master_key_aead.Encrypt(keyset.SerializeAsString(), associated_data);
  if (!encrypt_result.ok()) return encrypt_result.status();
  auto enc_keyset = absl::make_unique<EncryptedKeyset>();
  enc_keyset->set_encrypted_keyset(encrypt_result.value());
  return std::move(enc_keyset);
}

absl::StatusOr<util::SecretProto<Keyset>> Decrypt(
    const EncryptedKeyset& enc_keyset, const Aead& master_key_aead,
    absl::string_view associated_data) {
  auto decrypt_result =
      master_key_aead.Decrypt(enc_keyset.encrypted_keyset(), associated_data);
  if (!decrypt_result.ok()) return decrypt_result.status();
  util::SecretProto<Keyset> keyset;
  bool parsed = keyset->ParseFromString(decrypt_result.value());
  util::SafeZeroString(&decrypt_result.value());
  if (!parsed) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Could not parse the decrypted data as a Keyset-proto.");
  }
  return std::move(keyset);
}

absl::Status ValidateNoSecret(const Keyset& keyset) {
  for (const Keyset::Key& key : keyset.key()) {
    if (key.key_data().key_material_type() == KeyData::UNKNOWN_KEYMATERIAL ||
        key.key_data().key_material_type() == KeyData::SYMMETRIC ||
        key.key_data().key_material_type() == KeyData::ASYMMETRIC_PRIVATE) {
      return absl::Status(
          absl::StatusCode::kFailedPrecondition,
          "Cannot create KeysetHandle with secret key material from "
          "potentially unencrypted source.");
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<internal::ProtoKeySerialization> ToProtoKeySerialization(
    const Keyset::Key& key) {
  absl::optional<int> id_requirement = absl::nullopt;
  if (key.output_prefix_type() != OutputPrefixType::RAW) {
    id_requirement = key.key_id();
  }

  return internal::ProtoKeySerialization::Create(
      key.key_data().type_url(),
      RestrictedData(key.key_data().value(), InsecureSecretKeyAccess::Get()),
      key.key_data().key_material_type(), key.output_prefix_type(),
      id_requirement);
}

// Tries to serialize a LegacyProtoKey. Fails if the key is not a legacy type.
absl::StatusOr<internal::ProtoKeySerialization> SerializeLegacyKey(
    const Key& key) {
  const internal::LegacyProtoKey* proto_key =
      dynamic_cast<const internal::LegacyProtoKey*>(&key);
  if (proto_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to serialize legacy proto key.");
  }
  absl::StatusOr<const internal::ProtoKeySerialization*> serialized_key =
      proto_key->Serialization(InsecureSecretKeyAccess::Get());
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }

  return **serialized_key;
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(const Key& key) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              key, InsecureSecretKeyAccess::Get());
  if (!serialization.ok()) {
    return serialization.status();
  }

  const internal::ProtoKeySerialization* serialized_proto_key =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  if (serialized_proto_key == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto key.");
  }

  return *serialized_proto_key;
}

absl::StatusOr<internal::ProtoKeySerialization> GetProtoKeySerialization(
    const Key& key) {
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      SerializeKey(key);
  // TODO(b/359489205): Make sure that this excludes kNotFound error
  // potentially returned by registered classes.
  if (serialization.status().code() == absl::StatusCode::kNotFound) {
    // Fallback to legacy proto key.
    serialization = SerializeLegacyKey(key);
  }

  return serialization;
}

SecretProto<Keyset::Key> ToKeysetKey(
    int id, KeyStatusType status,
    const internal::ProtoKeySerialization& serialization) {
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

absl::StatusOr<SecretProto<Keyset::Key>>
CreateKeysetKeyFromProtoKeySerialization(
    const internal::ProtoKeySerialization& key, int id, KeyStatusType status) {
  absl::optional<int> id_requirement = key.IdRequirement();
  if (id_requirement.has_value() && *id_requirement != id) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong ID set for key with ID requirement.");
  }
  return ToKeysetKey(id, status, key);
}

absl::StatusOr<SecretProto<Keyset::Key>> CreateKeysetKey(const Key& key, int id,
                                                         KeyStatusType status) {
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      GetProtoKeySerialization(key);
  if (!serialization.ok()) {
    return serialization.status();
  }

  return CreateKeysetKeyFromProtoKeySerialization(*serialization, id, status);
}

}  // anonymous namespace

bool KeysetHandle::Entry::operator==(const Entry& other) const {
  return status_ == other.status_ && id_ == other.id_ &&
         is_primary_ == other.is_primary_ && *key_ == *other.key_;
}

absl::Status KeysetHandle::ValidateAt(int index) const {
  const Keyset::Key& proto_key = keyset_->key(index);
  OutputPrefixType output_prefix_type = proto_key.output_prefix_type();
  absl::optional<int> id_requirement = absl::nullopt;
  if (output_prefix_type != OutputPrefixType::RAW) {
    id_requirement = proto_key.key_id();
  }

  if (!internal::IsPrintableAscii(proto_key.key_data().type_url())) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "Non-printable ASCII character in type URL.");
  }

  absl::StatusOr<KeyStatus> key_status =
      internal::FromKeyStatusType(proto_key.status());
  if (!key_status.ok()) return key_status.status();

  return absl::OkStatus();
}

absl::Status KeysetHandle::Validate() const {
  int num_primary = 0;

  for (int i = 0; i < size(); ++i) {
    absl::Status status = ValidateAt(i);
    if (!status.ok()) return status;

    const Keyset::Key& proto_key = keyset_->key(i);
    if (proto_key.key_id() == keyset_->primary_key_id()) {
      ++num_primary;
      if (proto_key.status() != KeyStatusType::ENABLED) {
        return absl::Status(absl::StatusCode::kFailedPrecondition,
                            "Keyset has primary that is not enabled");
      }
    }
  }

  if (num_primary < 1) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "Keyset has no primary");
  }
  if (num_primary > 1) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "Keyset has more than one primary");
  }

  return absl::OkStatus();
}

KeysetHandle::Entry KeysetHandle::GetPrimary() const {
  absl::Status validation = Validate();
  CHECK_OK(validation);

  for (int i = 0; i < keyset_->key_size(); ++i) {
    if (keyset_->key(i).key_id() == keyset_->primary_key_id()) {
      return (*this)[i];
    }
  }

  // Since keyset handle was validated, it should have a valid primary key.
  internal::LogFatal("Keyset handle should have a valid primary key.");
}

KeysetHandle::Entry KeysetHandle::operator[](int index) const {
  CHECK(index >= 0 && index < size())
      << "Invalid index " << index << " for keyset of size " << size();

  if (!entries_.empty() && entries_.size() > index) {
    return *entries_[index];
  }
  // Since `entries_` has not been populated, the entry must be created on
  // demand from the key proto entry at `index` in `keyset_`. This special
  // case will no longer be necessary after `keyset_` has been removed from the
  // `KeysetHandle` class.
  //
  // TODO(b/277792846): Remove after transition to rely solely on
  // `KeysetHandle::Entry`.
  return CreateEntryAt(index);
}

KeysetHandle::Entry KeysetHandle::CreateEntryAt(int index) const {
  CHECK(index >= 0 && index < size())
      << "Invalid index " << index << " for keyset of size " << size();

  absl::Status validation = ValidateAt(index);
  CHECK_OK(validation);

  absl::StatusOr<Entry> entry =
      CreateEntry(keyset_->key(index), keyset_->primary_key_id());
  // Status should be OK since this keyset handle has been validated.
  CHECK_OK(entry.status());
  return *entry;
}

absl::StatusOr<KeysetHandle::Entry> KeysetHandle::CreateEntry(
    const Keyset::Key& proto_key, uint32_t primary_key_id) {
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      ToProtoKeySerialization(proto_key);
  if (!serialization.ok()) {
    return serialization.status();
  }

  absl::StatusOr<std::shared_ptr<const Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKeyWithLegacyFallback(*serialization,
                                      InsecureSecretKeyAccess::Get());
  if (!key.ok()) {
    return key.status();
  }

  absl::StatusOr<KeyStatus> key_status =
      internal::FromKeyStatusType(proto_key.status());
  if (!key_status.ok()) {
    return key_status.status();
  }

  return Entry(*std::move(key), *key_status, proto_key.key_id(),
               proto_key.key_id() == primary_key_id);
}

absl::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::Read(
    std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead,
    absl::flat_hash_map<std::string, std::string> monitoring_annotations) {
  return ReadWithAssociatedData(std::move(reader), master_key_aead,
                                /*associated_data=*/"",
                                std::move(monitoring_annotations));
}

absl::StatusOr<std::unique_ptr<KeysetHandle>>
KeysetHandle::ReadWithAssociatedData(
    std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead,
    absl::string_view associated_data,
    absl::flat_hash_map<std::string, std::string> monitoring_annotations) {
  absl::StatusOr<std::unique_ptr<EncryptedKeyset>> enc_keyset_result =
      reader->ReadEncrypted();
  if (!enc_keyset_result.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Error reading encrypted keyset data: %s",
                     enc_keyset_result.status().message());
  }

  auto keyset_result =
      Decrypt(*enc_keyset_result.value(), master_key_aead, associated_data);
  if (!keyset_result.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Error decrypting encrypted keyset: %s",
                     keyset_result.status().message());
  }
  absl::StatusOr<std::vector<std::shared_ptr<const Entry>>> entries =
      GetEntriesFromKeyset(**keyset_result);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != (*keyset_result)->key_size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return absl::WrapUnique(new KeysetHandle(*std::move(keyset_result),
                                           *std::move(entries),
                                           std::move(monitoring_annotations)));
}

absl::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::ReadNoSecret(
    const std::string& serialized_keyset,
    absl::flat_hash_map<std::string, std::string> monitoring_annotations) {
  util::SecretProto<Keyset> keyset;
  if (!keyset->ParseFromString(serialized_keyset)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Could not parse the input string as a Keyset-proto.");
  }
  absl::Status validation = ValidateNoSecret(*keyset);
  if (!validation.ok()) {
    return validation;
  }
  absl::StatusOr<std::vector<std::shared_ptr<const Entry>>> entries =
      GetEntriesFromKeyset(*keyset);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != keyset->key_size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return absl::WrapUnique(new KeysetHandle(std::move(keyset),
                                           *std::move(entries),
                                           std::move(monitoring_annotations)));
}

absl::Status KeysetHandle::Write(KeysetWriter* writer,
                                 const Aead& master_key_aead) const {
  return WriteWithAssociatedData(writer, master_key_aead, "");
}

absl::Status KeysetHandle::WriteWithAssociatedData(
    KeysetWriter* writer, const Aead& master_key_aead,
    absl::string_view associated_data) const {
  if (writer == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Writer must be non-null");
  }
  auto encrypt_result = Encrypt(*keyset_, master_key_aead, associated_data);
  if (!encrypt_result.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Encryption of the keyset failed: %s",
                     encrypt_result.status().message());
  }
  return writer->Write(*(encrypt_result.value()));
}

absl::Status KeysetHandle::WriteNoSecret(KeysetWriter* writer) const {
  if (writer == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Writer must be non-null");
  }

  absl::Status validation = ValidateNoSecret(*keyset_);
  if (!validation.ok()) return validation;

  return writer->Write(*keyset_);
}

absl::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::GenerateNew(
    const KeyTemplate& key_template, const KeyGenConfiguration& config,
    absl::flat_hash_map<std::string, std::string> monitoring_annotations) {
  auto handle = absl::WrapUnique(new KeysetHandle(
      util::SecretProto<Keyset>(), std::move(monitoring_annotations)));
  const absl::StatusOr<uint32_t> result =
      handle->AddKey(key_template, /*as_primary=*/true, config);
  if (!result.ok()) {
    return result.status();
  }
  return std::move(handle);
}

absl::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::GenerateNew(
    const KeyTemplate& key_template, const KeyGenConfiguration& config) {
  return GenerateNew(key_template, config, /*monitoring_annotations=*/{});
}

absl::StatusOr<std::unique_ptr<Keyset::Key>> ExtractPublicKey(
    const Keyset::Key& key, const KeyGenConfiguration& config) {
  if (key.key_data().key_material_type() != KeyData::ASYMMETRIC_PRIVATE) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Key material is not of type KeyData::ASYMMETRIC_PRIVATE");
  }

  absl::StatusOr<std::unique_ptr<KeyData>> key_data;
  if (internal::KeyGenConfigurationImpl::IsInGlobalRegistryMode(config)) {
    key_data = Registry::GetPublicKeyData(key.key_data().type_url(),
                                          key.key_data().value());
  } else {
    absl::StatusOr<const internal::KeyTypeInfoStore*> key_type_info_store =
        internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    if (!key_type_info_store.ok()) {
      return key_type_info_store.status();
    }
    absl::StatusOr<const internal::KeyTypeInfoStore::Info*> key_type_info =
        (*key_type_info_store)->Get(key.key_data().type_url());
    if (!key_type_info.ok()) {
      return key_type_info.status();
    }
    auto factory = dynamic_cast<const PrivateKeyFactory*>(
        &(*key_type_info)->key_factory());
    if (factory == nullptr) {
      return ToStatusF(
          absl::StatusCode::kInvalidArgument,
          "KeyManager for type '%s' does not have a PrivateKeyFactory.",
          key.key_data().type_url());
    }
    key_data = factory->GetPublicKeyData(key.key_data().value());
  }
  if (!key_data.ok()) {
    return key_data.status();
  }

  auto public_key = absl::make_unique<Keyset::Key>();
  public_key->set_key_id(key.key_id());
  public_key->set_status(key.status());
  public_key->set_output_prefix_type(key.output_prefix_type());
  *public_key->mutable_key_data() = std::move(**key_data);
  return std::move(public_key);
}

absl::StatusOr<std::unique_ptr<KeysetHandle>>
KeysetHandle::GetPublicKeysetHandle(const KeyGenConfiguration& config) const {
  util::SecretProto<Keyset> public_keyset;
  std::vector<std::shared_ptr<const Entry>> public_entries;

  for (int i = 0; i < keyset_->key().size(); ++i) {
    const Keyset::Key& key = keyset_->key(i);
    const Entry& entry = (*this)[i];
    const PrivateKey* private_key =
        dynamic_cast<const PrivateKey*>(entry.GetKey().get());
    if (private_key != nullptr) {
      absl::StatusOr<KeyStatusType> key_status =
          internal::ToKeyStatusType(entry.GetStatus());
      if (!key_status.ok()) {
        return key_status.status();
      }
      absl::StatusOr<SecretProto<Keyset::Key>> public_key = CreateKeysetKey(
          private_key->GetPublicKey(), entry.GetId(), key_status.value());
      if (!public_key.ok()) {
        return public_key.status();
      }
      // TODO(b/370439805): Replace this with creating a new entry from the
      // public key directly, after a way to get a dynamically allocated copy of
      // a key object reference is implemented.
      absl::StatusOr<const Entry> public_key_entry =
          CreateEntry(*public_key.value(), keyset_->primary_key_id());
      if (!public_key_entry.ok()) {
        return public_key_entry.status();
      }
      public_entries.push_back(
          std::make_shared<const Entry>(*public_key_entry));
      public_keyset->add_key()->Swap(&(*public_key.value()));
      // Falls back to legacy behavior.
    } else {
      auto public_key_result = ExtractPublicKey(key, config);
      if (!public_key_result.ok()) {
        return public_key_result.status();
      }
      absl::StatusOr<const Entry> entry =
          CreateEntry(*public_key_result.value(), keyset_->primary_key_id());
      if (!entry.ok()) {
        return entry.status();
      }
      public_entries.push_back(std::make_shared<const Entry>(*entry));
      public_keyset->add_key()->Swap(public_key_result.value().get());
    }
  }

  public_keyset->set_primary_key_id(keyset_->primary_key_id());
  if (public_entries.size() != public_keyset->key_size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return absl::WrapUnique<KeysetHandle>(
      new KeysetHandle(std::move(public_keyset), std::move(public_entries)));
}

absl::StatusOr<uint32_t> KeysetHandle::AddToKeyset(
    const google::crypto::tink::KeyTemplate& key_template, bool as_primary,
    const KeyGenConfiguration& config, Keyset* keyset) {
  if (key_template.output_prefix_type() ==
      google::crypto::tink::OutputPrefixType::UNKNOWN_PREFIX) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key template has UNKNOWN prefix");
  }
  if (key_template.output_prefix_type() ==
      google::crypto::tink::OutputPrefixType::WITH_ID_REQUIREMENT) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key template has WITH_ID_REQUIREMENT prefix");
  }

  // Generate new key data.
  absl::StatusOr<std::unique_ptr<KeyData>> key_data;
  if (internal::KeyGenConfigurationImpl::IsInGlobalRegistryMode(config)) {
    key_data = Registry::NewKeyData(key_template);
  } else {
    absl::StatusOr<const internal::KeyTypeInfoStore*> key_type_info_store =
        internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    if (!key_type_info_store.ok()) {
      return key_type_info_store.status();
    }
    absl::StatusOr<const internal::KeyTypeInfoStore::Info*> key_type_info =
        (*key_type_info_store)->Get(key_template.type_url());
    if (!key_type_info.ok()) {
      return key_type_info.status();
    }
    key_data = (*key_type_info)->key_factory().NewKeyData(key_template.value());
  }
  if (!key_data.ok()) {
    return key_data.status();
  }

  // Add and fill in new key in `keyset`.
  Keyset::Key* key = keyset->add_key();
  *(key->mutable_key_data()) = *std::move(key_data).value();
  key->set_status(KeyStatusType::ENABLED);
  key->set_output_prefix_type(key_template.output_prefix_type());

  uint32_t key_id = GenerateUnusedKeyId(*keyset);
  key->set_key_id(key_id);
  if (as_primary) {
    keyset->set_primary_key_id(key_id);
  }
  return key_id;
}

absl::StatusOr<uint32_t> KeysetHandle::AddKey(
    const google::crypto::tink::KeyTemplate& key_template, bool as_primary,
    const KeyGenConfiguration& config) {
  absl::StatusOr<uint32_t> id =
      AddToKeyset(key_template, as_primary, config, keyset_.get());
  if (!id.ok()) {
    return id.status();
  }
  absl::StatusOr<const Entry> entry = CreateEntry(
      keyset_->key(keyset_->key_size() - 1), keyset_->primary_key_id());
  if (!entry.ok()) {
    return entry.status();
  }
  entries_.push_back(std::make_shared<const Entry>(*entry));
  return *id;
}

KeysetInfo KeysetHandle::GetKeysetInfo() const {
  return KeysetInfoFromKeyset(*keyset_);
}

absl::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
KeysetHandle::GetEntriesFromKeyset(const Keyset& keyset) {
  std::vector<std::shared_ptr<const Entry>> entries;
  for (const Keyset::Key& key : keyset.key()) {
    absl::StatusOr<const Entry> entry =
        CreateEntry(key, keyset.primary_key_id());
    if (!entry.ok()) {
      return entry.status();
    }
    entries.push_back(std::make_shared<const Entry>(*entry));
  }
  return entries;
}

}  // namespace tink
}  // namespace crypto
