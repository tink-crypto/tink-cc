// Copyright 2024 Google LLC
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

#include "tink/keyderivation/keyset_deriver.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_proto_serialization.h"
#include "tink/config/global_registry.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/keyderivation/keyset_deriver_wrapper.h"
#include "tink/keyset_handle.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/hmac_proto_serialization.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

// Hex values from HKDF RFC https://tools.ietf.org/html/rfc5869#appendix-A.2.
static constexpr absl::string_view kOkmFromRfc =
    "b11e398dc80327a1c8e7f78c596a4934"
    "4f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09"
    "da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f";

KeyData PrfKeyFromRfc() {
  google::crypto::tink::HkdfPrfKey prf_key;
  prf_key.set_version(0);
  prf_key.mutable_params()->set_hash(HashType::SHA256);
  prf_key.mutable_params()->set_salt(
      test::HexDecodeOrDie("606162636465666768696a6b6c6d6e6f"
                           "707172737475767778797a7b7c7d7e7f"
                           "808182838485868788898a8b8c8d8e8f"
                           "909192939495969798999a9b9c9d9e9f"
                           "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));
  prf_key.set_key_value(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"
                           "101112131415161718191a1b1c1d1e1f"
                           "202122232425262728292a2b2c2d2e2f"
                           "303132333435363738393a3b3c3d3e3f"
                           "404142434445464748494a4b4c4d4e4f"));
  return test::AsKeyData(prf_key, KeyData::SYMMETRIC);
}

std::string SaltFromRfc() {
  return test::HexDecodeOrDie(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
}

std::unique_ptr<AesCtrHmacAeadKey> CreateAesCtrHmacAeadKey(
    int aes_key_size, int tag_size, AesCtrHmacAeadParameters::Variant variant,
    absl::string_view aes_secret, absl::string_view hmac_secret,
    absl::optional<int> id_requirement) {
  AesCtrHmacAeadParameters params =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(aes_key_size)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(tag_size)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(variant)
          .Build()
          .value();
  return std::make_unique<AesCtrHmacAeadKey>(
      AesCtrHmacAeadKey::Builder()
          .SetParameters(params)
          .SetAesKeyBytes(RestrictedData(test::HexDecodeOrDie(aes_secret),
                                         InsecureSecretKeyAccess::Get()))
          .SetHmacKeyBytes(RestrictedData(test::HexDecodeOrDie(hmac_secret),
                                          InsecureSecretKeyAccess::Get()))
          .SetIdRequirement(id_requirement)
          .Build(GetPartialKeyAccess())
          .value());
}

std::unique_ptr<AesGcmKey> CreateAesGcmKey(int key_size,
                                           AesGcmParameters::Variant variant,
                                           absl::string_view secret,
                                           absl::optional<int> id_requirement) {
  AesGcmParameters params = AesGcmParameters::Builder()
                                .SetKeySizeInBytes(key_size)
                                .SetIvSizeInBytes(12)
                                .SetTagSizeInBytes(16)
                                .SetVariant(variant)
                                .Build()
                                .value();
  return std::make_unique<AesGcmKey>(
      AesGcmKey::Create(params,
                        RestrictedData(test::HexDecodeOrDie(secret),
                                       InsecureSecretKeyAccess::Get()),
                        id_requirement, GetPartialKeyAccess())
          .value());
}

std::unique_ptr<XChaCha20Poly1305Key> CreateXChaCha20Poly1305Key(
    XChaCha20Poly1305Parameters::Variant variant, absl::string_view secret,
    absl::optional<int> id_requirement) {
  return std::make_unique<XChaCha20Poly1305Key>(
      XChaCha20Poly1305Key::Create(
          variant,
          RestrictedData(test::HexDecodeOrDie(secret),
                         InsecureSecretKeyAccess::Get()),
          id_requirement, GetPartialKeyAccess())
          .value());
}

std::unique_ptr<HmacKey> CreateHmacKey(int key_size, int cryptographic_tag_size,
                                       HmacParameters::HashType hash_type,
                                       HmacParameters::Variant variant,
                                       absl::string_view secret,
                                       absl::optional<int> id_requirement) {
  HmacParameters params =
      HmacParameters::Create(key_size, cryptographic_tag_size, hash_type,
                             variant)
          .value();
  return std::make_unique<HmacKey>(
      HmacKey::Create(params,
                      RestrictedData(test::HexDecodeOrDie(secret),
                                     InsecureSecretKeyAccess::Get()),
                      id_requirement, GetPartialKeyAccess())
          .value());
}

std::vector<std::vector<std::shared_ptr<Key>>> TestVectors() {
  return {
      /*AEAD KeysetHandle*/ {
          CreateAesCtrHmacAeadKey(
              /*aes_key_size=*/16, /*tag_size=*/16,
              AesCtrHmacAeadParameters::Variant::kTink,
              /*aes_secret=*/kOkmFromRfc.substr(0, 32),
              /*hmac_secret=*/kOkmFromRfc.substr(32, 64),
              /*id_requirement=*/1010101),
          CreateAesCtrHmacAeadKey(
              /*aes_key_size=*/32, /*tag_size=*/32,
              AesCtrHmacAeadParameters::Variant::kCrunchy,
              /*aes_secret=*/kOkmFromRfc.substr(0, 64),
              /*hmac_secret=*/kOkmFromRfc.substr(64, 64),
              /*id_requirement=*/2020202),
          CreateAesCtrHmacAeadKey(
              /*aes_key_size=*/16, /*tag_size=*/16,
              AesCtrHmacAeadParameters::Variant::kNoPrefix,
              /*aes_secret=*/kOkmFromRfc.substr(0, 32),
              /*hmac_secret=*/kOkmFromRfc.substr(32, 64),
              /*id_requirement=*/absl::nullopt),
          CreateAesGcmKey(
              /*key_size=*/16, AesGcmParameters::Variant::kTink,
              kOkmFromRfc.substr(0, 32), /*id_requirement=*/3030303),
          CreateAesGcmKey(
              /*key_size=*/32, AesGcmParameters::Variant::kCrunchy,
              kOkmFromRfc.substr(0, 64), /*id_requirement=*/4040404),
          CreateAesGcmKey(
              /*key_size=*/16, AesGcmParameters::Variant::kNoPrefix,
              kOkmFromRfc.substr(0, 32), /*id_requirement=*/absl::nullopt),
          CreateXChaCha20Poly1305Key(
              XChaCha20Poly1305Parameters::Variant::kTink,
              kOkmFromRfc.substr(0, 64), /*id_requirement=*/5050505),
          CreateXChaCha20Poly1305Key(
              XChaCha20Poly1305Parameters::Variant::kCrunchy,
              kOkmFromRfc.substr(0, 64), /*id_requirement=*/6060606),
          CreateXChaCha20Poly1305Key(
              XChaCha20Poly1305Parameters::Variant::kNoPrefix,
              kOkmFromRfc.substr(0, 64), /*id_requirement=*/absl::nullopt),
      },
      /*MAC KeysetHandle*/
      {
          CreateHmacKey(
              /*key_size=*/16, /*cryptographic_tag_size=*/10,
              HmacParameters::HashType::kSha256, HmacParameters::Variant::kTink,
              kOkmFromRfc.substr(0, 32), /*id_requirement=*/1010101),
          CreateHmacKey(
              /*key_size=*/24, /*cryptographic_tag_size=*/16,
              HmacParameters::HashType::kSha384,
              HmacParameters::Variant::kCrunchy, kOkmFromRfc.substr(0, 48),
              /*id_requirement=*/2020202),
          CreateHmacKey(
              /*key_size=*/32, /*cryptographic_tag_size=*/32,
              HmacParameters::HashType::kSha512,
              HmacParameters::Variant::kNoPrefix, kOkmFromRfc.substr(0, 64),
              /*id_requirement=*/absl::nullopt),
      },
  };
}

util::StatusOr<std::unique_ptr<KeysetHandle>> CreatePrfBasedDeriverHandle(
    std::vector<std::shared_ptr<Key>> derived_keys) {
  Keyset keyset;
  keyset.set_primary_key_id(derived_keys[0]->GetIdRequirement().value_or(0));

  for (const auto& derived_key : derived_keys) {
    // Get KeyTemplate from Parameters.
    util::StatusOr<std::unique_ptr<Serialization>> serialization =
        internal::MutableSerializationRegistry::GlobalInstance()
            .SerializeParameters<internal::ProtoParametersSerialization>(
                derived_key->GetParameters());
    if (!serialization.ok()) {
      return serialization.status();
    }
    const internal::ProtoParametersSerialization* proto_serialization =
        dynamic_cast<const internal::ProtoParametersSerialization*>(
            serialization->get());
    if (proto_serialization == nullptr) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Serialization is not ProtoParametersSerialization");
    }
    KeyTemplate derived_key_template = proto_serialization->GetKeyTemplate();

    // Create PrfBasedDeriverKey.
    google::crypto::tink::PrfBasedDeriverKey deriver_key;
    deriver_key.set_version(0);
    *deriver_key.mutable_prf_key() = PrfKeyFromRfc();
    *deriver_key.mutable_params()->mutable_derived_key_template() =
        derived_key_template;

    // Add PrfBasedDeriverKey to Keyset.
    Keyset::Key* keyset_key = keyset.add_key();
    *(keyset_key->mutable_key_data()) =
        test::AsKeyData(deriver_key, KeyData::SYMMETRIC);
    keyset_key->set_status(KeyStatusType::ENABLED);
    keyset_key->set_output_prefix_type(
        derived_key_template.output_prefix_type());
    keyset_key->set_key_id(derived_key->GetIdRequirement().value_or(0));
  }

  return TestKeysetHandle::GetKeysetHandle(keyset);
}

class KeysetDeriverTest
    : public TestWithParam<std::vector<std::shared_ptr<Key>>> {
  void TearDown() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(KeysetDeriverTests, KeysetDeriverTest,
                         ValuesIn(TestVectors()));

TEST_P(KeysetDeriverTest, PrfBasedDeriveKeyset) {
  std::vector<std::shared_ptr<Key>> derived_keys = GetParam();

  // Create KeysetDeriver KeysetHandle with the Parameters in `derived_keys`.

  // Proto serialization is required to convert the Parameters in `derived_keys`
  // to a KeyTemplate, which are used to create the KeysetDeriver KeysetHandle.
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesGcmProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterXChaCha20Poly1305ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      CreatePrfBasedDeriverHandle(derived_keys);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT((*handle)->size(), Eq(derived_keys.size()));

  // TODO(b/314831964): Remove once KeysetDeriver does not depend on the global
  // registry.
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<internal::PrfBasedDeriverKeyManager>(), true),
      IsOk());

  // Create primitive.
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*handle)->GetPrimitive<KeysetDeriver>(ConfigGlobalRegistry());
  ASSERT_THAT(deriver, IsOk());

  // Ensure key derivation does not use the global registry.
  Registry::Reset();

  // Derive KeysetHandle using the non-global ParametersToKeyDeriver map.
  util::StatusOr<std::unique_ptr<KeysetHandle>> derived_handle =
      (*deriver)->DeriveKeyset(SaltFromRfc());
  ASSERT_THAT(derived_handle, IsOk());
  ASSERT_THAT((*derived_handle)->size(), Eq(derived_keys.size()));
  for (int i = 0; i < derived_keys.size(); i++) {
    EXPECT_THAT(*(**derived_handle)[i].GetKey(),
                Eq(std::ref(*derived_keys[i])));
  }
}

TEST_P(KeysetDeriverTest, PrfBasedDeriveKeysetWithGlobalRegistry) {
  std::vector<std::shared_ptr<Key>> derived_keys = GetParam();

  // Create KeysetDeriver KeysetHandle with the Parameters in `derived_keys`.

  // Proto serialization is required to convert the Parameters in `derived_keys`
  // to a KeyTemplate, which are used to create the KeysetDeriver KeysetHandle.
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesGcmProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterXChaCha20Poly1305ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      CreatePrfBasedDeriverHandle(derived_keys);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT((*handle)->size(), Eq(derived_keys.size()));

  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<internal::PrfBasedDeriverKeyManager>(), true),
      IsOk());
  // When key managers are in the global registry, PrfBasedDeriverKeyManager
  // uses them to derive keys instead of the non-global ParametersToKeyDeriver
  // map. We register here since GetPrimitive validates `handle` by deriving an
  // unused KeysetHandle, which requires use of the key managers.
  ASSERT_THAT(AeadConfig::Register(), IsOk());

  // Create primitive.
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*handle)->GetPrimitive<KeysetDeriver>(ConfigGlobalRegistry());
  ASSERT_THAT(deriver, IsOk());

  // Derive KeysetHandle using the global registry.
  util::StatusOr<std::unique_ptr<KeysetHandle>> derived_handle =
      (*deriver)->DeriveKeyset(SaltFromRfc());
  ASSERT_THAT(derived_handle, IsOk());
  ASSERT_THAT((*derived_handle)->size(), Eq(derived_keys.size()));
  for (int i = 0; i < derived_keys.size(); i++) {
    EXPECT_THAT(*(**derived_handle)[i].GetKey(),
                Eq(std::ref(*derived_keys[i])));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
