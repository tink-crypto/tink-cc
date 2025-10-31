// Copyright 2017 Google LLC
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

#include "tink/aead/aead_config.h"

#include <list>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/key_gen_config_v0.h"
#include "tink/aead/kms_aead_key_manager.h"
#include "tink/aead/kms_envelope_aead_key_manager.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/aead/legacy_kms_envelope_aead_key.h"
#include "tink/aead/legacy_kms_envelope_aead_parameters.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/config/global_registry.h"
#include "tink/config/tink_fips.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/proto_parameters_format.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/chacha20_poly1305.pb.h"
#include "proto/kms_aead.pb.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"
#include "proto/x_aes_gcm.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::HasSubstr;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Test;

class AeadConfigTest : public Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(AeadConfigTest, RegisterWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(AeadConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the AeadWrapper has been properly registered and we can wrap
// primitives.
TEST_F(AeadConfigTest, WrappersRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keyset_handle.status(), IsOk());
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead.status(), IsOk());
  ASSERT_THAT(*aead, Not(IsNull()));
}

// FIPS-only mode tests
TEST_F(AeadConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  std::list<KeyTemplate> non_fips_key_templates = {
      AeadKeyTemplates::Aes128Eax(),
      AeadKeyTemplates::Aes256Eax(),
      AeadKeyTemplates::Aes128GcmSiv(),
      AeadKeyTemplates::Aes256GcmSiv(),
      AeadKeyTemplates::XChaCha20Poly1305(),
      AeadKeyTemplates::XAes256Gcm192BitNonce(),
      AeadKeyTemplates::XAes256Gcm160BitNonce(),
  };

  for (auto key_template : non_fips_key_templates) {
    auto new_keyset_handle_result =
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
    EXPECT_THAT(new_keyset_handle_result.status(),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST_F(AeadConfigTest, RegisterFipsValidTemplates) {
  if (!IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(AeadConfig::Register(), IsOk());

  std::list<KeyTemplate> fips_key_templates = {
      AeadKeyTemplates::Aes128Gcm(),
      AeadKeyTemplates::Aes256Gcm(),
      AeadKeyTemplates::Aes128CtrHmacSha256(),
      AeadKeyTemplates::Aes256CtrHmacSha256(),
  };

  for (auto key_template : fips_key_templates) {
    auto new_keyset_handle_result =
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
    EXPECT_THAT(new_keyset_handle_result, IsOk());
  }
}

TEST_F(AeadConfigTest, RegisterFailsIfBoringCryptoNotAvailable) {
  if (!IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Only supported in FIPS-only mode with BoringCrypto not available.";
  }

  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(AeadConfig::Register(), StatusIs(absl::StatusCode::kInternal));
}

TEST_F(AeadConfigTest, AesGcmProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              AeadKeyTemplates::Aes256Gcm());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kTink)
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(AeadConfigTest, AesGcmProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  google::crypto::tink::AesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(subtle::Random::GetRandomBytes(32));

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kTink)
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*params,
                        RestrictedData(subtle::Random::GetRandomBytes(32),
                                       InsecureSecretKeyAccess::Get()),
                        /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(AeadConfigTest, AesGcmSivProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              AeadKeyTemplates::Aes256GcmSiv());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesGcmSivParameters> params = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(AeadConfigTest, AesGcmSivProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  google::crypto::tink::AesGcmSivKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(subtle::Random::GetRandomBytes(32));

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesGcmSivParameters> params = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<AesGcmSivKey> key =
      AesGcmSivKey::Create(*params,
                           RestrictedData(subtle::Random::GetRandomBytes(32),
                                          InsecureSecretKeyAccess::Get()),
                           /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(AeadConfigTest, AesEaxProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              AeadKeyTemplates::Aes256Eax());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesEaxParameters> params =
      AesEaxParameters::Builder()
          .SetVariant(AesEaxParameters::Variant::kTink)
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(AeadConfigTest, AesEaxProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  google::crypto::tink::AesEaxKey key_proto;
  key_proto.set_version(0);
  key_proto.mutable_params()->set_iv_size(16);
  key_proto.set_key_value(subtle::Random::GetRandomBytes(32));

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesEaxKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesEaxParameters> params =
      AesEaxParameters::Builder()
          .SetVariant(AesEaxParameters::Variant::kTink)
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*params,
                        RestrictedData(subtle::Random::GetRandomBytes(32),
                                       InsecureSecretKeyAccess::Get()),
                        /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(AeadConfigTest, XChaCha20Poly1305ProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // TODO: b/347926425 - Rewrite tests using parameters proto format API.
  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              AeadKeyTemplates::XChaCha20Poly1305());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(AeadConfigTest, XChaCha20Poly1305ProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::XChaCha20Poly1305(),
                                KeyGenConfigAeadV0());
  ASSERT_THAT(handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  const internal::LegacyProtoKey* legacy_proto_key_from_handle =
      reinterpret_cast<const internal::LegacyProtoKey*>(
          (*handle)->GetPrimary().GetKey().get());
  EXPECT_THAT(legacy_proto_key_from_handle, Not(IsNull()));

  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kTink,
      RestrictedData(subtle::Random::GetRandomBytes(32),
                     InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Fails to serialize this key type.
  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  const XChaCha20Poly1305Key* key_from_handle =
      reinterpret_cast<const XChaCha20Poly1305Key*>(
          (*handle)->GetPrimary().GetKey().get());
  EXPECT_THAT(key_from_handle, Not(IsNull()));

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

TEST_F(AeadConfigTest, AesCtrHmacAeadProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // TODO: b/347926425 - Rewrite tests using parameters proto format API.
  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              AeadKeyTemplates::Aes256CtrHmacSha256());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesCtrHmacAeadParameters> params =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(AeadConfigTest, AesCtrHmacAeadProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes256CtrHmacSha256(),
                                KeyGenConfigAeadV0());
  ASSERT_THAT(handle, IsOk());

  // Failed to parse this key type, so fell back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*handle)->GetPrimary().GetKey().get()),
              Not(IsNull()));

  absl::StatusOr<AesCtrHmacAeadParameters> params =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*params)
          .SetAesKeyBytes(RestrictedData(subtle::Random::GetRandomBytes(32),
                                         InsecureSecretKeyAccess::Get()))
          .SetHmacKeyBytes(RestrictedData(subtle::Random::GetRandomBytes(32),
                                          InsecureSecretKeyAccess::Get()))
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Fails to serialize this key type.
  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle2 =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes256CtrHmacSha256(),
                                KeyGenConfigAeadV0());
  ASSERT_THAT(handle2, IsOk());

  // Parsing now creates the right key type.
  EXPECT_THAT(dynamic_cast<const AesCtrHmacAeadKey*>(
                  (*handle2)->GetPrimary().GetKey().get()),
              Not(IsNull()));

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

TEST_F(AeadConfigTest, ChaCha20Poly1305ProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);

  // TODO: b/347926425 - Rewrite tests using parameters proto format API.
  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(key_template);
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<ChaCha20Poly1305Parameters> params =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params)
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params),
      IsOk());
}

TEST_F(AeadConfigTest, ChaCha20Poly1305ProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  std::string key_bytes = subtle::Random::GetRandomBytes(32);
  google::crypto::tink::ChaCha20Poly1305Key key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(key_bytes);

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink,
      RestrictedData(key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

TEST_F(AeadConfigTest, XAesGcmProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // TODO: b/347926425 - Rewrite tests using parameters proto format API.
  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              AeadKeyTemplates::XAes256Gcm160BitNonce());
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, /*salt_size_bytes=*/12);
  ASSERT_THAT(params, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params)
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params),
      IsOk());
}

TEST_F(AeadConfigTest, XAesGcmProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  std::string key_bytes = subtle::Random::GetRandomBytes(32);
  google::crypto::tink::XAesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.mutable_params()->set_salt_size(12);
  key_proto.set_key_value(key_bytes);

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.XAesGcmKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, /*salt_size_bytes=*/12);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *params, RestrictedData(key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

TEST_F(AeadConfigTest, KmsAeadProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  google::crypto::tink::KmsAeadKeyFormat key_format;
  key_format.set_key_uri("key_uri");
  key_format.SerializeToString(key_template.mutable_value());

  absl::StatusOr<std::unique_ptr<Parameters>> proto_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(proto_parameters, IsOk());
  EXPECT_THAT(
      dynamic_cast<internal::LegacyProtoParameters*>(proto_parameters->get()),
      NotNull());

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create("key_uri",
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(SerializeParametersToProtoFormat(*parameters),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT(dynamic_cast<LegacyKmsAeadParameters*>(parsed_parameters->get()),
              NotNull());

  EXPECT_THAT(SerializeParametersToProtoFormat(*parameters), IsOk());
}

TEST_F(AeadConfigTest, KmsAeadProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  google::crypto::tink::KmsAeadKeyFormat key_format;
  key_format.set_key_uri("key_uri");
  key_format.SerializeToString(key_template.mutable_value());

  // NOTE: `KeyGenConfigAeadV0` does not support `KmsAeadKey`.
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<KmsAeadKeyManager>(), true),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*handle)->GetPrimary().GetKey().get()),
              NotNull());

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create("key_uri",
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());

  // Fails to serialize this key type.
  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle2 =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle2, IsOk());

  EXPECT_THAT(dynamic_cast<const LegacyKmsAeadKey*>(
                  (*handle2)->GetPrimary().GetKey().get()),
              NotNull());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

KeyTemplate GetXChaCha20Poly1305KeyTemplate() {
  google::crypto::tink::XChaCha20Poly1305KeyFormat key_format;
  key_format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

XChaCha20Poly1305Parameters GetXChaCha20Poly1305Parameters() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(parameters);
  return *parameters;
}

TEST_F(AeadConfigTest, KmsEnvelopeAeadProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  google::crypto::tink::KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri("kek_uri");
  *key_format.mutable_dek_template() = GetXChaCha20Poly1305KeyTemplate();
  key_format.SerializeToString(key_template.mutable_value());

  absl::StatusOr<std::unique_ptr<Parameters>> proto_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(proto_parameters, IsOk());
  EXPECT_THAT(
      dynamic_cast<internal::LegacyProtoParameters*>(proto_parameters->get()),
      NotNull());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          "kek_uri", LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          GetXChaCha20Poly1305Parameters());
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(SerializeParametersToProtoFormat(*parameters),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT(
      dynamic_cast<LegacyKmsEnvelopeAeadParameters*>(parsed_parameters->get()),
      NotNull());

  EXPECT_THAT(SerializeParametersToProtoFormat(*parameters), IsOk());
}

TEST_F(AeadConfigTest, KmsEnvelopeAeadProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  google::crypto::tink::KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri("kek_uri");
  *key_format.mutable_dek_template() = GetXChaCha20Poly1305KeyTemplate();
  key_format.SerializeToString(key_template.mutable_value());

  // NOTE: `KeyGenConfigAeadV0` does not support `KmsEnvelopeAeadKey`.
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<KmsEnvelopeAeadKeyManager>(), true),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*handle)->GetPrimary().GetKey().get()),
              NotNull());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          "kek_uri", LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          GetXChaCha20Poly1305Parameters());
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());

  // Fails to serialize this key type.
  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle2 =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle2, IsOk());

  EXPECT_THAT(dynamic_cast<const LegacyKmsEnvelopeAeadKey*>(
                  (*handle2)->GetPrimary().GetKey().get()),
              NotNull());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
