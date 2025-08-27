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

#include "tink/keyderivation/internal/key_derivers.h"

#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_eax_proto_serialization.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_proto_serialization.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/aes_siv_proto_serialization.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/ssl_util.h"
#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/hmac_proto_serialization.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_proto_serialization.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_proto_serialization.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/prf/hkdf_streaming_prf.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/subtle/random.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using KeyDeriversTest = TestWithParam<std::shared_ptr<Parameters>>;

std::unique_ptr<InputStream> Randomness() {
  std::unique_ptr<StreamingPrf> streaming_prf =
      subtle::HkdfStreamingPrf::New(
          subtle::HashType::SHA256,
          util::SecretDataFromStringView(subtle::Random::GetRandomBytes(48)),
          "salty")
          .value();
  return streaming_prf->ComputePrf("input");
}

INSTANTIATE_TEST_SUITE_P(
    KeyDeriversTests, KeyDeriversTest,
    ValuesIn(std::vector<std::shared_ptr<Parameters>>{
        // AEAD.
        std::make_unique<AesCtrHmacAeadParameters>(
            AesCtrHmacAeadParameters::Builder()
                .SetAesKeySizeInBytes(16)
                .SetHmacKeySizeInBytes(32)
                .SetIvSizeInBytes(16)
                .SetTagSizeInBytes(16)
                .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                .Build()
                .value()),
        std::make_unique<AesGcmParameters>(
            AesGcmParameters::Builder()
                .SetKeySizeInBytes(16)
                .SetIvSizeInBytes(12)
                .SetTagSizeInBytes(16)
                .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                .Build()
                .value()),
        std::make_unique<XChaCha20Poly1305Parameters>(
            XChaCha20Poly1305Parameters::Create(
                XChaCha20Poly1305Parameters::Variant::kNoPrefix)
                .value()),
        // Deterministic AEAD.
        std::make_unique<AesSivParameters>(
            AesSivParameters::Create(/*key_size_in_bytes=*/64,
                                     AesSivParameters::Variant::kNoPrefix)
                .value()),
        // MAC.
        std::make_unique<HmacParameters>(
            HmacParameters::Create(/*key_size_in_bytes=*/16,
                                   /*cryptographic_tag_size_in_bytes=*/10,
                                   HmacParameters::HashType::kSha256,
                                   HmacParameters::Variant::kNoPrefix)
                .value()),
        // PRF.
        std::make_unique<AesCmacPrfParameters>(
            AesCmacPrfParameters::Create(/*key_size_in_bytes=*/16).value()),
        std::make_unique<HkdfPrfParameters>(
            HkdfPrfParameters::Create(
                /*key_size_in_bytes=*/32, HkdfPrfParameters::HashType::kSha256,
                /*salt=*/test::HexDecodeOrDie("2025"))
                .value()),
        // Signature.
        std::make_unique<Ed25519Parameters>(
            Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix)
                .value()),
    }));

TEST_P(KeyDeriversTest, DeriveKey) {
  std::shared_ptr<Parameters> params = GetParam();
  absl::StatusOr<std::shared_ptr<Key>> key =
      DeriveKey(*params, Randomness().get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(std::ref(*params)));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(absl::nullopt));

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromKey(*key, KeyStatus::kEnabled,
                                                /*is_primary=*/true);
  EXPECT_THAT(KeysetHandleBuilder().AddEntry(std::move(entry)).Build(), IsOk());
}

TEST_P(KeyDeriversTest, InsufficientRandomness) {
  util::IstreamInputStream insufficient_randomness{
      absl::make_unique<std::stringstream>("0123456789")};
  absl::StatusOr<std::unique_ptr<Key>> key =
      DeriveKey(*GetParam().get(), &insufficient_randomness);
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kOutOfRange));
}

using KeyDeriversBoringSslTest = TestWithParam<std::shared_ptr<Parameters>>;

INSTANTIATE_TEST_SUITE_P(
    KeyDeriversBoringSslTests, KeyDeriversBoringSslTest,
    ValuesIn(std::vector<std::shared_ptr<Parameters>>{
        // Signature.
        std::make_unique<EcdsaParameters>(
            EcdsaParameters::Builder()
                .SetCurveType(EcdsaParameters::CurveType::kNistP256)
                .SetHashType(EcdsaParameters::HashType::kSha256)
                .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
                .SetVariant(EcdsaParameters::Variant::kNoPrefix)
                .Build()
                .value()),
    }));

TEST_P(KeyDeriversBoringSslTest, DeriveKey) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKey with seed used by Signature key derivation is "
                    "not supported by OpenSSL";
  }

  std::shared_ptr<Parameters> params = GetParam();
  absl::StatusOr<std::shared_ptr<Key>> key =
      DeriveKey(*params, Randomness().get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(std::ref(*params)));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(absl::nullopt));

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromKey(*key, KeyStatus::kEnabled,
                                                /*is_primary=*/true);
  EXPECT_THAT(KeysetHandleBuilder().AddEntry(std::move(entry)).Build(), IsOk());
}

TEST(MissingKeyDeriversTest, MissingKeyDeriver) {
  ASSERT_THAT(RegisterAesEaxProtoSerialization(), IsOk());
  absl::StatusOr<AesEaxParameters> params =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(DeriveKey(*params, Randomness().get()).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

// Test vector from https://tools.ietf.org/html/rfc5869#appendix-A.2.
class KeyDeriversRfcVectorTest : public Test {
 public:
  void SetUp() override {
    Registry::Reset();
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    absl::make_unique<HkdfPrfKeyManager>(), true),
                IsOk());

    google::crypto::tink::HkdfPrfKey prf_key;
    prf_key.set_version(0);
    prf_key.mutable_params()->set_hash(google::crypto::tink::HashType::SHA256);
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
    google::crypto::tink::KeyData key_data =
        test::AsKeyData(prf_key, google::crypto::tink::KeyData::SYMMETRIC);

    absl::StatusOr<std::unique_ptr<StreamingPrf>> streaming_prf =
        Registry::GetPrimitive<StreamingPrf>(key_data);
    ASSERT_THAT(streaming_prf, IsOk());
    absl::StatusOr<std::unique_ptr<StreamingPrf>> same_streaming_prf =
        Registry::GetPrimitive<StreamingPrf>(key_data);
    ASSERT_THAT(same_streaming_prf, IsOk());

    std::string salt = test::HexDecodeOrDie(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    randomness_from_rfc_vector_ = (*streaming_prf)->ComputePrf(salt);
    same_randomness_from_rfc_vector_ = (*same_streaming_prf)->ComputePrf(salt);
  }

  std::unique_ptr<InputStream> randomness_from_rfc_vector_;
  std::unique_ptr<InputStream> same_randomness_from_rfc_vector_;
  // The 82 bytes of the output key material (OKM).
  std::string derived_key_value_ =
      "b11e398dc80327a1c8e7f78c596a4934"
      "4f012eda2d4efad8a050cc4c19afa97c"
      "59045a99cac7827271cb41c65e590e09"
      "da3275600c2f09b8367793a9aca3db71"
      "cc30c58179ec3e87c14c01d5c1f3434f"
      "1d87";
};

TEST_F(KeyDeriversRfcVectorTest, AesCtrHmac) {
  // Derive key with Parameters map.
  absl::StatusOr<AesCtrHmacAeadParameters> params =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const AesCtrHmacAeadKey* key =
      dynamic_cast<const AesCtrHmacAeadKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string expected_aes_key_bytes =
      derived_key_value_.substr(0, 2 * params->GetAesKeySizeInBytes());
  std::string expected_hmac_key_bytes = derived_key_value_.substr(
      2 * params->GetAesKeySizeInBytes(), 2 * params->GetHmacKeySizeInBytes());
  ASSERT_THAT(test::HexEncode(key->GetAesKeyBytes(GetPartialKeyAccess())
                                  .GetSecret(InsecureSecretKeyAccess::Get())),
              Eq(expected_aes_key_bytes));
  ASSERT_THAT(test::HexEncode(key->GetHmacKeyBytes(GetPartialKeyAccess())
                                  .GetSecret(InsecureSecretKeyAccess::Get())),
              Eq(expected_hmac_key_bytes));

  // Derive key with AesCtrHmacAeadKeyManager.
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::AesCtrHmacAeadKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::AesCtrHmacAeadKey> proto_key =
      AesCtrHmacAeadKeyManager().DeriveKey(
          key_format, same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->aes_ctr_key().key_value()),
              Eq(expected_aes_key_bytes));
  EXPECT_THAT(test::HexEncode(proto_key->hmac_key().key_value()),
              Eq(expected_hmac_key_bytes));
}

TEST_F(KeyDeriversRfcVectorTest, AesGcm) {
  // Derive key with hard-coded map.
  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const AesGcmKey* key =
      dynamic_cast<const AesGcmKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_bytes =
      test::HexEncode(key->GetKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(key_bytes,
              Eq(derived_key_value_.substr(0, 2 * params->KeySizeInBytes())));

  // Derive key with AesGcmKeyManager.
  ASSERT_THAT(RegisterAesGcmProtoSerialization(), IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::AesGcmKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::AesGcmKey> proto_key =
      AesGcmKeyManager().DeriveKey(key_format,
                                   same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_bytes));
}

TEST_F(KeyDeriversRfcVectorTest, XChaCha20Poly1305) {
  // Derive key with hard-coded map.
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const XChaCha20Poly1305Key* key =
      dynamic_cast<const XChaCha20Poly1305Key*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_bytes =
      test::HexEncode(key->GetKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(key_bytes, Eq(derived_key_value_.substr(0, 2 * 32)));

  // Derive key with XChaCha20Poly1305KeyManager.
  ASSERT_THAT(RegisterXChaCha20Poly1305ProtoSerialization(), IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::XChaCha20Poly1305KeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::XChaCha20Poly1305Key> proto_key =
      XChaCha20Poly1305KeyManager().DeriveKey(
          key_format, same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_bytes));
}

TEST_F(KeyDeriversRfcVectorTest, AesSiv) {
  // Derive key with hard-coded map.
  absl::StatusOr<AesSivParameters> params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const AesSivKey* key =
      dynamic_cast<const AesSivKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_bytes =
      test::HexEncode(key->GetKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(key_bytes,
              Eq(derived_key_value_.substr(0, 2 * params->KeySizeInBytes())));

  // Derive key with AesSivKeyManager.
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::AesSivKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::AesSivKey> proto_key =
      AesSivKeyManager().DeriveKey(key_format,
                                   same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_bytes));
}

TEST_F(KeyDeriversRfcVectorTest, Hmac) {
  // Derive key with hard-coded map.
  absl::StatusOr<HmacParameters> params = HmacParameters::Create(
      /*key_size_in_bytes=*/16, /*cryptographic_tag_size_in_bytes=*/10,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const HmacKey* key = dynamic_cast<const HmacKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_bytes =
      test::HexEncode(key->GetKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(key_bytes,
              Eq(derived_key_value_.substr(0, 2 * params->KeySizeInBytes())));

  // Derive key with HmacKeyManager.
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::HmacKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::HmacKey> proto_key =
      HmacKeyManager().DeriveKey(key_format,
                                 same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_bytes));
}

TEST_F(KeyDeriversRfcVectorTest, AesCmacPrf) {
  // Derive key with hard-coded map.
  absl::StatusOr<AesCmacPrfParameters> params = AesCmacPrfParameters::Create(
      /*key_size_in_bytes=*/32);
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const AesCmacPrfKey* key =
      dynamic_cast<const AesCmacPrfKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_bytes =
      test::HexEncode(key->GetKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(key_bytes,
              Eq(derived_key_value_.substr(0, 2 * params->KeySizeInBytes())));

  // Derive key with AesCmacPrfKeyManager.
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::AesCmacPrfKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::AesCmacPrfKey> proto_key =
      AesCmacPrfKeyManager().DeriveKey(key_format,
                                       same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_bytes));
}

TEST_F(KeyDeriversRfcVectorTest, HkdfPrf) {
  // Derive key with hard-coded map.
  absl::StatusOr<HkdfPrfParameters> params = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/32, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/test::HexDecodeOrDie("2025"));
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const HkdfPrfKey* key =
      dynamic_cast<const HkdfPrfKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_bytes =
      test::HexEncode(key->GetKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(key_bytes,
              Eq(derived_key_value_.substr(0, 2 * params->KeySizeInBytes())));

  // Derive key with HkdfPrfKeyManager.
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::HkdfPrfKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::HkdfPrfKey> proto_key =
      HkdfPrfKeyManager().DeriveKey(key_format,
                                    same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_bytes));
}

TEST_F(KeyDeriversRfcVectorTest, Ecdsa) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKey with seed used by Signature key derivation is "
                    "not supported by OpenSSL";
  }

  // Derive key with hard-coded map.
  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const EcdsaPrivateKey* key =
      dynamic_cast<const EcdsaPrivateKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_value =
      test::HexEncode(key->GetPrivateKeyValue(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));

  // Derive key with EcdsaSignKeyManager.
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::EcdsaKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::EcdsaPrivateKey> proto_key =
      EcdsaSignKeyManager().DeriveKey(key_format,
                                      same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_value));
}

TEST_F(KeyDeriversRfcVectorTest, Ed25519) {
  // Derive key with hard-coded map.
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      DeriveKey(*params, randomness_from_rfc_vector_.get());
  ASSERT_THAT(generic_key, IsOk());
  const Ed25519PrivateKey* key =
      dynamic_cast<const Ed25519PrivateKey*>(&**std::move(generic_key));
  ASSERT_THAT(key, NotNull());
  std::string key_value =
      test::HexEncode(key->GetPrivateKeyBytes(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));

  // Derive key with Ed25519SignKeyManager.
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialization, IsOk());
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  google::crypto::tink::Ed25519KeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(
                  proto_serialization->GetKeyTemplateStruct().value),
              IsTrue());
  absl::StatusOr<google::crypto::tink::Ed25519PrivateKey> proto_key =
      Ed25519SignKeyManager().DeriveKey(key_format,
                                        same_randomness_from_rfc_vector_.get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT(test::HexEncode(proto_key->key_value()), Eq(key_value));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
