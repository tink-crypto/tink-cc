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
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_proto_serialization.h"
#include "tink/big_integer.h"
#include "tink/config/global_registry.h"
#include "tink/config/tink_config.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/aes_siv_proto_serialization.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/ssl_util.h"
#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/keyderivation/keyset_deriver_wrapper.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/keyderivation/prf_based_key_derivation_proto_serialization.h"
#include "tink/keyset_handle.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/hmac_proto_serialization.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hkdf_prf_proto_serialization.h"
#include "tink/registry.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_proto_serialization.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_proto_serialization.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

// The 82 bytes of the output key material (OKM) from the HKDF RFC
// https://tools.ietf.org/html/rfc5869#appendix-A.2.
static constexpr absl::string_view kOkmFromRfc =
    "b11e398dc80327a1c8e7f78c596a4934"
    "4f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09"
    "da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f"
    "1d87";

HkdfPrfKey PrfKeyFromRfc() {
  HkdfPrfParameters params =
      HkdfPrfParameters::Create(
          80, HkdfPrfParameters::HashType::kSha256, /*salt=*/
          test::HexDecodeOrDie("606162636465666768696a6b6c6d6e6f"
                               "707172737475767778797a7b7c7d7e7f"
                               "808182838485868788898a8b8c8d8e8f"
                               "909192939495969798999a9b9c9d9e9f"
                               "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
          .value();
  return HkdfPrfKey::Create(
             params,
             RestrictedData(
                 test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"
                                      "101112131415161718191a1b1c1d1e1f"
                                      "202122232425262728292a2b2c2d2e2f"
                                      "303132333435363738393a3b3c3d3e3f"
                                      "404142434445464748494a4b4c4d4e4f"),
                 InsecureSecretKeyAccess::Get()),
             GetPartialKeyAccess())
      .value();
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

std::unique_ptr<AesSivKey> CreateAesSivKey(int key_size,
                                           AesSivParameters::Variant variant,
                                           absl::string_view secret,
                                           absl::optional<int> id_requirement) {
  return std::make_unique<AesSivKey>(
      AesSivKey::Create(AesSivParameters::Create(key_size, variant).value(),
                        RestrictedData(test::HexDecodeOrDie(secret),
                                       InsecureSecretKeyAccess::Get()),
                        id_requirement, GetPartialKeyAccess())
          .value());
}

std::unique_ptr<Ed25519PrivateKey> CreateEd25519PrivateKey(
    Ed25519Parameters::Variant variant, absl::string_view secret_seed,
    absl::optional<int> id_requirement) {
  std::unique_ptr<internal::Ed25519Key> key_pair =
      internal::NewEd25519Key(
          util::SecretDataFromStringView(test::HexDecodeOrDie(secret_seed)))
          .value();
  Ed25519PublicKey public_key =
      Ed25519PublicKey::Create(Ed25519Parameters::Create(variant).value(),
                               key_pair->public_key, id_requirement,
                               GetPartialKeyAccess())
          .value();
  RestrictedData private_key_bytes =
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get());
  return absl::make_unique<Ed25519PrivateKey>(
      Ed25519PrivateKey::Create(public_key, private_key_bytes,
                                GetPartialKeyAccess())
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

std::unique_ptr<EcdsaPrivateKey> CreateEcdsaPrivateKey(
    crypto::tink::subtle::EllipticCurveType proto_curve_type,
    EcdsaParameters::CurveType curve_type, EcdsaParameters::HashType hash_type,
    EcdsaParameters::SignatureEncoding signature_encoding,
    EcdsaParameters::Variant variant, absl::string_view secret_seed,
    absl::optional<int> id_requirement) {
  internal::EcKey key_pair =
      internal::NewEcKey(
          proto_curve_type,
          util::SecretDataFromStringView(test::HexDecodeOrDie(secret_seed)))
          .value();
  EcPoint public_point(BigInteger(key_pair.pub_x), BigInteger(key_pair.pub_y));
  EcdsaPublicKey public_key =
      EcdsaPublicKey::Create(EcdsaParameters::Builder()
                                 .SetCurveType(curve_type)
                                 .SetHashType(hash_type)
                                 .SetSignatureEncoding(signature_encoding)
                                 .SetVariant(variant)
                                 .Build()
                                 .value(),
                             public_point, id_requirement,
                             GetPartialKeyAccess())
          .value();
  RestrictedBigInteger private_key_bytes =
      RestrictedBigInteger(util::SecretDataAsStringView(key_pair.priv),
                           InsecureSecretKeyAccess::Get());
  return std::make_unique<EcdsaPrivateKey>(
      EcdsaPrivateKey::Create(public_key, private_key_bytes,
                              GetPartialKeyAccess())
          .value());
}

std::unique_ptr<HkdfPrfKey> CreateHkdfPrfKey(
    int key_size_in_bytes, HkdfPrfParameters::HashType hash_type,
    absl::optional<absl::string_view> salt, absl::string_view secret) {
  HkdfPrfParameters params =
      HkdfPrfParameters::Create(key_size_in_bytes, hash_type, salt).value();
  return std::make_unique<HkdfPrfKey>(
      HkdfPrfKey::Create(params,
                         RestrictedData(test::HexDecodeOrDie(secret),
                                        InsecureSecretKeyAccess::Get()),
                         GetPartialKeyAccess())
          .value());
}

// TODO: b/314831964 - Add Variant:kLegacy test cases.
std::vector<std::shared_ptr<Key>> AeadTestVector() {
  return {
      CreateAesCtrHmacAeadKey(/*aes_key_size=*/16, /*tag_size=*/16,
                              AesCtrHmacAeadParameters::Variant::kTink,
                              /*aes_secret=*/kOkmFromRfc.substr(0, 32),
                              /*hmac_secret=*/kOkmFromRfc.substr(32, 64),
                              /*id_requirement=*/1010101),
      CreateAesCtrHmacAeadKey(/*aes_key_size=*/32, /*tag_size=*/32,
                              AesCtrHmacAeadParameters::Variant::kCrunchy,
                              /*aes_secret=*/kOkmFromRfc.substr(0, 64),
                              /*hmac_secret=*/kOkmFromRfc.substr(64, 64),
                              /*id_requirement=*/2020202),
      CreateAesCtrHmacAeadKey(/*aes_key_size=*/16, /*tag_size=*/16,
                              AesCtrHmacAeadParameters::Variant::kTink,
                              /*aes_secret=*/kOkmFromRfc.substr(0, 32),
                              /*hmac_secret=*/kOkmFromRfc.substr(32, 64),
                              /*id_requirement=*/3030303),
      CreateAesGcmKey(/*key_size=*/16, AesGcmParameters::Variant::kCrunchy,
                      kOkmFromRfc.substr(0, 32), /*id_requirement=*/4040404),
      CreateAesGcmKey(/*key_size=*/32, AesGcmParameters::Variant::kTink,
                      kOkmFromRfc.substr(0, 64), /*id_requirement=*/5050505),
      CreateAesGcmKey(/*key_size=*/16, AesGcmParameters::Variant::kNoPrefix,
                      kOkmFromRfc.substr(0, 32),
                      /*id_requirement=*/absl::nullopt),
      CreateXChaCha20Poly1305Key(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix,
          kOkmFromRfc.substr(0, 64),
          /*id_requirement=*/absl::nullopt),
      CreateXChaCha20Poly1305Key(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix,
          kOkmFromRfc.substr(0, 64),
          /*id_requirement=*/absl::nullopt),
      CreateXChaCha20Poly1305Key(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix,
          kOkmFromRfc.substr(0, 64), /*id_requirement=*/absl::nullopt),
  };
}

std::vector<std::shared_ptr<Key>> DaeadTestVector() {
  return {
      CreateAesSivKey(/*key_size=*/32, AesSivParameters::Variant::kTink,
                      kOkmFromRfc.substr(0, 64), /*id_requirement=*/1010101),
      CreateAesSivKey(/*key_size=*/48, AesSivParameters::Variant::kCrunchy,
                      kOkmFromRfc.substr(0, 96), /*id_requirement=*/2020202),
      CreateAesSivKey(/*key_size=*/64, AesSivParameters::Variant::kNoPrefix,
                      kOkmFromRfc.substr(0, 128),
                      /*id_requirement=*/absl::nullopt),
  };
}

std::vector<std::shared_ptr<Key>> Ed25519TestVector() {
  return {
      CreateEd25519PrivateKey(Ed25519Parameters::Variant::kTink,
                              kOkmFromRfc.substr(0, 64),
                              /*id_requirement=*/1010101),
      CreateEd25519PrivateKey(Ed25519Parameters::Variant::kCrunchy,
                              kOkmFromRfc.substr(0, 64),
                              /*id_requirement=*/2020202),
      CreateEd25519PrivateKey(Ed25519Parameters::Variant::kLegacy,
                              kOkmFromRfc.substr(0, 64),
                              /*id_requirement=*/3030303),
      CreateEd25519PrivateKey(Ed25519Parameters::Variant::kNoPrefix,
                              kOkmFromRfc.substr(0, 64),
                              /*id_requirement=*/absl::nullopt),
  };
}

std::vector<std::shared_ptr<Key>> MacTestVector() {
  return {
      CreateHmacKey(/*key_size=*/16, /*cryptographic_tag_size=*/10,
                    HmacParameters::HashType::kSha256,
                    HmacParameters::Variant::kTink, kOkmFromRfc.substr(0, 32),
                    /*id_requirement=*/1010101),
      CreateHmacKey(/*key_size=*/24, /*cryptographic_tag_size=*/16,
                    HmacParameters::HashType::kSha384,
                    HmacParameters::Variant::kCrunchy,
                    kOkmFromRfc.substr(0, 48), /*id_requirement=*/2020202),
      CreateHmacKey(
          /*key_size=*/32, /*cryptographic_tag_size=*/32,
          HmacParameters::HashType::kSha512, HmacParameters::Variant::kNoPrefix,
          kOkmFromRfc.substr(0, 64), /*id_requirement=*/absl::nullopt),
  };
}

std::vector<std::shared_ptr<Key>> EcdsaTestVector() {
  return {
      CreateEcdsaPrivateKey(subtle::EllipticCurveType::NIST_P256,
                            EcdsaParameters::CurveType::kNistP256,
                            EcdsaParameters::HashType::kSha256,
                            EcdsaParameters::SignatureEncoding::kDer,
                            EcdsaParameters::Variant::kTink,
                            kOkmFromRfc.substr(0, 32),
                            /*id_requirement=*/1010101),
      CreateEcdsaPrivateKey(subtle::EllipticCurveType::NIST_P384,
                            EcdsaParameters::CurveType::kNistP384,
                            EcdsaParameters::HashType::kSha384,
                            EcdsaParameters::SignatureEncoding::kDer,
                            EcdsaParameters::Variant::kCrunchy,
                            kOkmFromRfc.substr(0, 48),
                            /*id_requirement=*/2020202),
      CreateEcdsaPrivateKey(subtle::EllipticCurveType::NIST_P384,
                            EcdsaParameters::CurveType::kNistP384,
                            EcdsaParameters::HashType::kSha384,
                            EcdsaParameters::SignatureEncoding::kIeeeP1363,
                            EcdsaParameters::Variant::kLegacy,
                            kOkmFromRfc.substr(0, 48),
                            /*id_requirement=*/3030303),
      CreateEcdsaPrivateKey(subtle::EllipticCurveType::NIST_P521,
                            EcdsaParameters::CurveType::kNistP521,
                            EcdsaParameters::HashType::kSha512,
                            EcdsaParameters::SignatureEncoding::kIeeeP1363,
                            EcdsaParameters::Variant::kNoPrefix,
                            kOkmFromRfc.substr(0, 64),
                            /*id_requirement=*/absl::nullopt),
  };
}

std::vector<std::shared_ptr<Key>> PrfTestVector() {
  return {
      CreateHkdfPrfKey(
          /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha1,
          /*salt=*/test::HexDecodeOrDie("de"), kOkmFromRfc.substr(0, 32)),
      CreateHkdfPrfKey(/*key_size_in_bytes=*/16,
                       HkdfPrfParameters::HashType::kSha224,
                       /*salt=*/absl::nullopt, kOkmFromRfc.substr(0, 32)),
      CreateHkdfPrfKey(
          /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
          /*salt=*/test::HexDecodeOrDie("ad"), kOkmFromRfc.substr(0, 32)),
      CreateHkdfPrfKey(/*key_size_in_bytes=*/32,
                       HkdfPrfParameters::HashType::kSha384,
                       /*salt=*/absl::nullopt, kOkmFromRfc.substr(0, 64)),
      CreateHkdfPrfKey(
          /*key_size_in_bytes=*/32, HkdfPrfParameters::HashType::kSha512,
          /*salt=*/test::HexDecodeOrDie("beef"), kOkmFromRfc.substr(0, 64)),
  };
}

std::vector<std::vector<std::shared_ptr<Key>>> TestVectors() {
  std::vector<std::vector<std::shared_ptr<Key>>> vectors;
  vectors.push_back(AeadTestVector());
  vectors.push_back(DaeadTestVector());
  vectors.push_back(Ed25519TestVector());
  vectors.push_back(MacTestVector());
  vectors.push_back(PrfTestVector());

  // Deriving EC keys with secret seed is not implemented in OpenSSL.
  if (internal::IsBoringSsl()) {
    vectors.push_back(EcdsaTestVector());
  }

  return vectors;
}

absl::StatusOr<KeysetHandle> CreatePrfBasedDeriverHandle(
    std::vector<std::shared_ptr<Key>> derived_keys) {
  KeysetHandleBuilder builder;
  bool is_first_key = true;

  for (const auto& derived_key : derived_keys) {
    absl::StatusOr<PrfBasedKeyDerivationParameters> params =
        PrfBasedKeyDerivationParameters::Builder()
            .SetPrfParameters(PrfKeyFromRfc().GetParameters())
            .SetDerivedKeyParameters(derived_key->GetParameters())
            .Build();
    if (!params.ok()) {
      return params.status();
    }
    absl::StatusOr<PrfBasedKeyDerivationKey> key =
        PrfBasedKeyDerivationKey::Create(*params, PrfKeyFromRfc(),
                                         derived_key->GetIdRequirement(),
                                         GetPartialKeyAccess());
    if (!key.ok()) {
      return key.status();
    }
    builder.AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
        *key, KeyStatus::kEnabled, /*is_primary=*/is_first_key));
    is_first_key = false;
  }
  return builder.Build();
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
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());

  // Create KeysetDeriver KeysetHandle with the Parameters in `derived_keys`.
  std::vector<std::shared_ptr<Key>> derived_keys = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      CreatePrfBasedDeriverHandle(derived_keys);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT((*handle).size(), Eq(derived_keys.size()));

  // TODO(b/314831964): Remove once KeysetDeriver does not depend on the global
  // registry.
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<internal::PrfBasedDeriverKeyManager>(), true),
      IsOk());

  // Registering here as KeysetDeriver primitive creation verifies the derived
  // key parameters by attempting to derive a key.
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesGcmProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterXChaCha20Poly1305ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  // Create primitive.
  absl::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*handle).GetPrimitive<KeysetDeriver>(ConfigGlobalRegistry());
  ASSERT_THAT(deriver, IsOk());

  // Ensure key derivation does not use the global registry.
  Registry::Reset();

  // Derive KeysetHandle using the local ParametersToKeyDeriver map.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> derived_handle =
      (*deriver)->DeriveKeyset(SaltFromRfc());
  ASSERT_THAT(derived_handle, IsOk());
  ASSERT_THAT((*derived_handle)->size(), Eq(derived_keys.size()));
  for (int i = 0; i < derived_keys.size(); i++) {
    EXPECT_THAT(*(**derived_handle)[i].GetKey(),
                Eq(std::ref(*derived_keys[i])));
  }
}

TEST_P(KeysetDeriverTest, PrfBasedDeriveKeysetWithGlobalRegistry) {
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());

  // Create KeysetDeriver KeysetHandle with the Parameters in `derived_keys`.
  std::vector<std::shared_ptr<Key>> derived_keys = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      CreatePrfBasedDeriverHandle(derived_keys);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT((*handle).size(), Eq(derived_keys.size()));

  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<KeysetDeriverWrapper>()),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<internal::PrfBasedDeriverKeyManager>(), true),
      IsOk());

  // When the derived keys' key managers are in the global registry,
  // PrfBasedDeriverKeyManager uses them to derive keys instead of the
  // local ParametersToKeyDeriver map.
  //
  // Registering here as KeysetDeriver primitive creation verifies the derived
  // key parameters by attempting to derive a key.
  ASSERT_THAT(TinkConfig::Register(), IsOk());

  // Create primitive.
  absl::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*handle).GetPrimitive<KeysetDeriver>(ConfigGlobalRegistry());
  ASSERT_THAT(deriver, IsOk());

  // Derive KeysetHandle using the global registry.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> derived_handle =
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
