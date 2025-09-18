// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/internal/hpke_encrypt.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/hpke_decrypt.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/partial_key_access.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::CreateHpkeParams;
using ::crypto::tink::internal::CreateHpkePublicKey;
using ::crypto::tink::internal::CreateHpkeTestParams;
using ::crypto::tink::internal::DefaultHpkeTestParams;
using ::crypto::tink::internal::HpkeTestParams;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using HpkePublicKeyProto = ::google::crypto::tink::HpkePublicKey;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::Values;

constexpr int kTagLength = 16;  // Tag length (in bytes) for GCM and Poly1305.

class HpkeEncryptTest : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeEncryptionTestSuite, HpkeEncryptTest,
    Values(CreateHpkeParams(HpkeKem::DHKEM_P256_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_P256_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_256_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_P256_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY1305),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_256_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY1305),
           CreateHpkeParams(HpkeKem::X_WING, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_128_GCM)));

TEST_P(HpkeEncryptTest, SetupSenderContextAndEncrypt) {
  HpkeParams hpke_params = GetParam();
  absl::StatusOr<uint32_t> encapsulated_key_length =
      internal::HpkeEncapsulatedKeyLength(hpke_params.kem());
  ASSERT_THAT(encapsulated_key_length, IsOk());

  absl::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params, IsOk());
  HpkePublicKeyProto recipient_key =
      CreateHpkePublicKey(hpke_params, params->recipient_public_key);
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);
  ASSERT_THAT(hpke_encrypt, IsOk());

  std::vector<std::string> plaintexts = {"", params->plaintext};
  std::vector<std::string> context_infos = {"", params->application_info};
  for (const std::string& plaintext : plaintexts) {
    for (const std::string& context_info : context_infos) {
      SCOPED_TRACE(absl::StrCat("plaintext: '", plaintext, "', context_info: '",
                                context_info, "'"));
      int expected_ciphertext_length =
          *encapsulated_key_length + plaintext.size() + kTagLength;
      absl::StatusOr<std::string> encryption_result =
          (*hpke_encrypt)->Encrypt(plaintext, context_info);
      EXPECT_THAT(encryption_result,
                  IsOkAndHolds(SizeIs(expected_ciphertext_length)));
    }
  }
}

class HpkeEncryptWithBadParamTest : public testing::TestWithParam<HpkeParams> {
};

INSTANTIATE_TEST_SUITE_P(
    HpkeEncryptionWithBadParamTestSuite, HpkeEncryptWithBadParamTest,
    Values(CreateHpkeParams(HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::KDF_UNKNOWN, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AEAD_UNKNOWN),
           CreateHpkeParams(HpkeKem::DHKEM_P384_HKDF_SHA384,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA384, HpkeAead::AES_128_GCM)));

TEST_P(HpkeEncryptWithBadParamTest, BadParamFails) {
  HpkeParams hpke_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePublicKeyProto recipient_key =
      CreateHpkePublicKey(hpke_params, params.recipient_public_key);
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);
  ASSERT_THAT(hpke_encrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeEncryptWithZeroLengthPublicKey, ZeroLengthPublicKeyFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePublicKeyProto recipient_key =
      CreateHpkePublicKey(hpke_params, /*raw_key_bytes=*/"");

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);

  EXPECT_THAT(hpke_encrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

using HpkeEncryptTestVectorTest =
    testing::TestWithParam<HybridTestVector>;

TEST_P(HpkeEncryptTestVectorTest, EncryptWorks) {
  const HybridTestVector& param = GetParam();
  const HpkePrivateKey* hpke_key =
      dynamic_cast<HpkePrivateKey*>(param.hybrid_private_key.get());
  ASSERT_THAT(hpke_key, testing::NotNull());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      HpkeDecrypt::New(*hpke_key);
  ASSERT_THAT(decrypter, IsOk());
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypter =
      HpkeEncrypt::New(hpke_key->GetPublicKey());
  ASSERT_THAT(encrypter, IsOk());
  absl::StatusOr<std::string> ciphertext =
      (*encrypter)->Encrypt(param.plaintext, param.context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*decrypter)->Decrypt(*ciphertext, param.context_info),
              IsOkAndHolds(Eq(param.plaintext)));
}

INSTANTIATE_TEST_SUITE_P(HpkeEncryptTestVectorTest, HpkeEncryptTestVectorTest,
                         testing::ValuesIn(CreateHpkeTestVectors()));

std::string P384PointAsString() {
  std::string pub_key_x_p384_hex =
      "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA"
      "9055866064A254515480BC13";
  std::string pub_key_y_p384_hex =
      "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C"
      "3AE0D4FE7344FD2533264720";
  return test::HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p384_hex, pub_key_y_p384_hex));
}

TEST(HpkeDecryptNewFromKeyObject, P384DoesNotWork) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP384HkdfSha384)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P384PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(HpkeEncrypt::New(*public_key), Not(IsOk()));
}

// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
std::string P521PointAsString() {
  std::string pub_key_x_p521_hex =
      "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D4"
      "6E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4";
  std::string pub_key_y_p521_hex =
      "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25"
      "741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5";
  return HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p521_hex, pub_key_y_p521_hex));
}

TEST(HpkeDecryptNewFromKeyObject, P521DoesNotWork) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP521HkdfSha512)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P521PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(HpkeEncrypt::New(*public_key), Not(IsOk()));
}

// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
std::string P256PointAsString() {
  std::string pub_key_x_p256_hex =
      "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
  std::string pub_key_y_p256_hex =
      "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
  return HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p256_hex, pub_key_y_p256_hex));
}

TEST(HpkeDecryptNewFromKeyObject, SHA384DoesNotWork) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  EXPECT_THAT(HpkeEncrypt::New(*public_key), Not(IsOk()));
}

TEST(HpkeDecryptNewFromKeyObject, SHA512DoesNotWork) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha512)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  EXPECT_THAT(HpkeEncrypt::New(*public_key), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
