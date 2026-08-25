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
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
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
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateHpkeParams;
using ::crypto::tink::internal::CreateHpkePublicKey;
using ::crypto::tink::internal::CreateHpkeTestParams;
using ::crypto::tink::internal::DefaultHpkeTestParams;
using ::crypto::tink::internal::GetHpkeNistCurveTestCase;
using ::crypto::tink::internal::HpkeTestParams;
using ::crypto::tink::internal::P256PointAsString;
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
                            HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::ML_KEM768, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::ML_KEM1024, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_256_GCM)));

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

TEST(HpkeEncryptNewFromKeyObject, P384DoesNotWork) {
  EXPECT_THAT(HpkeEncrypt::New(
                  GetHpkeNistCurveTestCase(subtle::EllipticCurveType::NIST_P384)
                      .private_key->GetPublicKey()),
              Not(IsOk()));
}

TEST(HpkeEncryptNewFromKeyObject, P521DoesNotWork) {
  EXPECT_THAT(HpkeEncrypt::New(
                  GetHpkeNistCurveTestCase(subtle::EllipticCurveType::NIST_P521)
                      .private_key->GetPublicKey()),
              Not(IsOk()));
}

TEST(HpkeEncryptNewFromKeyObject, SHA384DoesNotWork) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  EXPECT_THAT(HpkeEncrypt::New(*public_key), Not(IsOk()));
}

TEST(HpkeEncryptNewFromKeyObject, SHA512DoesNotWork) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha512)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  EXPECT_THAT(HpkeEncrypt::New(*public_key), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
