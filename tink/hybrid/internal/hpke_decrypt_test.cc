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

#include "tink/hybrid/internal/hpke_decrypt.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/hpke_encrypt.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/partial_key_access.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateHpkeParams;
using ::crypto::tink::internal::CreateHpkePrivateKey;
using ::crypto::tink::internal::CreateHpkePublicKey;
using ::crypto::tink::internal::CreateHpkeTestParams;
using ::crypto::tink::internal::DefaultHpkeTestParams;
using ::crypto::tink::internal::GetHpkeNistCurveTestCase;
using ::crypto::tink::internal::HpkeTestParams;
using ::crypto::tink::internal::P256PointAsString;
using ::crypto::tink::internal::P256SecretValue;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::util::SecretDataFromStringView;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Values;
using HpkePrivateKeyProto = ::google::crypto::tink::HpkePrivateKey;
using HpkePublicKeyProto = ::google::crypto::tink::HpkePublicKey;

// Encrypts plaintext using HPKE for the given params and recipient public key.
absl::StatusOr<std::string> Encrypt(HpkeParams params,
                                    absl::string_view recipient_public_key,
                                    absl::string_view plaintext,
                                    absl::string_view context_info) {
  HpkePublicKeyProto recipient_key =
      CreateHpkePublicKey(params, std::string(recipient_public_key));
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);
  if (!hpke_encrypt.ok()) {
    return hpke_encrypt.status();
  }
  return (*hpke_encrypt)->Encrypt(plaintext, context_info);
}

class HpkeDecryptTest : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeDecryptionTestSuite, HpkeDecryptTest,
    Values(CreateHpkeParams(HpkeKem::DHKEM_P256_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_P256_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY1305),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY1305),
           CreateHpkeParams(HpkeKem::X_WING, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::ML_KEM768, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::ML_KEM1024, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_256_GCM)));

TEST_P(HpkeDecryptTest, SetupRecipientContextAndDecrypt) {
  HpkeParams hpke_params = GetParam();
  absl::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params, IsOk());
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(hpke_params, params->recipient_private_key);
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt, IsOk());

  std::vector<std::string> inputs = {"", params->plaintext};
  std::vector<std::string> context_infos = {"", params->application_info};
  for (const std::string& input : inputs) {
    for (const std::string& context_info : context_infos) {
      SCOPED_TRACE(absl::StrCat("input: '", input, "', context_info: '",
                                context_info, "'"));
      absl::StatusOr<std::string> ciphertext = Encrypt(
          hpke_params, params->recipient_public_key, input, context_info);
      ASSERT_THAT(ciphertext, IsOk());
      absl::StatusOr<std::string> plaintext =
          (*hpke_decrypt)->Decrypt(*ciphertext, context_info);
      EXPECT_THAT(plaintext, IsOkAndHolds(input));
    }
  }
}

class HpkeDecryptWithBadParamTest : public testing::TestWithParam<HpkeParams> {
};

INSTANTIATE_TEST_SUITE_P(
    HpkeDecryptionWithBadParamTestSuite, HpkeDecryptWithBadParamTest,
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

TEST_P(HpkeDecryptWithBadParamTest, BadParamsFails) {
  HpkeParams bad_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(bad_params, params.recipient_private_key);
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithShortCiphertextTest, ShortCiphertextFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt, IsOk());

  absl::StatusOr<std::string> plaintext =
      (*hpke_decrypt)->Decrypt("short ciphertext", "associated data");

  EXPECT_THAT(plaintext.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithBadCiphertextTest, BadCiphertextFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt, IsOk());
  absl::StatusOr<std::string> ciphertext =
      Encrypt(hpke_params, params.recipient_public_key, params.plaintext,
              params.application_info);
  ASSERT_THAT(ciphertext, IsOk());

  absl::StatusOr<std::string> plaintext =
      (*hpke_decrypt)
          ->Decrypt(absl::StrCat(*ciphertext, "modified ciphertext"),
                    params.application_info);

  EXPECT_THAT(plaintext.status(), StatusIs(absl::StatusCode::kUnknown));
}

TEST(HpkeDecryptWithBadAssociatedDataTest, BadAssociatedDataFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt, IsOk());
  absl::StatusOr<std::string> ciphertext =
      Encrypt(hpke_params, params.recipient_public_key, params.plaintext,
              params.application_info);
  ASSERT_THAT(ciphertext, IsOk());

  absl::StatusOr<std::string> plaintext =
      (*hpke_decrypt)
          ->Decrypt(*ciphertext,
                    absl::StrCat(params.application_info, "modified aad"));

  EXPECT_THAT(plaintext.status(), StatusIs(absl::StatusCode::kUnknown));
}

TEST(HpkeDecryptWithMissingPublicKeyTest, MissingPublicKeyFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  recipient_key.clear_public_key();

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);

  EXPECT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithMissingHpkeParamsTest, MissingHpkeParamsFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  recipient_key.mutable_public_key()->clear_params();

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);

  EXPECT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithZeroLengthPrivateKeyTest, ZeroLengthPrivateKeyFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKeyProto recipient_key =
      CreateHpkePrivateKey(hpke_params, /*raw_key_bytes=*/"");

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);

  EXPECT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

using HpkeDecryptTestVectorTest =
    testing::TestWithParam<internal::HybridTestVector>;

TEST_P(HpkeDecryptTestVectorTest, DecryptWorks) {
  const internal::HybridTestVector& param = GetParam();
  const HpkePrivateKey* hpke_key =
      dynamic_cast<HpkePrivateKey*>(param.hybrid_private_key.get());
  ASSERT_THAT(hpke_key, NotNull());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      HpkeDecrypt::New(*hpke_key);
  ASSERT_THAT(decrypter, IsOk());
  EXPECT_THAT((*decrypter)->Decrypt(param.ciphertext, param.context_info),
              IsOkAndHolds(Eq(param.plaintext)));
}

TEST_P(HpkeDecryptTestVectorTest, DecryptDifferentContextInfoFails) {
  const internal::HybridTestVector& param = GetParam();
  const HpkePrivateKey* hpke_key =
      dynamic_cast<HpkePrivateKey*>(param.hybrid_private_key.get());
  ASSERT_THAT(hpke_key, NotNull());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      HpkeDecrypt::New(*hpke_key);
  ASSERT_THAT(decrypter, IsOk());
  EXPECT_THAT(
      (*decrypter)
          ->Decrypt(param.ciphertext, absl::StrCat(param.context_info, "x")),
      Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(HpkeDecryptTestVectorTest, HpkeDecryptTestVectorTest,
                         testing::ValuesIn(internal::CreateHpkeTestVectors()));

TEST(HpkeDecryptNewFromKeyObject, P384DoesNotWork) {
  EXPECT_THAT(HpkeDecrypt::New(*GetHpkeNistCurveTestCase(
                                    subtle::EllipticCurveType::NIST_P384)
                                    .private_key),
              Not(IsOk()));
}

TEST(HpkeDecryptNewFromKeyObject, P521DoesNotWork) {
  EXPECT_THAT(HpkeDecrypt::New(*GetHpkeNistCurveTestCase(
                                    subtle::EllipticCurveType::NIST_P521)
                                    .private_key),
              Not(IsOk()));
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
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(HpkeDecrypt::New(*private_key), Not(IsOk()));
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
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(HpkeDecrypt::New(*private_key), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
