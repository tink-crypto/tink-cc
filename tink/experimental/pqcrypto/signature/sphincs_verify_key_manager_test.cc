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

#include "tink/experimental/pqcrypto/signature/sphincs_verify_key_manager.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/experimental/pqcrypto/signature/sphincs_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_verify.h"
#include "tink/experimental/pqcrypto/signature/util/enums.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/experimental/pqcrypto/sphincs.pb.h"
#include "proto/tink.pb.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-simple/api.h"
}

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::EnumsPqcrypto;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::SphincsHashType;
using ::google::crypto::tink::SphincsKeyFormat;
using ::google::crypto::tink::SphincsParams;
using ::google::crypto::tink::SphincsPrivateKey;
using ::google::crypto::tink::SphincsPublicKey;
using ::google::crypto::tink::SphincsSignatureType;
using ::google::crypto::tink::SphincsVariant;
using ::testing::Eq;
using ::testing::Not;

struct SphincsTestCase {
  std::string test_name;
  SphincsHashType hash_type;
  SphincsVariant variant;
  SphincsSignatureType sig_length_type;
  int32_t private_key_size;
  int32_t public_key_size;
};

using SphincsVerifyKeyManagerTest = testing::TestWithParam<SphincsTestCase>;

// Helper function that returns a valid sphincs private key.
absl::StatusOr<SphincsPrivateKey> CreateValidPrivateKey(
    int32_t private_key_size, SphincsHashType hash_type, SphincsVariant variant,
    SphincsSignatureType type) {
  SphincsKeyFormat key_format;
  SphincsParams* params = key_format.mutable_params();
  params->set_key_size(private_key_size);
  params->set_hash_type(hash_type);
  params->set_variant(variant);
  params->set_sig_length_type(type);

  return SphincsSignKeyManager().CreateKey(key_format);
}

// Helper function that returns a valid sphincs public key.
absl::StatusOr<SphincsPublicKey> CreateValidPublicKey(
    int32_t private_key_size, SphincsHashType hash_type, SphincsVariant variant,
    SphincsSignatureType type) {
  absl::StatusOr<SphincsPrivateKey> private_key =
      CreateValidPrivateKey(private_key_size, hash_type, variant, type);

  if (!private_key.ok()) return private_key.status();
  return SphincsSignKeyManager().GetPublicKey(*private_key);
}

TEST(SphincsVerifyKeyManagerTest, Basics) {
  EXPECT_THAT(SphincsVerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(SphincsVerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(SphincsVerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.SphincsPublicKey"));
}

TEST(SphincsVerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(SphincsVerifyKeyManager().ValidateKey(SphincsPublicKey()),
              Not(IsOk()));
}

TEST_P(SphincsVerifyKeyManagerTest, InvalidParam) {
  const SphincsTestCase& test_case = GetParam();

  SphincsKeyFormat key_format;
  SphincsParams* params = key_format.mutable_params();
  params->set_key_size(test_case.private_key_size);
  params->set_hash_type(test_case.hash_type);
  params->set_variant(test_case.variant);
  params->set_sig_length_type(SphincsSignatureType::SIG_TYPE_UNSPECIFIED);

  EXPECT_THAT(SphincsVerifyKeyManager().ValidateParams(*params), Not(IsOk()));
}

TEST_P(SphincsVerifyKeyManagerTest, PublicKeyValid) {
  const SphincsTestCase& test_case = GetParam();

  absl::StatusOr<SphincsPublicKey> public_key =
      CreateValidPublicKey(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(SphincsVerifyKeyManager().ValidateKey(*public_key), IsOk());
}

TEST(SphincsVerifyKeyManagerTest, PublicKeyInvalidParams) {
  absl::StatusOr<SphincsPublicKey> public_key = CreateValidPublicKey(
      subtle::kSphincsPrivateKeySize64, SphincsHashType::HASH_TYPE_UNSPECIFIED,
      SphincsVariant::VARIANT_UNSPECIFIED,
      SphincsSignatureType::SIG_TYPE_UNSPECIFIED);
  EXPECT_THAT(public_key, Not(IsOk()));
}

TEST_P(SphincsVerifyKeyManagerTest, PublicKeyWrongVersion) {
  const SphincsTestCase& test_case = GetParam();

  absl::StatusOr<SphincsPublicKey> public_key =
      CreateValidPublicKey(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(public_key, IsOk());

  public_key->set_version(1);
  EXPECT_THAT(SphincsVerifyKeyManager().ValidateKey(*public_key), Not(IsOk()));
}

TEST_P(SphincsVerifyKeyManagerTest, Create) {
  const SphincsTestCase& test_case = GetParam();

  absl::StatusOr<SphincsPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size, test_case.hash_type,
                            test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<SphincsPublicKey> public_key =
      SphincsSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key, IsOk());

  subtle::SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type = EnumsPqcrypto::ProtoToSubtle(test_case.hash_type),
      .variant = EnumsPqcrypto::ProtoToSubtle(test_case.variant),
      .sig_length_type =
          EnumsPqcrypto::ProtoToSubtle(test_case.sig_length_type),
      .private_key_size = test_case.private_key_size};
  subtle::SphincsPrivateKeyPqclean sphincs_private_key_pqclean(
      util::SecretDataFromStringView(private_key->key_value()),
      sphincs_params_pqclean);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> direct_signer =
      subtle::SphincsSign::New(sphincs_private_key_pqclean);
  ASSERT_THAT(direct_signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      SphincsVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "Some message";
  absl::StatusOr<std::string> signature = (*direct_signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(SphincsVerifyKeyManagerTest, CreateInvalidPublicKey) {
  const SphincsTestCase& test_case = GetParam();

  absl::StatusOr<SphincsPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size, test_case.hash_type,
                            test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<SphincsPublicKey> public_key =
      SphincsSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key, IsOk());

  std::string bad_public_key_data = "bad_public_key";
  public_key->set_key_value(bad_public_key_data);

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      SphincsVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  EXPECT_THAT(verifier, Not(IsOk()));
}

TEST_P(SphincsVerifyKeyManagerTest, CreateDifferentPublicKey) {
  const SphincsTestCase& test_case = GetParam();

  absl::StatusOr<SphincsPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size, test_case.hash_type,
                            test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(private_key, IsOk());

  // Create a new public key derived from a diffferent private key.
  absl::StatusOr<SphincsPrivateKey> new_private_key =
      CreateValidPrivateKey(test_case.private_key_size, test_case.hash_type,
                            test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(new_private_key, IsOk());
  absl::StatusOr<SphincsPublicKey> public_key =
      SphincsSignKeyManager().GetPublicKey(*new_private_key);
  ASSERT_THAT(public_key, IsOk());

  subtle::SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type = EnumsPqcrypto::ProtoToSubtle(test_case.hash_type),
      .variant = EnumsPqcrypto::ProtoToSubtle(test_case.variant),
      .sig_length_type =
          EnumsPqcrypto::ProtoToSubtle(test_case.sig_length_type),
      .private_key_size = test_case.private_key_size};
  subtle::SphincsPrivateKeyPqclean sphincs_private_key_pqclean(
      util::SecretDataFromStringView(private_key->key_value()),
      sphincs_params_pqclean);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> direct_signer =
      subtle::SphincsSign::New(sphincs_private_key_pqclean);
  ASSERT_THAT(direct_signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      SphincsVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "Some message";
  absl::StatusOr<std::string> signature = (*direct_signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    SphincsVerifyKeyManagerTests, SphincsVerifyKeyManagerTest,
    testing::ValuesIn<SphincsTestCase>(
        {{"SPHINCSHARAKA128FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSHARAKA192FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSHARAKA256FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256128FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256192FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256256FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256128FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256192FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256256FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_PUBLICKEYBYTES}}),
    [](const testing::TestParamInfo<SphincsVerifyKeyManagerTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace

}  // namespace tink
}  // namespace crypto
