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

#include "tink/hybrid/internal/hpke_util_boringssl.h"

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  google::crypto::tink::HpkeKem kem_proto;
  HpkeKem kem_struct;
  uint16_t kem_id;
};

using HpkeUtilBoringSslTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HpkeUtilBoringSslTestSuite, HpkeUtilBoringSslTest,
    Values(TestCase{google::crypto::tink::HpkeKem::DHKEM_P256_HKDF_SHA256,
                    HpkeKem::kP256HkdfSha256, EVP_HPKE_DHKEM_P256_HKDF_SHA256},
           TestCase{google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256,
                    HpkeKem::kX25519HkdfSha256,
                    EVP_HPKE_DHKEM_X25519_HKDF_SHA256}));

TEST_P(HpkeUtilBoringSslTest, ValidParamsFromProto) {
  TestCase test_case = GetParam();
  google::crypto::tink::HpkeParams params = CreateHpkeParams(
      test_case.kem_proto, google::crypto::tink::HpkeKdf::HKDF_SHA256,
      google::crypto::tink::HpkeAead::AES_256_GCM);

  absl::StatusOr<const EVP_HPKE_KEM *> kem_from_enum =
      KemParam(test_case.kem_proto);
  ASSERT_THAT(kem_from_enum, IsOk());
  EXPECT_THAT(EVP_HPKE_KEM_id(*kem_from_enum), Eq(test_case.kem_id));

  absl::StatusOr<const EVP_HPKE_KEM *> kem_from_proto = KemParam(params);
  ASSERT_THAT(kem_from_proto, IsOk());
  EXPECT_THAT(EVP_HPKE_KEM_id(*kem_from_proto), Eq(test_case.kem_id));

  absl::StatusOr<const EVP_HPKE_KDF *> kdf = KdfParam(params);
  ASSERT_THAT(kdf, IsOk());
  EXPECT_THAT(EVP_HPKE_KDF_id(*kdf), Eq(EVP_HPKE_HKDF_SHA256));

  absl::StatusOr<const EVP_HPKE_AEAD *> aead = AeadParam(params);
  ASSERT_THAT(aead, IsOk());
  EXPECT_THAT(EVP_HPKE_AEAD_id(*aead), Eq(EVP_HPKE_AES_256_GCM));
}

TEST_P(HpkeUtilBoringSslTest, ValidParamsFromStruct) {
  TestCase test_case = GetParam();
  HpkeParams params = {test_case.kem_struct, HpkeKdf::kHkdfSha256,
                       HpkeAead::kAes256Gcm};

  absl::StatusOr<const EVP_HPKE_KEM *> kem_from_proto = KemParam(params);
  ASSERT_THAT(kem_from_proto, IsOk());
  EXPECT_THAT(EVP_HPKE_KEM_id(*kem_from_proto), Eq(test_case.kem_id));

  absl::StatusOr<const EVP_HPKE_KDF *> kdf = KdfParam(params);
  ASSERT_THAT(kdf, IsOk());
  EXPECT_THAT(EVP_HPKE_KDF_id(*kdf), Eq(EVP_HPKE_HKDF_SHA256));

  absl::StatusOr<const EVP_HPKE_AEAD *> aead = AeadParam(params);
  ASSERT_THAT(aead, IsOk());
  EXPECT_THAT(EVP_HPKE_AEAD_id(*aead), Eq(EVP_HPKE_AES_256_GCM));
}

TEST(HpkeUtilBoringSslTest, UnknownKemParamFromProto) {
  google::crypto::tink::HpkeParams params =
      CreateHpkeParams(google::crypto::tink::HpkeKem::KEM_UNKNOWN,
                       google::crypto::tink::HpkeKdf::HKDF_SHA256,
                       google::crypto::tink::HpkeAead::AES_256_GCM);
  EXPECT_THAT(KemParam(params), Not(IsOk()));
  EXPECT_THAT(KdfParam(params), IsOk());
  EXPECT_THAT(AeadParam(params), IsOk());
}

TEST(HpkeUtilBoringSslTest, UnknownKemParamFromStruct) {
  HpkeParams params = {HpkeKem::kUnknownKem, HpkeKdf::kHkdfSha256,
                       HpkeAead::kAes256Gcm};
  EXPECT_THAT(KemParam(params), Not(IsOk()));
  EXPECT_THAT(KdfParam(params), IsOk());
  EXPECT_THAT(AeadParam(params), IsOk());
}

TEST(HpkeUtilBoringSslTest, UnknownKdfParamFromProto) {
  google::crypto::tink::HpkeParams params =
      CreateHpkeParams(google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256,
                       google::crypto::tink::HpkeKdf::KDF_UNKNOWN,
                       google::crypto::tink::HpkeAead::AES_256_GCM);
  EXPECT_THAT(KemParam(params), IsOk());
  EXPECT_THAT(KdfParam(params), Not(IsOk()));
  EXPECT_THAT(AeadParam(params), IsOk());
}

TEST(HpkeUtilBoringSslTest, UnknownKdfParamFromStruct) {
  HpkeParams params = {HpkeKem::kX25519HkdfSha256, HpkeKdf::kUnknownKdf,
                       HpkeAead::kAes256Gcm};
  EXPECT_THAT(KemParam(params), IsOk());
  EXPECT_THAT(KdfParam(params), Not(IsOk()));
  EXPECT_THAT(AeadParam(params), IsOk());
}

TEST(HpkeUtilBoringSslTest, UnknownAeadParamFromProto) {
  google::crypto::tink::HpkeParams params =
      CreateHpkeParams(google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256,
                       google::crypto::tink::HpkeKdf::HKDF_SHA256,
                       google::crypto::tink::HpkeAead::AEAD_UNKNOWN);
  EXPECT_THAT(KemParam(params), IsOk());
  EXPECT_THAT(KdfParam(params), IsOk());
  EXPECT_THAT(AeadParam(params), Not(IsOk()));
}

TEST(HpkeUtilBoringSslTest, UnknownAeadParamFromStruct) {
  HpkeParams params = {HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                       HpkeAead::kUnknownAead};
  EXPECT_THAT(KemParam(params), IsOk());
  EXPECT_THAT(KdfParam(params), IsOk());
  EXPECT_THAT(AeadParam(params), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
