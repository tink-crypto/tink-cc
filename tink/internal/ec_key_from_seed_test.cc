// Copyright 2026 Google LLC
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
#include "tink/internal/ec_key_from_seed.h"

#include <cstddef>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_util.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::test::EqualsSecretData;
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Matcher;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using EcKeyFromSeedTest = TestWithParam<subtle::EllipticCurveType>;

// Matcher for the equality of two EcKeys.
Matcher<EcKey> EqualsEcKey(const EcKey& expected) {
  return AllOf(Field(&EcKey::priv, EqualsSecretData(expected.priv)),
               Field(&EcKey::pub_x, Eq(expected.pub_x)),
               Field(&EcKey::pub_y, Eq(expected.pub_y)),
               Field(&EcKey::curve, Eq(expected.curve)));
}

TEST_P(EcKeyFromSeedTest, KeysFromDifferentSeedAreDifferent) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKeyFromSeed is not supported with OpenSSL";
  }

  SecretData seed1 =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  SecretData seed2 =
      SecretData(test::HexDecodeOrDie("0f0e0d0c0b0a09080706050403020100"));
  subtle::EllipticCurveType curve = GetParam();

  absl::StatusOr<EcKey> keypair1 = NewEcKeyFromSeed(curve, seed1);
  ASSERT_THAT(keypair1, IsOk());
  absl::StatusOr<EcKey> keypair2 = NewEcKeyFromSeed(curve, seed2);
  ASSERT_THAT(keypair2, IsOk());
  EXPECT_THAT(*keypair1, Not(EqualsEcKey(*keypair2)));
}

TEST_P(EcKeyFromSeedTest, SameSeedGivesSameKey) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKeyFromSeed is not supported with OpenSSL";
  }

  SecretData seed1 =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  subtle::EllipticCurveType curve = GetParam();

  absl::StatusOr<EcKey> keypair1 = NewEcKeyFromSeed(curve, seed1);
  ASSERT_THAT(keypair1, IsOk());
  absl::StatusOr<EcKey> keypair2 = NewEcKeyFromSeed(curve, seed1);
  ASSERT_THAT(keypair2, IsOk());
  EXPECT_THAT(*keypair1, EqualsEcKey(*keypair2));
}

INSTANTIATE_TEST_SUITE_P(EcKeyFromSeedTests, EcKeyFromSeedTest,
                         ValuesIn({subtle::NIST_P256, subtle::NIST_P384,
                                   subtle::NIST_P521}));

struct EcKeyFromSeedTestVector {
  subtle::EllipticCurveType curve;
  std::string seed_hex;
  std::string expected_priv_hex;
  // Uncompressed point encoding: 04 || x || y.
  std::string expected_pub_hex;
};

// Test vectors from BoringSSL's ECTest.DeriveFromSecret
// (crypto/fipsmodule/ec/ec_test.cc).
std::vector<EcKeyFromSeedTestVector> GetEcKeyFromSeedTestVectors() {
  return {
      {subtle::NIST_P256, "",
       "b98a86a71efb51ebdac4759937b977e9b0c05224675bb2b6a58ba306e237f4b8",
       "04fbe6cab439918e00231a2ff073cdc25823998864a9eb36f809095a1a919ece875"
       "a145803fbe89a6cde53936e3c6d9c253ed3d38f5f58cae455c27e95645ceda9"},
      {subtle::NIST_P256, "123456",
       "44a72bc62087b88e5ab7126766177ed0d8f1ed09ad066cd746527fc201105a7e",
       "04ec0555cd76e991fef7f5504343937d0f38696db3360a4854052cb0d84a377a5a0"
       "ff64c352755c28692b4ae085c2b817db9a1eddbd22e9cf39c12751e0870791b"},
      {subtle::NIST_P256, "00000000000000000000000000000000",
       "7ca1e2c83e6a5f2c1b3e7d58180226f269930c4b9fbe2a275096079630b7c57d",
       "0442ef70c8fc0fbe383ed0a0da36f39f9a590f3feebc07863cc858c9a8ef0465731"
       "0408c249bd4d61929c54b71ffe056e6b4fa1eb537039b43d1c175f0ceab0f89"},
      {subtle::NIST_P256,
       "de9c9b35543aaa0fba039e34e8ca9695da3225c7161c9e3a8c70356cac28c780",
       "659f5abf3b62b9931c29d6ed0722efd2349fa56f54e708cf3272f620f1bc44d0",
       "046741f806b593bf3a3d4a9d76bdcb9b0d7874633cbea8f42c05e78561f7e8ec362"
       "b9b6f1913ded796fbdafe7f210cea897ac22a4e580c06a60f2659fd09f1830f"},
      {subtle::NIST_P384, "123456",
       "95cd90d548997de090c7622708eccb7edc1b1bd78d2422235ad97406dada"
       "076555309da200096f6e4b36c46002beee89",
       "04007b2d026aa7636fa912c3f970d62bb6c10fa81c8f3290ed90b2d701696d1c6b9"
       "5af88ce13e962996a7ac37e16527cb5d69bd081b8641d07634cf84b438600ec9434"
       "15ac6bd7a0236f7ab0ea31ece67df03fa11646ea2b75e73d1b5e45b75c18"},
  };
}

using EcKeyFromSeedTestVectorTest = TestWithParam<EcKeyFromSeedTestVector>;

TEST_P(EcKeyFromSeedTestVectorTest, DerivesExpectedKey) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKeyFromSeed is not supported with OpenSSL";
  }
  const EcKeyFromSeedTestVector& test_vector = GetParam();

  absl::StatusOr<EcKey> key = NewEcKeyFromSeed(
      test_vector.curve,
      SecretData(test::HexDecodeOrDie(test_vector.seed_hex)));
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->curve, Eq(test_vector.curve));
  EXPECT_THAT(key->priv, EqualsSecretData(SecretData(test::HexDecodeOrDie(
                             test_vector.expected_priv_hex))));
  std::string expected_pub = test::HexDecodeOrDie(test_vector.expected_pub_hex);
  ASSERT_THAT(expected_pub[0], Eq('\x04'));
  const size_t coordinate_size = (expected_pub.size() - 1) / 2;
  EXPECT_THAT(key->pub_x, Eq(expected_pub.substr(1, coordinate_size)));
  EXPECT_THAT(key->pub_y, Eq(expected_pub.substr(1 + coordinate_size)));
}

INSTANTIATE_TEST_SUITE_P(EcKeyFromSeedTestVectorTests,
                         EcKeyFromSeedTestVectorTest,
                         ValuesIn(GetEcKeyFromSeedTestVectors()));

TEST(EcKeyFromSeedTest, FailsWithWrongCurve) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKeyFromSeed is not supported with OpenSSL";
  }
  SecretData seed =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  absl::StatusOr<EcKey> keypair =
      NewEcKeyFromSeed(subtle::EllipticCurveType::CURVE25519, seed);
  EXPECT_THAT(keypair.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST(EcKeyFromSeedTest, FailsInFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only test in FIPS-only mode";
  }
  SecretData seed =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  EXPECT_THAT(
      NewEcKeyFromSeed(subtle::EllipticCurveType::NIST_P256, seed).status(),
      Not(IsOk()));
}

TEST(EcKeyFromSeedTest, UnimplementedIfOpenSsl) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (IsBoringSsl()) {
    GTEST_SKIP()
        << "OpenSSL-only test; skipping because BoringSSL is being used";
  }
  SecretData seed =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  absl::StatusOr<EcKey> keypair =
      NewEcKeyFromSeed(subtle::EllipticCurveType::CURVE25519, seed);
  EXPECT_THAT(keypair.status(), StatusIs(absl::StatusCode::kUnimplemented));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
