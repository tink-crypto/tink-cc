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
#include "tink/internal/ec_util.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/secret_data.h"
#include "tink/util/test_util.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "absl/log/absl_check.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/ssl_util.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::EcdsaParameters;
using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::
    GetEllipticCurveTypeFromValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;
using ::crypto::tink::subtle::EcPointFormat;
using ::crypto::tink::subtle::EllipticCurveType;
using ::crypto::tink::test::EqualsSecretData;
using ::testing::AllOf;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Field;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsNull;
using ::testing::Matcher;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(EcUtilTest, NewEd25519KeyInvalidSeed) {
  std::string valid_seed = test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
  // Seed that is too small.
  for (int i = 0; i < 32; i++) {
    EXPECT_THAT(
        NewEd25519Key(util::SecretDataFromStringView(valid_seed.substr(0, i)))
            .status(),
        Not(IsOk()))
        << " with seed of length " << i;
  }
  // Seed that is too large.
  std::string large_seed = absl::StrCat(valid_seed, "a");
  EXPECT_THAT(
      NewEd25519Key(util::SecretDataFromStringView(large_seed)).status(),
      Not(IsOk()))
      << " with seed of length " << large_seed.size();
}

TEST(EcUtilTest, NewEcKeyReturnsWellFormedX25519Key) {
  absl::StatusOr<EcKey> ec_key =
      NewEcKey(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(ec_key, IsOk());
  EXPECT_THAT(
      *ec_key,
      AllOf(Field(&EcKey::curve, Eq(subtle::EllipticCurveType::CURVE25519)),
            Field(&EcKey::pub_x, SizeIs(X25519KeyPubKeySize())),
            Field(&EcKey::pub_y, IsEmpty()),
            Field(&EcKey::priv, SizeIs(X25519KeyPrivKeySize()))));
}

using EcUtilNewEcKeyWithSeed = TestWithParam<subtle::EllipticCurveType>;

// Matcher for the equality of two EcKeys.
Matcher<EcKey> EqualsEcKey(const EcKey& expected) {
  return AllOf(Field(&EcKey::priv, EqualsSecretData(expected.priv)),
               Field(&EcKey::pub_x, Eq(expected.pub_x)),
               Field(&EcKey::pub_y, Eq(expected.pub_y)),
               Field(&EcKey::curve, Eq(expected.curve)));
}

TEST_P(EcUtilNewEcKeyWithSeed, KeysFromDifferentSeedAreDifferent) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKey with seed is not supported with OpenSSL";
  }

  SecretData seed1 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  SecretData seed2 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("0f0e0d0c0b0a09080706050403020100"));
  subtle::EllipticCurveType curve = GetParam();

  absl::StatusOr<EcKey> keypair1 = NewEcKey(curve, seed1);
  ASSERT_THAT(keypair1, IsOk());
  absl::StatusOr<EcKey> keypair2 = NewEcKey(curve, seed2);
  ASSERT_THAT(keypair2, IsOk());
  EXPECT_THAT(*keypair1, Not(EqualsEcKey(*keypair2)));
}

TEST_P(EcUtilNewEcKeyWithSeed, SameSeedGivesSameKey) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKey with seed is not supported with OpenSSL";
  }

  SecretData seed1 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  subtle::EllipticCurveType curve = GetParam();

  absl::StatusOr<EcKey> keypair1 = NewEcKey(curve, seed1);
  ASSERT_THAT(keypair1, IsOk());
  absl::StatusOr<EcKey> keypair2 = NewEcKey(curve, seed1);
  ASSERT_THAT(keypair2, IsOk());
  EXPECT_THAT(*keypair1, EqualsEcKey(*keypair2));
}

INSTANTIATE_TEST_SUITE_P(EcUtilNewEcKeyWithSeeds, EcUtilNewEcKeyWithSeed,
                         ValuesIn({subtle::NIST_P256, subtle::NIST_P384,
                                   subtle::NIST_P521}));

TEST(EcUtilTest, GenerationWithSeedFailsWithWrongCurve) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "NewEcKey with seed is not supported with OpenSSL";
  }
  SecretData seed = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  absl::StatusOr<EcKey> keypair =
      NewEcKey(subtle::EllipticCurveType::CURVE25519, seed);
  EXPECT_THAT(keypair.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST(EcUtilTest, NewEcKeyFromSeedUnimplementedIfOpenSsl) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  if (IsBoringSsl()) {
    GTEST_SKIP()
        << "OpenSSL-only test; skipping because BoringSSL is being used";
  }
  SecretData seed = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  absl::StatusOr<EcKey> keypair =
      NewEcKey(subtle::EllipticCurveType::CURVE25519, seed);
  EXPECT_THAT(keypair.status(), StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(EcUtilTest, NewX25519KeyGeneratesNewKeyEveryTime) {
  absl::StatusOr<std::unique_ptr<X25519Key>> keypair1 = NewX25519Key();
  ASSERT_THAT(keypair1, IsOk());
  absl::StatusOr<std::unique_ptr<X25519Key>> keypair2 = NewX25519Key();
  ASSERT_THAT(keypair2, IsOk());

  EXPECT_THAT((*keypair1)->private_key,
              Not(EqualsSecretData((*keypair2)->private_key)));
  auto pub_key1 =
      absl::MakeSpan((*keypair1)->public_value, X25519KeyPubKeySize());
  auto pub_key2 =
      absl::MakeSpan((*keypair2)->public_value, X25519KeyPubKeySize());
  EXPECT_THAT(pub_key1, Not(ElementsAreArray(pub_key2)));
}

TEST(EcUtilTest, X25519KeyFromRandomPrivateKey) {
  absl::StatusOr<std::unique_ptr<X25519Key>> x25519_key = NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  absl::StatusOr<std::unique_ptr<X25519Key>> roundtrip_key =
      X25519KeyFromPrivateKey((*x25519_key)->private_key);
  ASSERT_THAT(roundtrip_key, IsOk());
  EXPECT_THAT((*roundtrip_key)->private_key,
              EqualsSecretData((*x25519_key)->private_key));
  EXPECT_THAT(
      absl::MakeSpan((*x25519_key)->public_value, X25519KeyPubKeySize()),
      ElementsAreArray(absl::MakeSpan((*roundtrip_key)->public_value,
                                      X25519KeyPubKeySize())));
}

struct X25519FunctionTestVector {
  std::string private_key;
  std::string expected_public_key;
};

// Returns some X25519 test vectors taken from
// https://datatracker.ietf.org/doc/html/rfc7748.
std::vector<X25519FunctionTestVector> GetX25519FunctionTestVectors() {
  return {
      // https://datatracker.ietf.org/doc/html/rfc7748#section-5.2
      {
          /*private_key=*/
          test::HexDecodeOrDie("090000000000000000000000000000000000000000000"
                               "0000000000000000000"),
          /*expected_public_key=*/
          test::HexDecodeOrDie("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854"
                               "b783c60e80311ae3079"),
      },
      // https://datatracker.ietf.org/doc/html/rfc7748#section-6.1; Alice
      {
          /*private_key=*/
          test::HexDecodeOrDie("77076d0a7318a57d3c16c17251b26645df4c2f87ebc09"
                               "92ab177fba51db92c2a"),
          /*expected_public_key=*/
          test::HexDecodeOrDie("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381"
                               "af4eba4a98eaa9b4e6a"),
      },
      // https://datatracker.ietf.org/doc/html/rfc7748#section-6.1; Bob
      {
          /*private_key=*/
          test::HexDecodeOrDie("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b"
                               "6fd1c2f8b27ff88e0eb"),
          /*expected_public_key=*/
          test::HexDecodeOrDie("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b786"
                               "74dadfc7e146f882b4f"),
      },
      // Locally made up test vector
      {
          /*private_key=*/
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          /*expected_public_key=*/
          test::HexDecodeOrDie("4049502db92ca2342c3f92dac5d6de7c85db5df5407a5"
                               "b4996ce39f2efb7e827"),
      },
  };
}

using X25519FunctionTest = TestWithParam<X25519FunctionTestVector>;

TEST_P(X25519FunctionTest, ComputeX25519PublicKey) {
  X25519FunctionTestVector test_vector = GetParam();

  absl::StatusOr<std::unique_ptr<X25519Key>> key = X25519KeyFromPrivateKey(
      util::SecretDataFromStringView(test_vector.private_key));
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(absl::MakeSpan((*key)->public_value, X25519KeyPubKeySize()),
              ElementsAreArray(test_vector.expected_public_key));
}

INSTANTIATE_TEST_SUITE_P(X25519SharedSecretTests, X25519FunctionTest,
                         ValuesIn(GetX25519FunctionTestVectors()));

struct X25519SharedSecretTestVector {
  std::string private_key;
  std::string public_key;
  std::string expected_shared_secret;
};

// Returns some X25519 test vectors taken from
// https://datatracker.ietf.org/doc/html/rfc7748#section-5.2.
std::vector<X25519SharedSecretTestVector> GetX25519SharedSecretTestVectors() {
  return {
      {
          /*private_key=*/
          test::HexDecodeOrDie("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5"
                               "a18506a2244ba449ac4"),
          /*public_key=*/
          test::HexDecodeOrDie("e6db6867583030db3594c1a424b15f7c726624ec26b33"
                               "53b10a903a6d0ab1c4c"),
          /*expected_shared_secret=*/
          test::HexDecodeOrDie("c3da55379de9c6908e94ea4df28d084f32eccf03491c7"
                               "1f754b4075577a28552"),
      },
      {
          /*private_key=*/
          test::HexDecodeOrDie("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea0"
                               "1d42ca4169e7918ba0d"),
          /*public_key=*/
          test::HexDecodeOrDie("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03"
                               "c3efc4cd549c715a493"),
          /*expected_shared_secret=*/
          test::HexDecodeOrDie("95cbde9476e8907d7aade45cb4b873f88b595a68799fa"
                               "152e6f8f7647aac7957"),
      },
  };
}

using X25519SharedSecretTest = TestWithParam<X25519SharedSecretTestVector>;

TEST_P(X25519SharedSecretTest, ComputeX25519SharedSecret) {
  X25519SharedSecretTestVector test_vector = GetParam();

  // Generate the EVP_PKEYs.
  internal::SslUniquePtr<EVP_PKEY> ssl_priv_key(EVP_PKEY_new_raw_private_key(
      /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr,
      /*in=*/reinterpret_cast<const uint8_t*>(test_vector.private_key.data()),
      /*len=*/Ed25519KeyPrivKeySize()));
  ASSERT_THAT(ssl_priv_key, Not(IsNull()));
  internal::SslUniquePtr<EVP_PKEY> ssl_pub_key(EVP_PKEY_new_raw_public_key(
      /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr,
      /*in=*/reinterpret_cast<const uint8_t*>(test_vector.public_key.data()),
      /*len=*/Ed25519KeyPrivKeySize()));
  ASSERT_THAT(ssl_pub_key, Not(IsNull()));

  EXPECT_THAT(
      ComputeX25519SharedSecret(ssl_priv_key.get(), ssl_pub_key.get()),
      absl_testing::IsOkAndHolds(EqualsSecretData(
          util::SecretDataFromStringView(test_vector.expected_shared_secret))));
}

INSTANTIATE_TEST_SUITE_P(X25519SharedSecretTests, X25519SharedSecretTest,
                         ValuesIn(GetX25519SharedSecretTestVectors()));

TEST(EcUtilTest, ComputeX25519SharedSecretInvalidKeyType) {
  // Key pair of an invalid type EVP_PKEY_ED25519.
  SslUniquePtr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,
                                                      /*e=*/nullptr));
  ASSERT_THAT(pctx, Not(IsNull()));
  ASSERT_EQ(EVP_PKEY_keygen_init(pctx.get()), 1);
  EVP_PKEY* invalid_type_key_ptr = nullptr;
  ASSERT_EQ(EVP_PKEY_keygen(pctx.get(), &invalid_type_key_ptr), 1);
  SslUniquePtr<EVP_PKEY> invalid_type_key(invalid_type_key_ptr);

  // Private and public key with valid type.
  internal::SslUniquePtr<EVP_PKEY> ssl_priv_key(EVP_PKEY_new_raw_private_key(
      /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr,
      /*in=*/
      reinterpret_cast<const uint8_t*>(
          test::HexDecodeOrDie("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5"
                               "a18506a2244ba449ac4")
              .data()),
      /*len=*/Ed25519KeyPrivKeySize()));
  ASSERT_THAT(ssl_priv_key, Not(IsNull()));
  internal::SslUniquePtr<EVP_PKEY> ssl_pub_key(EVP_PKEY_new_raw_public_key(
      /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr,
      /*in=*/
      reinterpret_cast<const uint8_t*>(
          test::HexDecodeOrDie("e6db6867583030db3594c1a424b15f7c726624ec26b33"
                               "53b10a903a6d0ab1c4c")
              .data()),
      /*len=*/Ed25519KeyPubKeySize()));
  ASSERT_THAT(ssl_pub_key, Not(IsNull()));

  EXPECT_THAT(
      ComputeX25519SharedSecret(ssl_priv_key.get(), invalid_type_key.get())
          .status(),
      Not(IsOk()));
  EXPECT_THAT(
      ComputeX25519SharedSecret(invalid_type_key.get(), ssl_pub_key.get())
          .status(),
      Not(IsOk()));
}

struct EncodingTestVector {
  EcPointFormat format;
  std::string x_hex;
  std::string y_hex;
  std::string encoded_hex;
  EllipticCurveType curve;
};

std::vector<EncodingTestVector> GetEncodingTestVectors() {
  return {
      {EcPointFormat::UNCOMPRESSED,
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
       "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       "0400093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918e"
       "c6619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a00aa3fb2"
       "448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327acaac1fa4"
       "0424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       EllipticCurveType::NIST_P521},
      {EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
       "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a00aa3fb244"
       "8335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327acaac1fa404"
       "24c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       EllipticCurveType::NIST_P521},
      {EcPointFormat::COMPRESSED,
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
       "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       "0300093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918e"
       "c6619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       EllipticCurveType::NIST_P521}};
}

using EcUtilEncodeDecodePointTest = TestWithParam<EncodingTestVector>;

TEST_P(EcUtilEncodeDecodePointTest, EcPointEncode) {
  const EncodingTestVector& test = GetParam();
  absl::StatusOr<SslUniquePtr<EC_POINT>> point =
      GetEcPoint(test.curve, test::HexDecodeOrDie(test.x_hex),
                 test::HexDecodeOrDie(test.y_hex));
  ASSERT_THAT(point, IsOk());

  absl::StatusOr<std::string> encoded_point =
      EcPointEncode(test.curve, test.format, point->get());
  ASSERT_THAT(encoded_point, IsOk());
  EXPECT_EQ(test.encoded_hex, test::HexEncode(*encoded_point));
}

TEST_P(EcUtilEncodeDecodePointTest, EcPointDecode) {
  const EncodingTestVector& test = GetParam();
  // Get the test point and its encoded version.
  absl::StatusOr<SslUniquePtr<EC_POINT>> point =
      GetEcPoint(test.curve, test::HexDecodeOrDie(test.x_hex),
                 test::HexDecodeOrDie(test.y_hex));
  ASSERT_THAT(point, IsOk());
  std::string encoded_str = test::HexDecodeOrDie(test.encoded_hex);

  absl::StatusOr<SslUniquePtr<EC_GROUP>> ec_group =
      EcGroupFromCurveType(test.curve);
  absl::StatusOr<SslUniquePtr<EC_POINT>> ec_point =
      EcPointDecode(test.curve, test.format, encoded_str);
  ASSERT_THAT(ec_point, IsOk());
  EXPECT_EQ(EC_POINT_cmp(ec_group->get(), point->get(), ec_point->get(),
                         /*ctx=*/nullptr),
            0);

  // Modifying the 1st byte decoding fails.
  encoded_str[0] = '0';
  absl::StatusOr<SslUniquePtr<EC_POINT>> ec_point2 =
      EcPointDecode(test.curve, test.format, encoded_str);
  EXPECT_THAT(ec_point2, Not(IsOk()));
  if (test.format == EcPointFormat::UNCOMPRESSED ||
      test.format == EcPointFormat::COMPRESSED) {
    EXPECT_THAT(std::string(ec_point2.status().message()),
                HasSubstr("point should start with"));
  }
}

INSTANTIATE_TEST_SUITE_P(
    EcUtilEncodeDecodePointTests, EcUtilEncodeDecodePointTest,
    ValuesIn(GetEncodingTestVectors()),
    [](const TestParamInfo<EcUtilEncodeDecodePointTest::ParamType>& info) {
      switch (info.param.format) {
        case EcPointFormat::UNCOMPRESSED:
          return "Uncompressed";
        case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
          return "DoNotUseCrunchyUncompressed";
        case EcPointFormat::COMPRESSED:
          return "Compressed";
        default:
          return "Unknown";
      }
    });

TEST(EcUtilTest, EcFieldSizeInBytes) {
  EXPECT_THAT(EcFieldSizeInBytes(EllipticCurveType::NIST_P256),
              IsOkAndHolds(256 / 8));
  EXPECT_THAT(EcFieldSizeInBytes(EllipticCurveType::NIST_P384),
              IsOkAndHolds(384 / 8));
  EXPECT_THAT(EcFieldSizeInBytes(EllipticCurveType::NIST_P521),
              IsOkAndHolds((521 + 7) / 8));
  EXPECT_THAT(EcFieldSizeInBytes(EllipticCurveType::CURVE25519),
              IsOkAndHolds(256 / 8));
  EXPECT_THAT(EcFieldSizeInBytes(EllipticCurveType::UNKNOWN_CURVE).status(),
              Not(IsOk()));
}

TEST(EcUtilTest, EcPointEncodingSizeInBytes) {
  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::NIST_P256,
                                         EcPointFormat::UNCOMPRESSED),
              IsOkAndHolds(2 * (256 / 8) + 1));
  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::NIST_P256,
                                         EcPointFormat::COMPRESSED),
              IsOkAndHolds(256 / 8 + 1));
  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::NIST_P384,
                                         EcPointFormat::UNCOMPRESSED),
              IsOkAndHolds(2 * (384 / 8) + 1));
  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::NIST_P384,
                                         EcPointFormat::COMPRESSED),
              IsOkAndHolds(384 / 8 + 1));
  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::NIST_P521,
                                         EcPointFormat::UNCOMPRESSED),
              IsOkAndHolds(2 * ((521 + 7) / 8) + 1));
  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::NIST_P521,
                                         EcPointFormat::COMPRESSED),
              IsOkAndHolds((521 + 7) / 8 + 1));
  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::CURVE25519,
                                         EcPointFormat::COMPRESSED),
              IsOkAndHolds(256 / 8));

  EXPECT_THAT(EcPointEncodingSizeInBytes(EllipticCurveType::NIST_P256,
                                         EcPointFormat::UNKNOWN_FORMAT)
                  .status(),
              Not(IsOk()));
}

TEST(EcUtilTest, CurveTypeFromEcGroupSuccess) {
  EC_GROUP* p256_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_GROUP* p384_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  EC_GROUP* p521_group = EC_GROUP_new_by_curve_name(NID_secp521r1);

  absl::StatusOr<EllipticCurveType> p256_curve =
      CurveTypeFromEcGroup(p256_group);
  absl::StatusOr<EllipticCurveType> p384_curve =
      CurveTypeFromEcGroup(p384_group);
  absl::StatusOr<EllipticCurveType> p521_curve =
      CurveTypeFromEcGroup(p521_group);

  ASSERT_THAT(p256_curve, IsOkAndHolds(EllipticCurveType::NIST_P256));
  ASSERT_THAT(p384_curve, IsOkAndHolds(EllipticCurveType::NIST_P384));
  ASSERT_THAT(p521_curve, IsOkAndHolds(EllipticCurveType::NIST_P521));
}

TEST(EcUtilTest, CurveTypeFromEcGroupUnimplemented) {
  EXPECT_THAT(
      CurveTypeFromEcGroup(EC_GROUP_new_by_curve_name(NID_secp224r1)).status(),
      StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(EcUtilTest, ToSubtleEllipticCurveTypeSuccess) {
  EXPECT_THAT(ToSubtleEllipticCurveType(EcdsaParameters::CurveType::kNistP256),
              IsOkAndHolds(EllipticCurveType::NIST_P256));
  EXPECT_THAT(ToSubtleEllipticCurveType(EcdsaParameters::CurveType::kNistP384),
              IsOkAndHolds(EllipticCurveType::NIST_P384));
  EXPECT_THAT(ToSubtleEllipticCurveType(EcdsaParameters::CurveType::kNistP521),
              IsOkAndHolds(EllipticCurveType::NIST_P521));
}

TEST(EcUtilTest, ToSubtleEllipticCurveTypeUnknownFails) {
  EXPECT_THAT(ToSubtleEllipticCurveType(
                  EcdsaParameters::CurveType::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcUtilTest, EcGroupFromCurveTypeSuccess) {
  absl::StatusOr<SslUniquePtr<EC_GROUP>> p256_curve =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  absl::StatusOr<SslUniquePtr<EC_GROUP>> p384_curve =
      EcGroupFromCurveType(EllipticCurveType::NIST_P384);
  absl::StatusOr<SslUniquePtr<EC_GROUP>> p521_curve =
      EcGroupFromCurveType(EllipticCurveType::NIST_P521);
  ASSERT_THAT(p256_curve, IsOk());
  ASSERT_THAT(p384_curve, IsOk());
  ASSERT_THAT(p521_curve, IsOk());

  SslUniquePtr<EC_GROUP> ssl_p256_group(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  SslUniquePtr<EC_GROUP> ssl_p384_group(
      EC_GROUP_new_by_curve_name(NID_secp384r1));
  SslUniquePtr<EC_GROUP> ssl_p521_group(
      EC_GROUP_new_by_curve_name(NID_secp521r1));

  EXPECT_EQ(EC_GROUP_cmp(p256_curve->get(), ssl_p256_group.get(),
                         /*ignored=*/nullptr),
            0);
  EXPECT_EQ(EC_GROUP_cmp(p384_curve->get(), ssl_p384_group.get(),
                         /*ignored=*/nullptr),
            0);
  EXPECT_EQ(EC_GROUP_cmp(p521_curve->get(), ssl_p521_group.get(),
                         /*ignored=*/nullptr),
            0);
}

TEST(EcUtilTest, EcGroupFromCurveTypeUnimplemented) {
  EXPECT_THAT(EcGroupFromCurveType(EllipticCurveType::UNKNOWN_CURVE).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(EcUtilTest, GetEcPointReturnsAValidPoint) {
  SslUniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_secp521r1));
  const unsigned int kCurveSizeInBytes =
      (EC_GROUP_get_degree(group.get()) + 7) / 8;

  constexpr absl::string_view kXCoordinateHex =
      "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
      "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a";
  constexpr absl::string_view kYCoordinateHex =
      "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
      "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf";
  absl::StatusOr<SslUniquePtr<EC_POINT>> point = GetEcPoint(
      EllipticCurveType::NIST_P521, test::HexDecodeOrDie(kXCoordinateHex),
      test::HexDecodeOrDie(kYCoordinateHex));
  ASSERT_THAT(point, IsOk());

  // We check that we can decode this point and the result is the same as the
  // original coordinates.
  std::string xy;
  subtle::ResizeStringUninitialized(&xy, 2 * kCurveSizeInBytes);
  SslUniquePtr<BIGNUM> x(BN_new());
  SslUniquePtr<BIGNUM> y(BN_new());
  ASSERT_EQ(EC_POINT_get_affine_coordinates(group.get(), point->get(), x.get(),
                                            y.get(), /*ctx=*/nullptr),
            1);
  ASSERT_THAT(
      BignumToBinaryPadded(absl::MakeSpan(&xy[0], kCurveSizeInBytes), x.get()),
      IsOk());
  ASSERT_THAT(
      BignumToBinaryPadded(
          absl::MakeSpan(&xy[kCurveSizeInBytes], kCurveSizeInBytes), y.get()),
      IsOk());
  EXPECT_EQ(xy, absl::StrCat(test::HexDecodeOrDie(kXCoordinateHex),
                             test::HexDecodeOrDie(kYCoordinateHex)));
}

struct WycheproofTest {
  std::string test_name;
  std::string filename;
};

using EcUtilWycheproofTest = TestWithParam<WycheproofTest>;

TEST_P(EcUtilWycheproofTest, EcSignatureIeeeToDer) {
  const WycheproofTest& wycheproof_test = GetParam();

  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1(wycheproof_test.filename);
  ASSERT_THAT(parsed_input, IsOk());
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    EllipticCurveType curve =
        GetEllipticCurveTypeFromValue(test_group.struct_value()
                                          .fields()
                                          .at("publicKey")
                                          .struct_value()
                                          .fields()
                                          .at("curve"));
    if (curve == EllipticCurveType::UNKNOWN_CURVE) {
      continue;
    }
    absl::StatusOr<SslUniquePtr<EC_GROUP>> ec_group =
        EcGroupFromCurveType(curve);
    ASSERT_THAT(ec_group, IsOk());
    // Read all the valid signatures.
    for (const auto& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      const auto& test_fields = test.struct_value().fields();
      std::string result = test_fields.at("result").string_value();
      if (result != "valid") {
        continue;
      }
      std::string sig = GetBytesFromHexValue(test_fields.at("sig"));
      absl::StatusOr<std::string> der_encoded =
          EcSignatureIeeeToDer(ec_group->get(), sig);
      ASSERT_THAT(der_encoded, IsOk());

      // Make sure we can reconstruct the IEEE format: [ s || r ].
      SslUniquePtr<ECDSA_SIG> ecdsa_sig(ECDSA_SIG_from_bytes(
          reinterpret_cast<const uint8_t*>(der_encoded->data()),
          der_encoded->size()));
      ASSERT_THAT(ecdsa_sig, Not(IsNull()));
      // Owned by OpenSSL/BoringSSL.
      const BIGNUM* r;
      const BIGNUM* s;
      ECDSA_SIG_get0(ecdsa_sig.get(), &r, &s);
      ASSERT_THAT(r, Not(IsNull()));
      ASSERT_THAT(s, Not(IsNull()));

      absl::StatusOr<int32_t> field_size = EcFieldSizeInBytes(curve);
      ASSERT_THAT(field_size, IsOk());
      absl::StatusOr<std::string> r_str = BignumToString(r, *field_size);
      ASSERT_THAT(r_str, IsOk());
      absl::StatusOr<std::string> s_str = BignumToString(s, *field_size);
      ASSERT_THAT(s_str, IsOk());
      EXPECT_EQ(absl::StrCat(*r_str, *s_str), sig);
    }
  }
}

TEST_P(EcUtilWycheproofTest, EcSignatureDerToIeeeRoundTrip) {
  const WycheproofTest& wycheproof_test = GetParam();

  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1(wycheproof_test.filename);
  ASSERT_THAT(parsed_input, IsOk());
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    EllipticCurveType curve =
        GetEllipticCurveTypeFromValue(test_group.struct_value()
                                          .fields()
                                          .at("publicKey")
                                          .struct_value()
                                          .fields()
                                          .at("curve"));
    if (curve == EllipticCurveType::UNKNOWN_CURVE) {
      continue;
    }
    absl::StatusOr<SslUniquePtr<EC_GROUP>> ec_group =
        EcGroupFromCurveType(curve);
    ASSERT_THAT(ec_group, IsOk());
    for (const auto& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      const auto& test_fields = test.struct_value().fields();
      std::string result = test_fields.at("result").string_value();
      if (result != "valid") {
        continue;
      }
      std::string sig = GetBytesFromHexValue(test_fields.at("sig"));
      absl::StatusOr<std::string> der_encoded =
          EcSignatureIeeeToDer(ec_group->get(), sig);
      ASSERT_THAT(der_encoded, IsOk());
      EXPECT_THAT(EcSignatureDerToIeee(ec_group->get(), *der_encoded),
                  IsOkAndHolds(sig));
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    EcUtilWycheproofTestInstantiation, EcUtilWycheproofTest,
    ValuesIn<WycheproofTest>({
        {"P256", "ecdsa_secp256r1_webcrypto_test.json"},
        {"P384", "ecdsa_secp384r1_webcrypto_test.json"},
        {"P521", "ecdsa_secp521r1_webcrypto_test.json"},
    }),
    [](const TestParamInfo<EcUtilWycheproofTest::ParamType>& info) {
      return info.param.test_name;
    });

// P-256 signature from //third_party/tink/cc/signature/internal/testing.
constexpr absl::string_view kP256DerSignatureHex =
    "3046022100baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276ae1f4b3c63"
    "a2022100d404a3015cb229f7cb036c2b5f77cc546065eed4b75837cec2883d1e35d5eb9f";
constexpr absl::string_view kP256IeeeSignatureHex =
    "baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276ae1f4b3c63a2"
    "d404a3015cb229f7cb036c2b5f77cc546065eed4b75837cec2883d1e35d5eb9f";

TEST(EcUtilTest, EcSignatureDerToIeeeKnownAnswer) {
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  ASSERT_THAT(group, IsOk());
  EXPECT_THAT(EcSignatureDerToIeee(group->get(),
                                   test::HexDecodeOrDie(kP256DerSignatureHex)),
              IsOkAndHolds(test::HexDecodeOrDie(kP256IeeeSignatureHex)));
}

TEST(EcUtilTest, EcSignatureDerToIeeePadsShortIntegers) {
  // r = 1, s = 2 encoded as minimal DER INTEGERs; the IEEE encoding must be
  // zero-padded to the field size.
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  ASSERT_THAT(group, IsOk());
  std::string expected(31, '\0');
  expected.push_back('\x01');
  expected.append(31, '\0');
  expected.push_back('\x02');
  EXPECT_THAT(EcSignatureDerToIeee(group->get(),
                                   test::HexDecodeOrDie("3006020101020102")),
              IsOkAndHolds(expected));
}

TEST(EcUtilTest, EcSignatureDerToIeeeRejectsTrailingBytes) {
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  ASSERT_THAT(group, IsOk());
  EXPECT_THAT(EcSignatureDerToIeee(
                  group->get(),
                  absl::StrCat(test::HexDecodeOrDie(kP256DerSignatureHex), "x"))
                  .status(),
              Not(IsOk()));
}

TEST(EcUtilTest, EcSignatureDerToIeeeRejectsTruncatedInput) {
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  ASSERT_THAT(group, IsOk());
  std::string der = test::HexDecodeOrDie(kP256DerSignatureHex);
  EXPECT_THAT(EcSignatureDerToIeee(group->get(), der.substr(0, der.size() - 1))
                  .status(),
              Not(IsOk()));
  EXPECT_THAT(EcSignatureDerToIeee(group->get(), "").status(), Not(IsOk()));
}

TEST(EcUtilTest, EcSignatureDerToIeeeRejectsNonMinimalInteger) {
  // r is encoded with a superfluous leading zero byte (0x00 0x01), which is
  // not valid DER.
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  ASSERT_THAT(group, IsOk());
  EXPECT_THAT(EcSignatureDerToIeee(group->get(),
                                   test::HexDecodeOrDie("300702020001020102"))
                  .status(),
              Not(IsOk()));
}

using EcKeyFromSslEcKeyTestWithParam =
    testing::TestWithParam<EllipticCurveType>;

TEST_P(EcKeyFromSslEcKeyTestWithParam, EcKeyFromSslEcKeySucceeds) {
  EllipticCurveType curve_type = GetParam();
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(curve_type);
  SslUniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group->get());
  EC_KEY_generate_key(key.get());

  absl::StatusOr<EcKey> ec_key = EcKeyFromSslEcKey(curve_type, *key);

  EXPECT_THAT(ec_key, IsOk());
  EXPECT_THAT(ec_key->curve, Eq(curve_type));
  EXPECT_THAT(ec_key->priv, Not(IsEmpty()));
  EXPECT_THAT(ec_key->pub_x, Not(IsEmpty()));
  EXPECT_THAT(ec_key->pub_y, Not(IsEmpty()));
}

TEST(EcKeyFromSSLEcKeyTest, EcKeyFromSslKeyFailsWrongCurveType) {
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  SslUniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group->get());
  EC_KEY_generate_key(key.get());

  absl::StatusOr<EcKey> ec_key =
      EcKeyFromSslEcKey(EllipticCurveType::NIST_P384, *key);

  EXPECT_THAT(ec_key.status(), StatusIs(absl::StatusCode::kInternal));
}

INSTANTIATE_TEST_SUITE_P(EcKeyFromSslEcKeyTestWithParams,
                         EcKeyFromSslEcKeyTestWithParam,
                         testing::ValuesIn({EllipticCurveType::NIST_P256,
                                            EllipticCurveType::NIST_P384,
                                            EllipticCurveType::NIST_P521}));

// ECDH test vector.
struct EcdhWycheproofTestVector {
  std::string testcase_name;
  EllipticCurveType curve;
  std::string id;
  std::string comment;
  std::string pub_bytes;
  std::string priv_bytes;
  std::string expected_shared_bytes;
  std::string result;
  EcPointFormat format;
};

// Utility function to look for a `value` inside an array of flags `flags`.
bool HasFlag(const google::protobuf::Value& flags, absl::string_view value) {
  if (!flags.has_list_value()) {
    return false;
  }
  for (const google::protobuf::Value& flag : flags.list_value().values()) {
    if (flag.string_value() == value) {
      return true;
    }
  }
  return false;
}

// Reads Wycheproof's ECDH test vectors from the given file `file_name`.
std::vector<EcdhWycheproofTestVector> ReadEcdhWycheproofTestVectors(
    absl::string_view file_name) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1(std::string(file_name));
  ABSL_CHECK_OK(parsed_input.status());
  std::vector<EcdhWycheproofTestVector> test_vectors;
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    const auto& test_group_fields = test_group.struct_value().fields();
    // Tink only supports secp256r1, secp384r1 or secp521r1.
    EllipticCurveType curve =
        GetEllipticCurveTypeFromValue(test_group_fields.at("curve"));
    if (curve == EllipticCurveType::UNKNOWN_CURVE) {
      continue;
    }

    for (const google::protobuf::Value& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      auto test_fields = test.struct_value().fields();
      // Wycheproof's ECDH public key uses ASN encoding while Tink uses X9.62
      // format point encoding. For the purpose of testing, we note the
      // followings:
      //  + The prefix of ASN encoding contains curve name, so we can skip test
      //  vector with "UnnamedCurve".
      //  + The suffix of ASN encoding is X9.62 format point encoding.
      // TODO(quannguyen): Use X9.62 test vectors once it's available.
      if (HasFlag(test_fields.at("flags"), /*value=*/"UnnamedCurve")) {
        continue;
      }
      // Get the format from "flags".
      EcPointFormat format = EcPointFormat::UNCOMPRESSED;
      if (HasFlag(test_fields.at("flags"), /*value=*/"CompressedPoint")) {
        format = EcPointFormat::COMPRESSED;
      }
      // Testcase name is of the form: <file_name_without_extension>_tcid<tcid>.
      std::vector<std::string> file_name_tokens =
          absl::StrSplit(file_name, '.');
      test_vectors.push_back({
          absl::StrCat(file_name_tokens[0], "_tcid",
                       test_fields.at("tcId").number_value()),
          curve,
          absl::StrCat(test_fields["tcId"].number_value()),
          test_fields.at("comment").string_value(),
          GetBytesFromHexValue(test_fields.at("public")),
          GetBytesFromHexValue(test_fields.at("private")),
          GetBytesFromHexValue(test_fields.at("shared")),
          test_fields.at("result").string_value(),
          format,
      });
    }
  }
  return test_vectors;
}

using EcUtilComputeEcdhSharedSecretTest =
    TestWithParam<EcdhWycheproofTestVector>;

TEST_P(EcUtilComputeEcdhSharedSecretTest, ComputeEcdhSharedSecretWycheproof) {
  EcdhWycheproofTestVector params = GetParam();

  absl::StatusOr<int32_t> point_size =
      internal::EcPointEncodingSizeInBytes(params.curve, params.format);
  ASSERT_THAT(point_size, IsOk());
  ABSL_CHECK_GE(*point_size, 0);
  if (static_cast<size_t>(*point_size) > params.pub_bytes.size()) {
    GTEST_SKIP();
  }

  std::string pub_bytes = params.pub_bytes.substr(
      params.pub_bytes.size() - *point_size, *point_size);

  absl::StatusOr<SslUniquePtr<EC_POINT>> pub_key =
      EcPointDecode(params.curve, params.format, pub_bytes);
  if (!pub_key.ok()) {
    // Make sure we didn't fail decoding a valid point, then we can terminate
    // testing;
    ASSERT_NE(params.result, "valid");
    return;
  }

  absl::StatusOr<SslUniquePtr<BIGNUM>> priv_key =
      StringToBignum(params.priv_bytes);
  ASSERT_THAT(priv_key, IsOk());

  absl::StatusOr<SecretData> shared_secret =
      ComputeEcdhSharedSecret(params.curve, priv_key->get(), pub_key->get());

  if (params.result == "invalid") {
    EXPECT_THAT(shared_secret, Not(IsOk()));
  } else {
    EXPECT_THAT(
        shared_secret,
        absl_testing::IsOkAndHolds(EqualsSecretData(
            util::SecretDataFromStringView(params.expected_shared_bytes))));
  }
}

std::vector<EcdhWycheproofTestVector> GetEcUtilComputeEcdhSharedSecretParams() {
  std::vector<EcdhWycheproofTestVector> test_vectors =
      ReadEcdhWycheproofTestVectors(
          /*file_name=*/"ecdh_secp256r1_test.json");
  std::vector<EcdhWycheproofTestVector> others = ReadEcdhWycheproofTestVectors(
      /*file_name=*/"ecdh_secp384r1_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  others = ReadEcdhWycheproofTestVectors(
      /*file_name=*/"ecdh_secp521r1_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  others = ReadEcdhWycheproofTestVectors(
      /*file_name=*/"ecdh_secp256r1_webcrypto_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  others = ReadEcdhWycheproofTestVectors(
      /*file_name=*/"ecdh_secp384r1_webcrypto_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  others = ReadEcdhWycheproofTestVectors(
      /*file_name=*/"ecdh_secp521r1_webcrypto_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  return test_vectors;
}

INSTANTIATE_TEST_SUITE_P(
    EcUtilComputeEcdhSharedSecretTests, EcUtilComputeEcdhSharedSecretTest,
    ValuesIn(GetEcUtilComputeEcdhSharedSecretParams()),
    [](const TestParamInfo<EcUtilComputeEcdhSharedSecretTest::ParamType>&
           info) { return info.param.testcase_name; });

struct PointEncodingTestCase {
  std::string test_name;
  EllipticCurveType curve;
  EcPoint point;
  std::string expected_uncompressed;
  std::string expected_compressed;
};

// Test vector from Project Wycheproof:
// testvectors_v1/ecdh_secp256r1_ecpoint_test.json (tcId: 1 for uncompressed,
// tcId: 2 for compressed).
PointEncodingTestCase GetP256TestCase() {
  std::string x = test::HexDecodeOrDie(
      "62d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26");
  std::string y = test::HexDecodeOrDie(
      "ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf");
  std::string expected_uncompressed = test::HexDecodeOrDie(
      "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26"
      "ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf");
  std::string expected_compressed = test::HexDecodeOrDie(
      "0362d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26");
  return PointEncodingTestCase{
      /*test_name=*/"P256",
      /*curve=*/EllipticCurveType::NIST_P256,
      /*point=*/EcPoint(BigInteger(x), BigInteger(y)),
      /*expected_uncompressed=*/expected_uncompressed,
      /*expected_compressed=*/expected_compressed,
  };
}

// Test vector from Project Wycheproof:
// testvectors_v1/ecdh_secp384r1_ecpoint_test.json (tcId: 1 for uncompressed,
// tcId: 2 for compressed).
PointEncodingTestCase GetP384TestCase() {
  std::string x = test::HexDecodeOrDie(
      "790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f"
      "791b64a6be15969ffa012dd9185d8796");
  std::string y = test::HexDecodeOrDie(
      "d9b954baa8a75e82df711b3b56eadff6b0f668c3b26b4b1aeb308a1fcc1c680d"
      "329a6705025f1c98a0b5e5bfcb163caa");
  std::string expected_uncompressed = test::HexDecodeOrDie(
      "04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f791b64"
      "a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b3b56eadff6b0f668c3"
      "b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163caa");
  std::string expected_compressed = test::HexDecodeOrDie(
      "02790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f"
      "791b64a6be15969ffa012dd9185d8796");
  return PointEncodingTestCase{
      /*test_name=*/"P384",
      /*curve=*/EllipticCurveType::NIST_P384,
      /*point=*/EcPoint(BigInteger(x), BigInteger(y)),
      /*expected_uncompressed=*/expected_uncompressed,
      /*expected_compressed=*/expected_compressed,
  };
}

// Test vector from Project Wycheproof:
// testvectors_v1/ecdh_secp521r1_ecpoint_test.json (tcId: 1 for uncompressed,
// tcId: 2 for compressed).
PointEncodingTestCase GetP521TestCase() {
  std::string x = test::HexDecodeOrDie(
      "0064da3e94733db536a74a0d8a5cb2265a31c54a1da6529a198377fbd38575d9"
      "d79769ca2bdf2d4c972642926d444891a652e7f492337251adf1613cf3077999"
      "b5ce");
  std::string y = test::HexDecodeOrDie(
      "00e04ad19cf9fd4722b0c824c069f70c3c0e7ebc5288940dfa92422152ae4a4f"
      "79183ced375afb54db1409ddf338b85bb6dbfc5950163346bb63a90a70c5aba0"
      "98f7");
  std::string expected_uncompressed = test::HexDecodeOrDie(
      "04"
      "0064da3e94733db536a74a0d8a5cb2265a31c54a1da6529a198377fbd38575d9"
      "d79769ca2bdf2d4c972642926d444891a652e7f492337251adf1613cf3077999"
      "b5ce"
      "00e04ad19cf9fd4722b0c824c069f70c3c0e7ebc5288940dfa92422152ae4a4f"
      "79183ced375afb54db1409ddf338b85bb6dbfc5950163346bb63a90a70c5aba0"
      "98f7");
  std::string expected_compressed = test::HexDecodeOrDie(
      "03"
      "0064da3e94733db536a74a0d8a5cb2265a31c54a1da6529a198377fbd38575d9"
      "d79769ca2bdf2d4c972642926d444891a652e7f492337251adf1613cf3077999"
      "b5ce");
  return PointEncodingTestCase{
      /*test_name=*/"P521",
      /*curve=*/EllipticCurveType::NIST_P521,
      /*point=*/EcPoint(BigInteger(x), BigInteger(y)),
      /*expected_uncompressed=*/expected_uncompressed,
      /*expected_compressed=*/expected_compressed,
  };
}

std::vector<PointEncodingTestCase> GetPointEncodingTestCases() {
  return {GetP256TestCase(), GetP384TestCase(), GetP521TestCase()};
}

using EcUtilPointEncodingTest = TestWithParam<PointEncodingTestCase>;

TEST_P(EcUtilPointEncodingTest, EncodeUncompressed) {
  const PointEncodingTestCase& test = GetParam();
  EXPECT_THAT(EncodeEcPointToString(test.curve, EcPointFormat::UNCOMPRESSED,
                                    test.point),
              IsOkAndHolds(test.expected_uncompressed));
}

TEST_P(EcUtilPointEncodingTest, EncodeCompressed) {
  const PointEncodingTestCase& test = GetParam();
  EXPECT_THAT(
      EncodeEcPointToString(test.curve, EcPointFormat::COMPRESSED, test.point),
      IsOkAndHolds(test.expected_compressed));
}

TEST_P(EcUtilPointEncodingTest, DecodeUncompressed) {
  const PointEncodingTestCase& test = GetParam();
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::UNCOMPRESSED,
                              test.expected_uncompressed),
              IsOkAndHolds(test.point));
}

TEST_P(EcUtilPointEncodingTest, DecodeCompressed) {
  const PointEncodingTestCase& test = GetParam();
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::COMPRESSED,
                              test.expected_compressed),
              IsOkAndHolds(test.point));
}

TEST_P(EcUtilPointEncodingTest, DecodeRejectsWrongPrefix) {
  const PointEncodingTestCase& test = GetParam();

  // Using compressed prefix on uncompressed encoding and vice versa.
  std::string wrong_prefix_uncompressed = test.expected_uncompressed;
  wrong_prefix_uncompressed[0] = test.expected_compressed[0];
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::UNCOMPRESSED,
                              wrong_prefix_uncompressed)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  std::string wrong_prefix_compressed = test.expected_compressed;
  wrong_prefix_compressed[0] = test.expected_uncompressed[0];
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::COMPRESSED,
                              wrong_prefix_compressed)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  wrong_prefix_compressed[0] = '\x05';
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::COMPRESSED,
                              wrong_prefix_compressed)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EcUtilPointEncodingTest, DecodeRejectsWrongLength) {
  const PointEncodingTestCase& test = GetParam();

  // Truncated.
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::UNCOMPRESSED,
                              test.expected_uncompressed.substr(
                                  0, test.expected_uncompressed.size() - 1))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::COMPRESSED,
                              test.expected_compressed.substr(
                                  0, test.expected_compressed.size() - 1))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Extra byte.
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::UNCOMPRESSED,
                              absl::StrCat(test.expected_uncompressed,
                                           absl::string_view("\0", 1)))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(DecodeToEcPoint(test.curve, EcPointFormat::COMPRESSED,
                              absl::StrCat(test.expected_compressed,
                                           absl::string_view("\0", 1)))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Empty string.
  EXPECT_THAT(
      DecodeToEcPoint(test.curve, EcPointFormat::UNCOMPRESSED, "").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EcUtilPointEncodingTest, DecodeRejectsPointNotOnCurve) {
  const PointEncodingTestCase& test = GetParam();

  std::string corrupted = test.expected_uncompressed;
  corrupted.back() ^= 0x01;
  EXPECT_THAT(
      DecodeToEcPoint(test.curve, EcPointFormat::UNCOMPRESSED, corrupted)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EcUtilPointEncodingTest, EncodeRejectsPointNotOnCurve) {
  const PointEncodingTestCase& test = GetParam();

  std::string y(test.point.GetY().GetValue());
  y.back() ^= 0x01;
  EcPoint off_curve(test.point.GetX(), BigInteger(y));
  EXPECT_THAT(
      EncodeEcPointToString(test.curve, EcPointFormat::UNCOMPRESSED, off_curve)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

INSTANTIATE_TEST_SUITE_P(
    EcUtilPointEncodingTests, EcUtilPointEncodingTest,
    ValuesIn(GetPointEncodingTestCases()),
    [](const TestParamInfo<EcUtilPointEncodingTest::ParamType>& info) {
      return info.param.test_name;
    });

TEST(EcUtilPointEncodingTest, CrossCurveMismatchRejectsEncoding) {
  PointEncodingTestCase p256_test = GetP256TestCase();
  // A P-256 point is not on P-384.
  EXPECT_THAT(
      EncodeEcPointToString(EllipticCurveType::NIST_P384,
                            EcPointFormat::UNCOMPRESSED, p256_test.point)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  // A P-256 encoding is not a valid P-384 encoding.
  EXPECT_THAT(
      DecodeToEcPoint(EllipticCurveType::NIST_P384, EcPointFormat::UNCOMPRESSED,
                      p256_test.expected_uncompressed)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcUtilPointEncodingTest, UnsupportedFormatRejects) {
  PointEncodingTestCase p256_test = GetP256TestCase();
  EXPECT_THAT(
      EncodeEcPointToString(EllipticCurveType::NIST_P256,
                            EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                            p256_test.point)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      EncodeEcPointToString(EllipticCurveType::NIST_P256,
                            EcPointFormat::UNKNOWN_FORMAT, p256_test.point)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(DecodeToEcPoint(EllipticCurveType::NIST_P256,
                              EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                              absl::StrCat(p256_test.point.GetX().GetValue(),
                                           p256_test.point.GetY().GetValue()))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(DecodeToEcPoint(EllipticCurveType::NIST_P256,
                              EcPointFormat::UNKNOWN_FORMAT,
                              p256_test.expected_uncompressed)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcUtilPointEncodingTest, UnsupportedCurveRejects) {
  PointEncodingTestCase p256_test = GetP256TestCase();
  EXPECT_THAT(
      EncodeEcPointToString(EllipticCurveType::CURVE25519,
                            EcPointFormat::UNCOMPRESSED, p256_test.point)
          .status(),
      Not(IsOk()));
  EXPECT_THAT(
      EncodeEcPointToString(EllipticCurveType::UNKNOWN_CURVE,
                            EcPointFormat::UNCOMPRESSED, p256_test.point)
          .status(),
      Not(IsOk()));
  EXPECT_THAT(DecodeToEcPoint(EllipticCurveType::CURVE25519,
                              EcPointFormat::UNCOMPRESSED,
                              p256_test.expected_uncompressed)
                  .status(),
              Not(IsOk()));
  EXPECT_THAT(DecodeToEcPoint(EllipticCurveType::UNKNOWN_CURVE,
                              EcPointFormat::UNCOMPRESSED,
                              p256_test.expected_uncompressed)
                  .status(),
              Not(IsOk()));
}

TEST(EcUtilTest, ComputePublicPointSuccess) {
  absl::StatusOr<EcPoint> p256_point = ComputePublicPoint(
      EllipticCurveType::NIST_P256,
      P256SecretValue().GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(p256_point, IsOk());
  EXPECT_THAT(*p256_point, Eq(P256Point()));

  absl::StatusOr<EcPoint> p384_point = ComputePublicPoint(
      EllipticCurveType::NIST_P384,
      P384SecretValue().GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(p384_point, IsOk());
  EXPECT_THAT(*p384_point, Eq(P384Point()));

  absl::StatusOr<EcPoint> p521_point = ComputePublicPoint(
      EllipticCurveType::NIST_P521,
      P521SecretValue().GetSecret(InsecureSecretKeyAccess::Get()));
  ASSERT_THAT(p521_point, IsOk());
  EXPECT_THAT(*p521_point, Eq(P521Point()));
}

TEST(EcUtilTest, ComputePublicPointZeroScalarFails) {
  EXPECT_THAT(
      ComputePublicPoint(EllipticCurveType::NIST_P256, std::string(32, '\0')),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcUtilTest, ComputePublicPointOrderScalarFails) {
  // NIST P-256 group order n
  std::string order_bytes;
  ASSERT_TRUE(absl::HexStringToBytes(
      "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
      &order_bytes));
  EXPECT_THAT(ComputePublicPoint(EllipticCurveType::NIST_P256, order_bytes),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcUtilTest, ComputePublicPointInvalidCurveFails) {
  EXPECT_THAT(ComputePublicPoint(EllipticCurveType::UNKNOWN_CURVE, "scalar"),
              StatusIs(absl::StatusCode::kUnimplemented));
  EXPECT_THAT(ComputePublicPoint(EllipticCurveType::CURVE25519, "scalar"),
              StatusIs(absl::StatusCode::kUnimplemented));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
