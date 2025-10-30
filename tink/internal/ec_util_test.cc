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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
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
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::
    GetEllipticCurveTypeFromValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectors;
using ::crypto::tink::subtle::EcPointFormat;
using ::crypto::tink::subtle::EllipticCurveType;
using ::crypto::tink::test::EqualsSecretData;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
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

// Use wycheproof test vectors to verify Ed25519 key generation from a seed (the
// private key) results in the public/private key.
TEST(EcUtilTest, NewEd25519KeyWithWycheproofTestVectors) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectors("eddsa_test.json");
  ASSERT_THAT(parsed_input, IsOk());

  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");

  // For this test we are only interested in Ed25519 keys.
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    const google::protobuf::Value& key_value =
        test_group.struct_value().fields().at("key");
    SecretData private_key = util::SecretDataFromStringView(
        GetBytesFromHexValue(key_value.struct_value().fields().at("sk")));
    std::string public_key =
        GetBytesFromHexValue(key_value.struct_value().fields().at("pk"));

    absl::StatusOr<std::unique_ptr<Ed25519Key>> key =
        NewEd25519Key(private_key);
    ASSERT_THAT(key, IsOk());
    EXPECT_EQ((*key)->public_key, public_key);
    EXPECT_TRUE(util::SecretDataEquals((*key)->private_key, private_key));
  }
}

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

  EXPECT_THAT(ComputeX25519SharedSecret(ssl_priv_key.get(), ssl_pub_key.get()),
              IsOkAndHolds(EqualsSecretData(util::SecretDataFromStringView(
                  test_vector.expected_shared_secret))));
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

TEST(EcUtilTest, EcSignatureIeeeToDer) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectors("ecdsa_webcrypto_test.json");
  ASSERT_THAT(parsed_input, IsOk());
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    EllipticCurveType curve = GetEllipticCurveTypeFromValue(
        test_group.struct_value().fields().at("key").struct_value().fields().at(
            "curve"));
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
      const uint8_t* der_sig_data_ptr =
          reinterpret_cast<const uint8_t*>(der_encoded->data());
      SslUniquePtr<ECDSA_SIG> ecdsa_sig(d2i_ECDSA_SIG(
          /*out=*/nullptr, &der_sig_data_ptr, der_encoded->size()));
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
      ReadTestVectors(std::string(file_name));
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
  if (*point_size > params.pub_bytes.size()) {
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
    EXPECT_THAT(shared_secret,
                IsOkAndHolds(EqualsSecretData(util::SecretDataFromStringView(
                    params.expected_shared_bytes))));
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
      /*file_name=*/"ecdh_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  return test_vectors;
}

INSTANTIATE_TEST_SUITE_P(
    EcUtilComputeEcdhSharedSecretTests, EcUtilComputeEcdhSharedSecretTest,
    ValuesIn(GetEcUtilComputeEcdhSharedSecretParams()),
    [](const TestParamInfo<EcUtilComputeEcdhSharedSecretTest::ParamType>&
           info) { return info.param.testcase_name; });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
