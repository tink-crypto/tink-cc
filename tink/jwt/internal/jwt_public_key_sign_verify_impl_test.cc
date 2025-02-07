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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "tink/internal/ec_util.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/internal/jwt_public_key_verify_impl.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::Not;

TEST(JwtSignatureImplTest, CreateAndValidateToken) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt_or =
      RawJwtBuilder()
          .SetTypeHeader("typeHeader")
          .SetJwtId("id123")
          .SetNotBefore(now - absl::Seconds(300))
          .SetIssuedAt(now)
          .SetExpiration(now + absl::Seconds(300))
          .Build();
  ASSERT_THAT(raw_jwt_or, IsOk());
  RawJwt raw_jwt = raw_jwt_or.value();

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
      subtle::EcdsaSignBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign =
      JwtPublicKeySignImpl::Raw(*std::move(sign), "ES256");

  util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
      subtle::EcdsaVerifyBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(verify, IsOk());
  std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
      JwtPublicKeyVerifyImpl::Raw(*std::move(verify), "ES256");

  util::StatusOr<std::string> compact =
      jwt_sign->SignAndEncodeWithKid(raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator, IsOk());

  // Success
  util::StatusOr<VerifiedJwt> verified_jwt =
      jwt_verify->VerifyAndDecodeWithKid(*compact, *validator,
                                         /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  // Fails because kid header is not present
  EXPECT_THAT(
      jwt_verify->VerifyAndDecodeWithKid(*compact, *validator, "kid-123")
          .status(),
      Not(IsOk()));

  // Fails with wrong issuer
  util::StatusOr<JwtValidator> validator2 =
      JwtValidatorBuilder().ExpectIssuer("unknown").Build();
  ASSERT_THAT(validator2, IsOk());
  EXPECT_THAT(jwt_verify->VerifyAndDecodeWithKid(*compact, *validator2,
                                                 /*kid=*/absl::nullopt),
              Not(IsOk()));

  // Fails because token is not yet valid
  util::StatusOr<JwtValidator> validator_1970 =
      JwtValidatorBuilder().SetFixedNow(absl::FromUnixSeconds(12345)).Build();
  ASSERT_THAT(validator_1970, IsOk());
  EXPECT_THAT(jwt_verify->VerifyAndDecodeWithKid(*compact, *validator_1970,
                                                 /*kid=*/absl::nullopt),
              Not(IsOk()));
}

TEST(JwtSignatureImplTest, CreateAndValidateTokenWithKid) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
      subtle::EcdsaSignBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign =
      JwtPublicKeySignImpl::Raw(*std::move(sign), "ES256");

  util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
      subtle::EcdsaVerifyBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(verify, IsOk());
  std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
      JwtPublicKeyVerifyImpl::Raw(*std::move(verify), "ES256");

  util::StatusOr<std::string> compact =
      jwt_sign->SignAndEncodeWithKid(*raw_jwt, "kid-123");
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();

  util::StatusOr<VerifiedJwt> verified_jwt =
      jwt_verify->VerifyAndDecodeWithKid(*compact, *validator, "kid-123");
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  // Kid header in the token is ignored.
  EXPECT_THAT(
      jwt_verify
          ->VerifyAndDecodeWithKid(*compact, *validator, /*kid=*/absl::nullopt)
          .status(),
      IsOk());

  // parse header to make sure the kid value is set correctly.
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header, IsOk());
  EXPECT_THAT(header->fields().find("kid")->second.string_value(),
              Eq("kid-123"));
}

TEST(JwtSignatureImplTest, SignAndEncodeWithKidFailsWithWrongKid) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  std::string kid = "01020304";
  util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
      subtle::EcdsaSignBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign =
      JwtPublicKeySignImpl::WithKid(*std::move(sign), "ES256", kid);
  EXPECT_THAT(jwt_sign->SignAndEncodeWithKid(*raw_jwt, /*kid=*/"05060708"),
              Not(IsOk()));
  EXPECT_THAT(jwt_sign->SignAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt),
              Not(IsOk()));
}

TEST(JwtSignatureImplTest, SignAndEncodeWithKidFailsIfCustomKidIsPresent) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  std::string kid = "01020304";
  util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
      subtle::EcdsaSignBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign =
      JwtPublicKeySignImpl::RawWithCustomKid(*std::move(sign), "ES256", kid);
  EXPECT_THAT(jwt_sign->SignAndEncodeWithKid(*raw_jwt, /*kid=*/"05060708"),
              Not(IsOk()));
}

TEST(JwtSignatureImplTest, SignerWithKidAndValidate) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  std::string kid = "01020304";
  util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
      subtle::EcdsaSignBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(sign, IsOk());
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign =
      JwtPublicKeySignImpl::WithKid(*std::move(sign), "ES256", kid);

  util::StatusOr<std::string> compact =
      jwt_sign->SignAndEncodeWithKid(*raw_jwt, kid);
  ASSERT_THAT(compact, IsOk());

  // Parse header to make sure the kid value is set correctly.
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header, IsOk());
  EXPECT_THAT(header->fields().find("kid")->second.string_value(), Eq(kid));

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();

  {
    // RAW verifier.
    util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
        subtle::EcdsaVerifyBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verify, IsOk());
    std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
        JwtPublicKeyVerifyImpl::Raw(*std::move(verify), "ES256");

    util::StatusOr<VerifiedJwt> verified_jwt =
        jwt_verify->VerifyAndDecodeWithKid(*compact, *validator, kid);
    ASSERT_THAT(verified_jwt, IsOk());
    EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
    EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

    // Kid header in the token is ignored.
    EXPECT_THAT(jwt_verify
                    ->VerifyAndDecodeWithKid(*compact, *validator,
                                             /*kid=*/absl::nullopt)
                    .status(),
                IsOk());
    // A wrong kid makes the verification fail.
    EXPECT_THAT(
        jwt_verify
            ->VerifyAndDecodeWithKid(*compact, *validator, /*kid=*/"wrong-kid")
            .status(),
        Not(IsOk()));
  }
  {
    // Verifier with kid.
    util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
        subtle::EcdsaVerifyBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verify, IsOk());
    std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
        JwtPublicKeyVerifyImpl::WithKid(*std::move(verify), "ES256", kid);

    util::StatusOr<VerifiedJwt> verified_jwt =
        jwt_verify->VerifyAndDecodeWithKid(*compact, *validator, kid);
    ASSERT_THAT(verified_jwt, IsOk());
    EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
    EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

    // Kid must be specified.
    EXPECT_THAT(jwt_verify
                    ->VerifyAndDecodeWithKid(*compact, *validator,
                                             /*kid=*/absl::nullopt)
                    .status(),
                Not(IsOk()));
    // A wrong kid makes the verification fail.
    EXPECT_THAT(
        jwt_verify
            ->VerifyAndDecodeWithKid(*compact, *validator, /*kid=*/"wrong-kid")
            .status(),
        Not(IsOk()));
  }
  {
    // Raw verifier with custom kid.
    util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
        subtle::EcdsaVerifyBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verify, IsOk());
    std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
        JwtPublicKeyVerifyImpl::RawWithCustomKid(*std::move(verify), "ES256",
                                                 kid);

    // Must not specify a kid.
    EXPECT_THAT(jwt_verify->VerifyAndDecodeWithKid(*compact, *validator, kid),
                Not(IsOk()));

    util::StatusOr<VerifiedJwt> verified_jwt =
        jwt_verify->VerifyAndDecodeWithKid(*compact, *validator,
                                           /*kid=*/absl::nullopt);
    ASSERT_THAT(verified_jwt, IsOk());
    EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
    EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));
  }
}

TEST(JwtSignatureImplTest, SignerWithCustomKidAndValidate) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  std::string custom_kid = "01020304";
  util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
      subtle::EcdsaSignBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(sign, IsOk());
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign =
      JwtPublicKeySignImpl::RawWithCustomKid(*std::move(sign), "ES256",
                                             custom_kid);

  util::StatusOr<std::string> compact =
      jwt_sign->SignAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact, IsOk());
  // Parse header to make sure the kid value is set correctly.
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header, IsOk());
  EXPECT_THAT(header->fields().find("kid")->second.string_value(),
              Eq(custom_kid));

  {
    // Verify with a RAW verifier works.
    util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
        subtle::EcdsaVerifyBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verify, IsOk());
    std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
        JwtPublicKeyVerifyImpl::Raw(*std::move(verify), "ES256");

    util::StatusOr<JwtValidator> validator =
        JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();

    // Kid header in the token is ignored.
    util::StatusOr<VerifiedJwt> verified_jwt =
        jwt_verify->VerifyAndDecodeWithKid(*compact, *validator,
                                           /*kid=*/absl::nullopt);
    ASSERT_THAT(verified_jwt, IsOk());
    EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
    EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));
  }
  {
    // Verify with a verifier with custom kid works.
    util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
        subtle::EcdsaVerifyBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verify, IsOk());
    std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
        JwtPublicKeyVerifyImpl::RawWithCustomKid(*std::move(verify), "ES256",
                                                 custom_kid);

    util::StatusOr<JwtValidator> validator =
        JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();

    util::StatusOr<VerifiedJwt> verified_jwt =
        jwt_verify->VerifyAndDecodeWithKid(*compact, *validator,
                                           /*kid=*/absl::nullopt);
    ASSERT_THAT(verified_jwt, IsOk());
    EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
    EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));
    // Specifying a kid makes the verification fail.
    EXPECT_THAT(
        jwt_verify->VerifyAndDecodeWithKid(*compact, *validator, custom_kid),
        Not(IsOk()));
  }
  {
    // Verify with a verifier with different custom kid fails.
    util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
        subtle::EcdsaVerifyBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verify, IsOk());
    std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
        JwtPublicKeyVerifyImpl::RawWithCustomKid(
            *std::move(verify), "ES256",
            /*custom_kid=*/"another-custom-kid");

    util::StatusOr<JwtValidator> validator =
        JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();

    EXPECT_THAT(jwt_verify->VerifyAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                Not(IsOk()));
  }
}

TEST(JwtSignatureImplTest, FailsWithModifiedCompact) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetJwtId("id123").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
      subtle::EcdsaSignBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign =
      JwtPublicKeySignImpl::Raw(*std::move(sign), "ES256");

  util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
      subtle::EcdsaVerifyBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(verify, IsOk());
  std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
      JwtPublicKeyVerifyImpl::Raw(*std::move(verify), "ES256");

  util::StatusOr<std::string> compact =
      jwt_sign->SignAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact, IsOk());
  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());

  EXPECT_THAT(
      jwt_verify
          ->VerifyAndDecodeWithKid(*compact, *validator, /*kid=*/absl::nullopt)
          .status(),
      IsOk());
  EXPECT_FALSE(jwt_verify
                   ->VerifyAndDecodeWithKid(absl::StrCat(*compact, "x"),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify
                   ->VerifyAndDecodeWithKid(absl::StrCat(*compact, " "),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify
                   ->VerifyAndDecodeWithKid(absl::StrCat("x", *compact),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify
                   ->VerifyAndDecodeWithKid(absl::StrCat(" ", *compact),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
}

TEST(JwtSignatureImplTest, FailsWithInvalidTokens) {
  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
      subtle::EcdsaVerifyBoringSsl::New(
          *ec_key, subtle::HashType::SHA256,
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(verify, IsOk());
  std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify =
      JwtPublicKeyVerifyImpl::Raw(*std::move(verify), "ES256");

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(
      jwt_verify->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.YWJj.",
                                         *validator, /*kid=*/absl::nullopt),
      Not(IsOk()));
  EXPECT_THAT(
      jwt_verify->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9?.e30.YWJj",
                                         *validator, /*kid=*/absl::nullopt),
      Not(IsOk()));
  EXPECT_THAT(
      jwt_verify->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30?.YWJj",
                                         *validator, /*kid=*/absl::nullopt),
      Not(IsOk()));
  EXPECT_THAT(
      jwt_verify->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.YWJj?",
                                         *validator, /*kid=*/absl::nullopt),
      Not(IsOk()));
  EXPECT_THAT(jwt_verify->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.YWJj",
                                                 *validator,
                                                 /*kid=*/absl::nullopt),
              Not(IsOk()));
  EXPECT_THAT(
      jwt_verify->VerifyAndDecodeWithKid("", *validator, /*kid=*/absl::nullopt),
      Not(IsOk()));
  EXPECT_THAT(jwt_verify->VerifyAndDecodeWithKid("..", *validator,
                                                 /*kid=*/absl::nullopt)

                  ,
              Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
