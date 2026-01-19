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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_validator.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::testing::Not;

TEST(JwtValidator, ExpiredTokenNotOK) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, NotExpiredTokenOK) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, TokenWithExpEqualToNowIsExpired) {
  absl::Time now = absl::FromUnixSeconds(12345);
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder().SetExpiration(now).Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetFixedNow(now).Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, ClockSkewIsToLarge) {
  EXPECT_THAT(JwtValidatorBuilder().SetClockSkew(absl::Minutes(11)).Build(),
              Not(IsOk()));
}

TEST(JwtValidator, RecentlyExpiredTokenWithClockSkewOK) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetClockSkew(absl::Seconds(200)).Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheFutureNotOK) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now + absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, NotBeforeInThePastOK) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now - absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, TokenWithNotBeforeEqualToNowIsValid) {
  absl::Time now = absl::FromUnixSeconds(12345);
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetNotBefore(now).WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetFixedNow(now).AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheNearFutureWithClockSkewOK) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now + absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .AllowMissingExpiration()
                                               .SetClockSkew(absl::Seconds(200))
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, IssuedAt) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> tokenIssuedInTheFuture =
      RawJwtBuilder()
          .SetIssuedAt(now + absl::Seconds(100))
          .WithoutExpiration()
          .Build();
  ASSERT_THAT(tokenIssuedInTheFuture, IsOk());
  absl::StatusOr<RawJwt> tokenIssuedInThePast =
      RawJwtBuilder()
          .SetIssuedAt(now - absl::Seconds(100))
          .WithoutExpiration()
          .Build();
  ASSERT_THAT(tokenIssuedInThePast, IsOk());
  absl::StatusOr<RawJwt> tokenWithoutIssuedAt =
      RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(tokenWithoutIssuedAt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*tokenIssuedInTheFuture), IsOk());
  EXPECT_THAT(validator->Validate(*tokenIssuedInThePast), IsOk());
  EXPECT_THAT(validator->Validate(*tokenWithoutIssuedAt), IsOk());

  absl::StatusOr<JwtValidator> issued_at_validator =
      JwtValidatorBuilder()
          .ExpectIssuedInThePast()
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(issued_at_validator, IsOk());
  EXPECT_THAT(issued_at_validator->Validate(*tokenIssuedInTheFuture),
              Not(IsOk()));
  EXPECT_THAT(issued_at_validator->Validate(*tokenIssuedInThePast), IsOk());
  EXPECT_THAT(issued_at_validator->Validate(*tokenWithoutIssuedAt),
              Not(IsOk()));
}

TEST(JwtValidator, IssuedAtWithClockSkew) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> tokenOneMinuteInTheFuture =
      RawJwtBuilder()
          .SetIssuedAt(now + absl::Minutes(1))
          .WithoutExpiration()
          .Build();
  ASSERT_THAT(tokenOneMinuteInTheFuture, IsOk());

  absl::StatusOr<JwtValidator> validator_without_clock_skew =
      JwtValidatorBuilder()
          .ExpectIssuedInThePast()
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator_without_clock_skew, IsOk());
  EXPECT_THAT(
      validator_without_clock_skew->Validate(*tokenOneMinuteInTheFuture),
      Not(IsOk()));

  absl::StatusOr<JwtValidator> validator_with_clock_skew =
      JwtValidatorBuilder()
          .ExpectIssuedInThePast()
          .AllowMissingExpiration()
          .SetClockSkew(absl::Minutes(2))
          .Build();
  ASSERT_THAT(validator_with_clock_skew, IsOk());
  EXPECT_THAT(validator_with_clock_skew->Validate(*tokenOneMinuteInTheFuture),
              IsOk());
}

TEST(JwtValidator, RequiresTypeHeaderButNotTypHeaderNotOK) {
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, InvalidTypeHeaderNotOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("JWT")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, CorrectTypeHeaderOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, TypeHeaderInTokenButNotInValiatorNotOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, IgnoreTypeHeaderOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().IgnoreTypeHeader().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, RequiresIssuerButNotIssuerNotOK) {
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, InvalidIssuerNotOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, CorrectIssuerOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, IssuerInTokenButNotInValiatorNotOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, IgnoreIssuerOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().IgnoreIssuer().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, RequiresAudienceButNotAudienceNotOK) {
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectAudience("audience")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, InvalidAudienceNotOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetSubject("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectAudience("audience")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, CorrectAudienceOK) {
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .AddAudience("otherAudience")
                                   .AddAudience("audience")
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectAudience("audience")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, AudienceInTokenButNotInValiatorNotOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().AddAudience("audience").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, NoAudienceOK) {
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, IgnoreAudiencesOK) {
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().AddAudience("audience").WithoutExpiration().Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().IgnoreAudiences().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, FixedNowExpiredNotOk) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder()
          .SetFixedNow(now + absl::Seconds(200))
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, FixedNowNotYetValidNotOk) {
  absl::Time now = absl::Now();
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now - absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder()
          .SetFixedNow(now - absl::Seconds(200))
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), Not(IsOk()));
}

TEST(JwtValidator, FixedNowValidOk) {
  absl::Time now = absl::FromUnixSeconds(12345);
  absl::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetExpiration(now + absl::Seconds(100))
                                   .SetNotBefore(now - absl::Seconds(100))
                                   .Build();
  ASSERT_THAT(jwt, IsOk());

  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetFixedNow(now).Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, CallBuildTwiceOk) {
  JwtValidatorBuilder builder = JwtValidatorBuilder().AllowMissingExpiration();

  builder.ExpectIssuer("issuer1");
  absl::StatusOr<JwtValidator> validator1 = builder.Build();
  ASSERT_THAT(validator1, IsOk());

  builder.ExpectIssuer("issuer2");
  absl::StatusOr<JwtValidator> validator2 = builder.Build();
  ASSERT_THAT(validator2, IsOk());

  absl::StatusOr<RawJwt> jwt1 =
      RawJwtBuilder().SetIssuer("issuer1").WithoutExpiration().Build();
  ASSERT_THAT(jwt1, IsOk());
  absl::StatusOr<RawJwt> jwt2 =
      RawJwtBuilder().SetIssuer("issuer2").WithoutExpiration().Build();
  ASSERT_THAT(jwt2, IsOk());

  EXPECT_THAT(validator1->Validate(*jwt1), IsOk());
  EXPECT_THAT(validator1->Validate(*jwt2), Not(IsOk()));
  EXPECT_THAT(validator2->Validate(*jwt2), IsOk());
  EXPECT_THAT(validator2->Validate(*jwt1), Not(IsOk()));
}

TEST(JwtValidator, InvalidValidators) {
  EXPECT_THAT(JwtValidatorBuilder()
                  .ExpectTypeHeader("a")
                  .IgnoreTypeHeader()
                  .AllowMissingExpiration()
                  .Build(),
              Not(IsOk()));
  EXPECT_THAT(JwtValidatorBuilder()
                  .ExpectIssuer("a")
                  .IgnoreIssuer()
                  .AllowMissingExpiration()
                  .Build(),
              Not(IsOk()));
  EXPECT_THAT(JwtValidatorBuilder()
                  .ExpectAudience("a")
                  .IgnoreAudiences()
                  .AllowMissingExpiration()
                  .Build(),
              Not(IsOk()));
}

}  // namespace tink
}  // namespace crypto
