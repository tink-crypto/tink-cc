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

#include "tink/jwt/internal/jwt_mac_impl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::Not;

namespace crypto {
namespace tink {
namespace jwt_internal {

namespace {

util::StatusOr<std::unique_ptr<JwtMacInternal>> CreateJwtMac() {
  std::string key_value;
  if (!absl::WebSafeBase64Unescape(
          "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1"
          "qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          &key_value)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "failed to parse key");
  }
  crypto::tink::util::StatusOr<std::unique_ptr<Mac>> mac =
      subtle::HmacBoringSsl::New(
          util::Enums::ProtoToSubtle(google::crypto::tink::HashType::SHA256),
          32, util::SecretDataFromStringView(key_value));
  if (!mac.ok()) {
    return mac.status();
  }
  std::unique_ptr<JwtMacInternal> jwt_mac =
      JwtMacImpl::Raw(*std::move(mac), "HS256");
  return std::move(jwt_mac);
}

TEST(JwtMacImplTest, CreateAndValidateToken) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac, IsOk());

  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  EXPECT_TRUE(raw_jwt->HasTypeHeader());
  EXPECT_THAT(raw_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator, IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(*compact, *validator,
                                            /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  util::StatusOr<JwtValidator> validator2 =
      JwtValidatorBuilder().ExpectIssuer("unknown").Build();
  ASSERT_THAT(validator2, IsOk());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid(*compact, *validator2,
                                               /*kid=*/absl::nullopt)
                   .ok());
}

TEST(JwtMacImplTest, CreateAndValidateTokenWithKid) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac, IsOk());

  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  EXPECT_TRUE(raw_jwt->HasTypeHeader());
  EXPECT_THAT(raw_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, "kid-123");
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator, IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(*compact, *validator,
                                            /*kid=*/"kid-123");
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  // with kid=absl::nullopt, the kid header in the token is ignored.
  EXPECT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*compact, *validator,
                                              /*kid=*/absl::nullopt)
                  .status(),
              IsOk());

  // with a different kid, the verification fails.
  EXPECT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*compact, *validator,
                                              /*kid=*/"other-kid")
                  .status(),
              Not(IsOk()));

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

TEST(JwtMacImplTest, ValidateFixedToken) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac, IsOk());

  // token that expired in 2011
  std::string compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  util::StatusOr<JwtValidator> validator_1970 =
      JwtValidatorBuilder()
          .ExpectTypeHeader("JWT")
          .ExpectIssuer("joe")
          .SetFixedNow(absl::FromUnixSeconds(12345))
          .Build();
  ASSERT_THAT(validator_1970, IsOk());

  // verification succeeds because token was valid 1970
  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(compact, *validator_1970,
                                            /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("joe"));
  EXPECT_THAT(verified_jwt->GetBooleanClaim("http://example.com/is_root"),
              IsOkAndHolds(true));

  // verification fails because token is expired
  util::StatusOr<JwtValidator> validator_now = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_now, IsOk());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid(compact, *validator_now,
                                               /*kid=*/absl::nullopt)
                   .ok());

  // verification fails because token was modified
  std::string modified_compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXi";
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid(
                       modified_compact, *validator_1970, /*kid=*/absl::nullopt)
                   .ok());
}

TEST(JwtMacImplTest, ValidateInvalidTokens) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac, IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator, IsOk());

  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.abc.",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9?.e30.abc",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30?.abc",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.abc?",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
}

TEST(JwtMacImplWithKidTest, ComputeFailsWithWrongKid) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  auto key = subtle::Random::GetRandomKeyBytes(32);
  std::string kid = "01020304";
  util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      subtle::HashType::SHA256, /*tag_size=*/32, key);

  std::unique_ptr<JwtMacInternal> jwt_mac =
      JwtMacImpl::WithKid(*std::move(mac), "HS256", kid);
  EXPECT_THAT(jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/"05060708"),
              Not(IsOk()));
  EXPECT_THAT(
      jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt),
      Not(IsOk()));
}

TEST(JwtMacImplWithKidTest, Verify) {
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  auto key = subtle::Random::GetRandomKeyBytes(32);
  std::string kid = "01020304";
  util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      subtle::HashType::SHA256, /*tag_size=*/32, key);
  ASSERT_THAT(mac, IsOk());
  std::unique_ptr<JwtMacInternal> jwt_mac =
      JwtMacImpl::WithKid(*std::move(mac), "HS256", kid);
  util::StatusOr<std::string> compact =
      jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, kid);
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  {
    // RAW.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::Raw(*std::move(mac), "HS256");
    // KID is ignored with a RAW verifier.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                IsOk());
    // Correct KID works.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, kid),
                IsOk());
    // A wrong KID makes the verification fail.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
  {
    // WithKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::WithKid(*std::move(mac), "HS256", kid);
    // KID must be specified.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, kid),
                IsOk());
    // No KID makes the verification fail.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                Not(IsOk()));
    // A wrong KID makes the verification fail.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
  {
    // WithCustomKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::RawWithCustomKid(*std::move(mac), "HS256", "custom-kid");
    // Specifying a KID makes the verification fail because the key must be RAW.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, kid),
                Not(IsOk()));
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                Not(IsOk()));
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
}

TEST(JwtMacImplRawTest, VerifyTokenWithKid) {
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  auto key = subtle::Random::GetRandomKeyBytes(32);
  std::string kid = "01020304";
  util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      subtle::HashType::SHA256, /*tag_size=*/32, key);
  ASSERT_THAT(mac, IsOk());
  std::unique_ptr<JwtMacInternal> jwt_mac =
      JwtMacImpl::Raw(*std::move(mac), "HS256");
  util::StatusOr<std::string> compact =
      jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, kid);
  ASSERT_THAT(compact, IsOk());
  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  {
    // RAW.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::Raw(*std::move(mac), "HS256");
    // KID is ignored with a RAW verifier.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                IsOk());
    // Correct KID works.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, kid),
                IsOk());
    // A wrong KID makes the verification fail.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
  {
    // WithKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::WithKid(*std::move(mac), "HS256", kid);
    // KID must be specified.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, kid),
                IsOk());
    // No KID makes the verification fail.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                Not(IsOk()));
    // A wrong KID makes the verification fail.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
  {
    // WithCustomKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::RawWithCustomKid(*std::move(mac), "HS256", "custom-kid");
    // All combinations fail because the key must be RAW.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, kid),
                Not(IsOk()));
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                Not(IsOk()));
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
}

TEST(JwtMacImplRawTest, VerifyRawToken) {
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  auto key = subtle::Random::GetRandomKeyBytes(32);
  util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      subtle::HashType::SHA256, /*tag_size=*/32, key);
  ASSERT_THAT(mac, IsOk());
  std::unique_ptr<JwtMacInternal> jwt_mac =
      JwtMacImpl::Raw(*std::move(mac), "HS256");
  util::StatusOr<std::string> compact =
      jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact, IsOk());
  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  {
    // RAW.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::Raw(*std::move(mac), "HS256");
    // No KID is OK.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                IsOk());
    // Any KID fails.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "kid"),
                Not(IsOk()));
  }
  {
    // WithKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::WithKid(*std::move(mac), "HS256", "kid");
    // All combinations fail.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "kid"),
                Not(IsOk()));
    // Fails because no KID is specified.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                Not(IsOk()));
    // Fails because KID is wrong.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
  {
    // WithCustomKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::RawWithCustomKid(*std::move(mac), "HS256", "custom-kid");
    // No KID is OK.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                IsOk());
    // Specifying any KID fails.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "custom-kid"),
        Not(IsOk()));
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
}

TEST(JwtMacImplRawWithCustomKidTest, ComputeFailsWithAnyKid) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  auto key = subtle::Random::GetRandomKeyBytes(32);
  std::string kid = "01020304";
  util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      subtle::HashType::SHA256, /*tag_size=*/32, key);

  std::unique_ptr<JwtMacInternal> jwt_mac =
      JwtMacImpl::RawWithCustomKid(*std::move(mac), "HS256", kid);
  // Using any KID fails.
  EXPECT_THAT(jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/"05060708"),
              Not(IsOk()));
  EXPECT_THAT(jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/"01020304"),
              Not(IsOk()));
}

TEST(JwtMacImplRawWithCustomKidTest, Verify) {
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());
  auto key = subtle::Random::GetRandomKeyBytes(32);
  util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      subtle::HashType::SHA256, /*tag_size=*/32, key);
  ASSERT_THAT(mac, IsOk());
  std::unique_ptr<JwtMacInternal> jwt_mac = JwtMacImpl::RawWithCustomKid(
      *std::move(mac), "HS256", /*custom_kid=*/"custom-kid");
  util::StatusOr<std::string> compact =
      jwt_mac->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact, IsOk());
  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  {
    // RAW.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::Raw(*std::move(mac), "HS256");
    // No KID is OK.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                IsOk());
    // Any KID fails.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "kid"),
                Not(IsOk()));
  }
  {
    // WithKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac =
        JwtMacImpl::WithKid(*std::move(mac), "HS256", "kid");
    // All combinations fail.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "kid"),
                Not(IsOk()));
    // Fails because no KID is specified.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                Not(IsOk()));
    // Fails because KID is wrong.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
  {
    // WithCustomKid.
    util::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
        subtle::HashType::SHA256, /*tag_size=*/32, key);
    ASSERT_THAT(mac, IsOk());
    std::unique_ptr<JwtMacInternal> jwt_mac = JwtMacImpl::RawWithCustomKid(
        *std::move(mac), "HS256", /*custom_kid=*/"custom-kid");
    // No KID is OK.
    EXPECT_THAT(jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator,
                                                   /*kid=*/absl::nullopt),
                IsOk());
    // Specifying any KID fails.
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "custom-kid"),
        Not(IsOk()));
    EXPECT_THAT(
        jwt_mac->VerifyMacAndDecodeWithKid(*compact, *validator, "wrong-kid"),
        Not(IsOk()));
  }
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
