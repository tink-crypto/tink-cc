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
////////////////////////////////////////////////////////////////////////////////

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/jwt/internal/jwt_ml_dsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ml_dsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/jwt_public_key_verify_internal.h"
#include "tink/jwt/jwt_ml_dsa_proto_serialization.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/key_manager.h"
#include "proto/jwt_ml_dsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;

TEST(JwtMlDsaSignKeyManagerTest, Basic) {
  std::unique_ptr<KeyManager<JwtPublicKeySignInternal>> key_manager =
      MakeJwtMlDsaSignKeyManager();

  EXPECT_THAT(key_manager->get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey"));
  EXPECT_THAT(key_manager->get_version(), Eq(0));
  EXPECT_THAT(key_manager->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey"),
              IsTrue());
  EXPECT_THAT(key_manager->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"),
              IsFalse());
}

TEST(JwtMlDsaVerifyKeyManagerTest, Basic) {
  std::unique_ptr<KeyManager<JwtPublicKeyVerifyInternal>> key_manager =
      MakeJwtMlDsaVerifyKeyManager();

  EXPECT_THAT(key_manager->get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey"));
  EXPECT_THAT(key_manager->get_version(), Eq(0));
  EXPECT_THAT(key_manager->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey"),
              IsTrue());
  EXPECT_THAT(key_manager->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"),
              IsFalse());
}

TEST(JwtMlDsaSignVerifyKeyManagerTest, GetPrimitive) {
  ASSERT_THAT(RegisterJwtMlDsaProtoSerialization(), IsOk());

  google::crypto::tink::JwtMlDsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(google::crypto::tink::JwtMlDsaAlgorithm::ML_DSA44);
  std::unique_ptr<KeyManager<JwtPublicKeySignInternal>> sign_key_manager =
      MakeJwtMlDsaSignKeyManager();
  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> private_key =
      sign_key_manager->get_key_factory().NewKey(format);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<crypto::tink::JwtPublicKeySignInternal>>
      signer = sign_key_manager->GetPrimitive(**private_key);
  ASSERT_THAT(signer, IsOk());

  const google::crypto::tink::JwtMlDsaPrivateKey* jwt_ml_dsa_private_key =
      dynamic_cast<const google::crypto::tink::JwtMlDsaPrivateKey*>(
          private_key->get());
  ASSERT_THAT(jwt_ml_dsa_private_key, NotNull());
  ASSERT_THAT(jwt_ml_dsa_private_key->has_public_key(), IsTrue());

  std::unique_ptr<KeyManager<JwtPublicKeyVerifyInternal>> verify_key_manager =
      MakeJwtMlDsaVerifyKeyManager();

  absl::StatusOr<std::unique_ptr<crypto::tink::JwtPublicKeyVerifyInternal>>
      verifier = verify_key_manager->GetPrimitive(
          jwt_ml_dsa_private_key->public_key());
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact =
      (*signer)->SignAndEncodeWithKid(*raw_jwt, /*kid=*/std::nullopt);
  ASSERT_THAT(compact, IsOk());
  EXPECT_THAT((*verifier)->VerifyAndDecodeWithKid(*compact, *validator,
                                                  /*kid=*/absl::nullopt),
              IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
