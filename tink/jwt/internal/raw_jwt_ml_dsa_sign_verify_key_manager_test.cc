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
#include "tink/jwt/internal/raw_jwt_ml_dsa_sign_key_manager.h"
#include "tink/jwt/internal/raw_jwt_ml_dsa_verify_key_manager.h"
#include "tink/jwt/jwt_ml_dsa_proto_serialization.h"
#include "tink/key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/util/protobuf_helper.h"
#include "proto/jwt_ml_dsa.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;

TEST(JwtMlDsaSignKeyManagerTest, Basic) {
  std::unique_ptr<KeyManager<PublicKeySign>> key_manager =
      MakeRawJwtMlDsaSignKeyManager();

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
  std::unique_ptr<KeyManager<PublicKeyVerify>> key_manager =
      MakeRawJwtMlDsaVerifyKeyManager();

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
  std::unique_ptr<KeyManager<PublicKeySign>> sign_key_manager =
      MakeRawJwtMlDsaSignKeyManager();
  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> private_key =
      sign_key_manager->get_key_factory().NewKey(format);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<crypto::tink::PublicKeySign>> signer =
      sign_key_manager->GetPrimitive(**private_key);
  ASSERT_THAT(signer, IsOk());

  const google::crypto::tink::JwtMlDsaPrivateKey* jwt_ml_dsa_private_key =
      portable_proto::DynamicCastMessage<
          google::crypto::tink::JwtMlDsaPrivateKey>(private_key->get());
  ASSERT_THAT(jwt_ml_dsa_private_key, NotNull());
  ASSERT_THAT(jwt_ml_dsa_private_key->has_public_key(), IsTrue());

  std::unique_ptr<KeyManager<PublicKeyVerify>> verify_key_manager =
      MakeRawJwtMlDsaVerifyKeyManager();

  absl::StatusOr<std::unique_ptr<crypto::tink::PublicKeyVerify>> verifier =
      verify_key_manager->GetPrimitive(jwt_ml_dsa_private_key->public_key());
  ASSERT_THAT(verifier, IsOk());

  std::string message = "Some message";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
