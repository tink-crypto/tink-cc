// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/ml_dsa_sign_key_manager.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key_manager.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/ml_dsa_proto_serialization.h"
#include "tink/signature/internal/ml_dsa_verify_key_manager.h"
#include "tink/signature/internal/testing/ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/util/protobuf_helper.h"
#include "proto/ml_dsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::NotNull;

class MlDsaSignKeyManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());
    key_manager_ = MakeMlDsaSignKeyManager();
  }

  std::unique_ptr<KeyManager<PublicKeySign>> key_manager_;
};

google::crypto::tink::MlDsaPrivateKey CreateValidPrivateKeyProto() {
  const SignatureTestVector& test_vector = GetMlDsaTestVector(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  const auto& ml_dsa_private_key =
      dynamic_cast<const MlDsaPrivateKey&>(*test_vector.signature_private_key);

  google::crypto::tink::MlDsaPrivateKey proto;
  proto.set_version(0);
  proto.set_key_value(
      ml_dsa_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()));
  google::crypto::tink::MlDsaPublicKey* public_key_proto =
      proto.mutable_public_key();
  public_key_proto->set_version(0);
  public_key_proto->set_key_value(
      ml_dsa_private_key.GetPublicKey().GetPublicKeyBytes(
          GetPartialKeyAccess()));
  public_key_proto->mutable_params()->set_ml_dsa_instance(
      google::crypto::tink::MlDsaInstance::ML_DSA_65);
  return proto;
}

TEST_F(MlDsaSignKeyManagerTest, Basic) {
  EXPECT_THAT(key_manager_->get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey"));
  EXPECT_THAT(key_manager_->get_version(), Eq(0));
  EXPECT_THAT(key_manager_->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey"),
              Eq(true));
  EXPECT_THAT(key_manager_->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"),
              Eq(false));
}

TEST_F(MlDsaSignKeyManagerTest, GetPrimitive) {
  auto public_key_manager = MakeMlDsaVerifyKeyManager();

  google::crypto::tink::MlDsaPrivateKey private_key =
      CreateValidPrivateKeyProto();
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      key_manager_->GetPrimitive(private_key);
  ASSERT_THAT(signer, IsOk());

  auto verifier = public_key_manager->GetPrimitive(private_key.public_key());
  ASSERT_THAT(verifier, IsOk());

  auto signature = (*signer)->Sign("message");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "message"), IsOk());
}

TEST_F(MlDsaSignKeyManagerTest, NewKey) {
  google::crypto::tink::MlDsaKeyFormat key_format;
  key_format.set_version(0);
  key_format.mutable_params()->set_ml_dsa_instance(
      google::crypto::tink::MlDsaInstance::ML_DSA_65);

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> private_key =
      key_manager_->get_key_factory().NewKey(key_format);
  ASSERT_THAT(private_key, IsOk());

  const google::crypto::tink::MlDsaPrivateKey* ml_dsa_private_key =
      portable_proto::DynamicCastMessage<google::crypto::tink::MlDsaPrivateKey>(
          private_key->get());
  ASSERT_THAT(ml_dsa_private_key, NotNull());
  EXPECT_THAT(ml_dsa_private_key->version(), Eq(0));
  EXPECT_THAT(ml_dsa_private_key->key_value(), Not(IsEmpty()));
  ASSERT_THAT(ml_dsa_private_key->has_public_key(), IsTrue());
  EXPECT_THAT(ml_dsa_private_key->public_key().version(), Eq(0));
  EXPECT_THAT(ml_dsa_private_key->public_key().key_value(), Not(IsEmpty()));
  EXPECT_THAT(ml_dsa_private_key->public_key().params().ml_dsa_instance(),
              Eq(google::crypto::tink::MlDsaInstance::ML_DSA_65));

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      key_manager_->GetPrimitive(**private_key);
  ASSERT_THAT(signer, IsOk());

  std::unique_ptr<KeyManager<PublicKeyVerify>> public_key_manager =
      MakeMlDsaVerifyKeyManager();
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      public_key_manager->GetPrimitive(ml_dsa_private_key->public_key());
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign("message");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "message"), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"), Not(IsOk()));
}

TEST_F(MlDsaSignKeyManagerTest, NewKeyData) {
  google::crypto::tink::MlDsaKeyFormat key_format;
  key_format.set_version(0);
  key_format.mutable_params()->set_ml_dsa_instance(
      google::crypto::tink::MlDsaInstance::ML_DSA_65);

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>> key_data =
      key_manager_->get_key_factory().NewKeyData(
          key_format.SerializeAsString());
  ASSERT_THAT(key_data, IsOk());
  EXPECT_THAT((*key_data)->type_url(),
              Eq("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey"));
  EXPECT_THAT((*key_data)->key_material_type(),
              Eq(google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE));

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      key_manager_->GetPrimitive(**key_data);
  ASSERT_THAT(signer, IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
