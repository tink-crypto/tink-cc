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

#include "tink/signature/internal/slh_dsa_sign_key_manager.h"

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
#include "tink/signature/internal/slh_dsa_verify_key_manager.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/internal/testing/slh_dsa_test_vectors.h"
#include "tink/signature/signature_config.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/util/protobuf_helper.h"
#include "proto/slh_dsa.pb.h"
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

class SlhDsaSignKeyManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(SignatureConfig::Register(), IsOk());
    key_manager_ = MakeSlhDsaSignKeyManager();
  }

  std::unique_ptr<KeyManager<PublicKeySign>> key_manager_;
};

google::crypto::tink::SlhDsaPrivateKey CreateValidPrivateKeyProto() {
  const SignatureTestVector& test_vector =
      GetSlhDsaTestVector(SlhDsaParameters::HashType::kSha2,
                          SlhDsaParameters::SignatureType::kSmallSignature,
                          SlhDsaParameters::Variant::kNoPrefix);
  const auto& slh_dsa_private_key =
      dynamic_cast<const SlhDsaPrivateKey&>(*test_vector.signature_private_key);

  google::crypto::tink::SlhDsaPrivateKey proto;
  proto.set_version(0);
  proto.set_key_value(
      slh_dsa_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()));
  auto* public_key_proto = proto.mutable_public_key();
  public_key_proto->set_version(0);
  public_key_proto->set_key_value(
      slh_dsa_private_key.GetPublicKey().GetPublicKeyBytes(
          GetPartialKeyAccess()));
  public_key_proto->mutable_params()->set_key_size(
      slh_dsa_private_key.GetPublicKey()
          .GetParameters()
          .GetPrivateKeySizeInBytes());
  public_key_proto->mutable_params()->set_hash_type(google::crypto::tink::SHA2);
  public_key_proto->mutable_params()->set_sig_type(
      google::crypto::tink::SMALL_SIGNATURE);
  return proto;
}

TEST_F(SlhDsaSignKeyManagerTest, Basic) {
  EXPECT_THAT(key_manager_->get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey"));
  EXPECT_THAT(key_manager_->get_version(), Eq(0));
  EXPECT_THAT(key_manager_->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey"),
              Eq(true));
  EXPECT_THAT(key_manager_->DoesSupport(
                  "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"),
              Eq(false));
}

TEST_F(SlhDsaSignKeyManagerTest, GetPrimitive) {
  auto public_key_manager = MakeSlhDsaVerifyKeyManager();

  google::crypto::tink::SlhDsaPrivateKey private_key =
      CreateValidPrivateKeyProto();
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      key_manager_->GetPrimitive(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      public_key_manager->GetPrimitive(private_key.public_key());
  ASSERT_THAT(verifier, IsOk());

  auto signature = (*signer)->Sign("message");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "message"), IsOk());
}

TEST_F(SlhDsaSignKeyManagerTest, NewKey) {
  google::crypto::tink::SlhDsaKeyFormat key_format;
  key_format.set_version(0);
  key_format.mutable_params()->set_key_size(64);
  key_format.mutable_params()->set_hash_type(google::crypto::tink::SHA2);
  key_format.mutable_params()->set_sig_type(
      google::crypto::tink::SMALL_SIGNATURE);

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> private_key =
      key_manager_->get_key_factory().NewKey(key_format);
  ASSERT_THAT(private_key, IsOk());

  const google::crypto::tink::SlhDsaPrivateKey* slh_dsa_private_key =
      portable_proto::DynamicCastMessage<
          google::crypto::tink::SlhDsaPrivateKey>(private_key->get());
  ASSERT_THAT(slh_dsa_private_key, NotNull());
  EXPECT_THAT(slh_dsa_private_key->version(), Eq(0));
  EXPECT_THAT(slh_dsa_private_key->key_value(), Not(IsEmpty()));
  ASSERT_THAT(slh_dsa_private_key->has_public_key(), IsTrue());
  EXPECT_THAT(slh_dsa_private_key->public_key().version(), Eq(0));
  EXPECT_THAT(slh_dsa_private_key->public_key().key_value(), Not(IsEmpty()));
  EXPECT_THAT(slh_dsa_private_key->public_key().params().key_size(), Eq(64));
  EXPECT_THAT(slh_dsa_private_key->public_key().params().hash_type(),
              Eq(google::crypto::tink::SHA2));
  EXPECT_THAT(slh_dsa_private_key->public_key().params().sig_type(),
              Eq(google::crypto::tink::SMALL_SIGNATURE));

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      key_manager_->GetPrimitive(**private_key);
  ASSERT_THAT(signer, IsOk());

  std::unique_ptr<KeyManager<PublicKeyVerify>> public_key_manager =
      MakeSlhDsaVerifyKeyManager();
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      public_key_manager->GetPrimitive(slh_dsa_private_key->public_key());
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign("message");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "message"), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"), Not(IsOk()));
}

TEST_F(SlhDsaSignKeyManagerTest, NewKeyData) {
  google::crypto::tink::SlhDsaKeyFormat key_format;
  key_format.set_version(0);
  key_format.mutable_params()->set_key_size(64);
  key_format.mutable_params()->set_hash_type(google::crypto::tink::SHA2);
  key_format.mutable_params()->set_sig_type(
      google::crypto::tink::SMALL_SIGNATURE);

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>> key_data =
      key_manager_->get_key_factory().NewKeyData(
          key_format.SerializeAsString());
  ASSERT_THAT(key_data, IsOk());
  EXPECT_THAT((*key_data)->type_url(),
              Eq("type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey"));
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
