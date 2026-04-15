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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/signature/internal/slh_dsa_verify_key_manager.h"
#include "tink/signature/signature_config.h"
#include "tink/util/test_matchers.h"
#include "proto/slh_dsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::NotNull;

class SlhDsaSignKeyManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(SignatureConfig::Register(), IsOk());
    key_manager_ = MakeSlhDsaSignKeyManager();
  }

  std::unique_ptr<KeyManager<PublicKeySign>> key_manager_;
};

google::crypto::tink::SlhDsaKeyFormat CreateValidKeyFormat() {
  google::crypto::tink::SlhDsaKeyFormat format;
  format.set_version(0);
  format.mutable_params()->set_key_size(64);
  format.mutable_params()->set_hash_type(google::crypto::tink::SHA2);
  format.mutable_params()->set_sig_type(google::crypto::tink::SMALL_SIGNATURE);
  return format;
}

absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> CreateValidKey(
    const KeyManager<PublicKeySign>& key_manager) {
  auto format = CreateValidKeyFormat();
  return key_manager.get_key_factory().NewKey(format);
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

  auto private_key = CreateValidKey(*key_manager_);
  ASSERT_THAT(private_key, IsOk());
  auto signer = key_manager_->GetPrimitive(**private_key);
  ASSERT_THAT(signer, IsOk());

  const google::crypto::tink::SlhDsaPrivateKey* slh_dsa_private_key =
      dynamic_cast<const google::crypto::tink::SlhDsaPrivateKey*>(
          private_key->get());
  ASSERT_THAT(slh_dsa_private_key, NotNull());

  auto verifier =
      public_key_manager->GetPrimitive(slh_dsa_private_key->public_key());
  ASSERT_THAT(verifier, IsOk());

  auto signature = (*signer)->Sign("message");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "message"), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
