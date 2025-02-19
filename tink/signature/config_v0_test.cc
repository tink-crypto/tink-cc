// Copyright 2023 Google LLC
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

#include "tink/signature/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/key_gen_config_v0.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

using ConfigV0Test = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(
    ConfigV0TestSuite, ConfigV0Test,
    Values(SignatureKeyTemplates::EcdsaP256(), SignatureKeyTemplates::Ed25519(),
           SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4(),
           SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4()));

TEST_P(ConfigV0Test, GetPrimitive) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigSignatureV0());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(KeyGenConfigSignatureV0());
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(ConfigSignatureV0());
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(ConfigSignatureV0());
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

#ifdef OPENSSL_IS_BORINGSSL
TEST(PqcSignatureConfigV0Test, SlhDsaGetPrimitive) {
  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters,
                                              KeyGenConfigSignatureV0());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(KeyGenConfigSignatureV0());
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(ConfigSignatureV0());
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(ConfigSignatureV0());
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

TEST(PqcSignatureConfigV0Test, MlDsaGetPrimitive) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters,
                                              KeyGenConfigSignatureV0());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(KeyGenConfigSignatureV0());
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(ConfigSignatureV0());
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(ConfigSignatureV0());
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}
#endif

}  // namespace
}  // namespace tink
}  // namespace crypto
