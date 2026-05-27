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

#include "tink/hybrid/config_2026.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid/key_gen_config_2026.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyset_handle.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

using Config2026Test = TestWithParam<KeyTemplate>;

#ifdef OPENSSL_IS_BORINGSSL
INSTANTIATE_TEST_SUITE_P(
    Config2026TestSuite, Config2026Test,
    Values(HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm(),
           HybridKeyTemplates::HpkeP256HkdfSha256Aes128Gcm(),
           HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm()));
#else
INSTANTIATE_TEST_SUITE_P(
    Config2026TestSuite, Config2026Test,
    Values(HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm()));
#endif

TEST_P(Config2026Test, GetPrimitive) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigHybrid2026());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(KeyGenConfigHybrid2026());
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      (*public_handle)->GetPrimitive<HybridEncrypt>(ConfigHybrid2026());
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      (*handle)->GetPrimitive<HybridDecrypt>(ConfigHybrid2026());
  ASSERT_THAT(decrypt, IsOk());

  std::string plaintext = "plaintext";
  absl::StatusOr<std::string> ciphertext = (*encrypt)->Encrypt(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "ad"), IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
