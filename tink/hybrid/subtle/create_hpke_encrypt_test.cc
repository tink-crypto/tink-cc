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

#include "tink/hybrid/subtle/create_hpke_encrypt.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/hybrid/subtle/create_hpke_decrypt.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::crypto::tink::internal::CreateHpkeTestVectors;
using ::crypto::tink::internal::HybridTestVector;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateHpkeHybridEncryptTestVectorTest = TestWithParam<HybridTestVector>;

TEST_P(CreateHpkeHybridEncryptTestVectorTest, EncryptDecryptTestVectors) {
  const HybridTestVector& test_vector = GetParam();
  const HpkePrivateKey& key =
      dynamic_cast<const HpkePrivateKey&>(*test_vector.hybrid_private_key);
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypter =
      CreateHpkeHybridEncrypt(key.GetPublicKey());
  ASSERT_THAT(encrypter, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypter)->Encrypt(test_vector.plaintext, test_vector.context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext, StartsWith(key.GetPublicKey().GetOutputPrefix()));

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      CreateHpkeHybridDecrypt(key);
  ASSERT_THAT(decrypter, IsOk());
  EXPECT_THAT((*decrypter)->Decrypt(*ciphertext, test_vector.context_info),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(CreateHpkeHybridEncryptTestVectorTests,
                         CreateHpkeHybridEncryptTestVectorTest,
                         ValuesIn(CreateHpkeTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
