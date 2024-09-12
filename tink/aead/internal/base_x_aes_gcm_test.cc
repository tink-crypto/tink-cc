// Copyright 2024 Google LLC
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

#include "tink/aead/internal/base_x_aes_gcm.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::Eq;
using ::testing::TestWithParam;

constexpr int kDefaultSaltSize = 12;
constexpr int kKeySize = 32;

util::StatusOr<XAesGcmKey> CreateKey(absl::string_view key, int salt_size) {
  util::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, salt_size);
  if (!params.ok()) {
    return params.status();
  }
  return XAesGcmKey::Create(*params,
                            RestrictedData(SecretDataFromStringView(key),
                                           InsecureSecretKeyAccess::Get()),
                            absl::nullopt, GetPartialKeyAccess());
}

util::StatusOr<XAesGcmKey> CreateKey(int salt_size) {
  return CreateKey(Random::GetRandomBytes(kKeySize), salt_size);
}

TEST(BaseXAesGcmTest, CreationSucceeds) {
  util::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(BaseXAesGcm::New(std::move(*key)), IsOk());
}

TEST(BaseXAesGcmTest, MinCtSize) {
  util::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<BaseXAesGcm> base_x_aes_gcm =
      BaseXAesGcm::New(std::move(*key));
  ASSERT_THAT(base_x_aes_gcm, IsOk());
  ASSERT_THAT(base_x_aes_gcm->min_ct_size(), Eq(kDefaultSaltSize + 28));
}

TEST(BaseXAesGcmTest, DeriveWithInvalidSaltSizeFails) {
  util::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<BaseXAesGcm> base_x_aes_gcm =
      BaseXAesGcm::New(std::move(*key));
  ASSERT_THAT(base_x_aes_gcm, IsOk());

  std::string salt = Random::GetRandomBytes(kDefaultSaltSize + 1);
  for (int i : {7, 13}) {
    EXPECT_THAT(base_x_aes_gcm->DerivePerMessageKey(salt.substr(0, i)).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(BaseXAesGcmTest, DeriveWithValidSaltSize) {
  util::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<BaseXAesGcm> base_x_aes_gcm =
      BaseXAesGcm::New(std::move(*key));
  ASSERT_THAT(base_x_aes_gcm, IsOk());

  std::string salt = Random::GetRandomBytes(kDefaultSaltSize);
  for (int i : {8, 12}) {
    EXPECT_THAT(base_x_aes_gcm->DerivePerMessageKey(salt.substr(0, i)).status(),
                IsOk());
  }
}

struct XAesGcmKeyDerivationTestVector {
  std::string name;
  std::string base_hex_key;
  std::string salt;
  std::string derived_hex_key;
};

using BaseXAesGcmTest = TestWithParam<XAesGcmKeyDerivationTestVector>;

TEST_P(BaseXAesGcmTest, DeriveWithKnownTestVectors) {
  const XAesGcmKeyDerivationTestVector& test_case = GetParam();
  util::StatusOr<XAesGcmKey> key = CreateKey(
      absl::HexStringToBytes(test_case.base_hex_key), kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<BaseXAesGcm> base_x_aes_gcm =
      BaseXAesGcm::New(std::move(*key));
  ASSERT_THAT(base_x_aes_gcm, IsOk());

  absl::StatusOr<SecretData> dervived_key =
      base_x_aes_gcm->DerivePerMessageKey(test_case.salt);
  ASSERT_THAT(dervived_key, IsOk());

  EXPECT_THAT(
      absl::BytesToHexString(util::SecretDataAsStringView(*dervived_key)),
      Eq(test_case.derived_hex_key));
}

// Test vectors from
// https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md#test-vectors.
std::vector<XAesGcmKeyDerivationTestVector> GetTestVectors() {
  return {
      {
          /*name=*/"test_vector_1",
          /*base_hex_key=*/
          "0101010101010101010101010101010101010101010101010101010101010101",
          /*salt=*/"ABCDEFGHIJKL",
          /*derived_hex_key=*/
          "c8612c9ed53fe43e8e005b828a1631a0bbcb6ab2f46514ec4f439fcfd0fa969b",
      },
      {
          /*name=*/"test_vector_2",
          /*hex_key=*/
          "0303030303030303030303030303030303030303030303030303030303030303",
          /*nonce=*/"ABCDEFGHIJKL",
          /*derived_hex_key=*/
          "e9c621d4cdd9b11b00a6427ad7e559aeedd66b3857646677748f8ca796cb3fd8",
      },
  };
}

INSTANTIATE_TEST_SUITE_P(
    BaseXAesGcmTestVectors, BaseXAesGcmTest,
    testing::ValuesIn(GetTestVectors()),
    [](const testing::TestParamInfo<BaseXAesGcmTest::ParamType>& info) {
      return info.param.name;
    });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
