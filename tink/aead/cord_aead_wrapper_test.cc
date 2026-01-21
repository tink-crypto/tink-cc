// Copyright 2020 Google LLC
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

#include "tink/aead/cord_aead_wrapper.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_test_helpers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/aead/cord_aead.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::DummyCordAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

TEST(AeadSetWrapperTest, WrapNullptr) {
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(nullptr);
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(absl::StatusCode::kInternal, aead_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      std::string(aead_result.status().message()));
}

TEST(AeadSetWrapperTest, WrapEmpty) {
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(absl::make_unique<PrimitiveSet<CordAead>>());
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, aead_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      std::string(aead_result.status().message()));
}

TEST(AeadSetWrapperTest, WrapperEncryptDecrypt) {
  uint32_t key_id = 1234543;
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_key_id(key_id);
  key_info.set_status(KeyStatusType::ENABLED);
  std::string aead_name = "aead0";
  auto aead_set_builder = PrimitiveSet<CordAead>::Builder();
  std::unique_ptr<CordAead> aead =
      absl::make_unique<DummyCordAead>(aead_name);
  aead_set_builder.AddPrimaryPrimitive(std::move(aead), key_info);
  auto aead_set = std::move(aead_set_builder).Build();
  ASSERT_THAT(aead_set, IsOk());

  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(
      std::make_unique<PrimitiveSet<CordAead>>(*std::move(aead_set)));
  ASSERT_THAT(aead_result, IsOk());
  auto wrapped_aead = std::move(aead_result.value());
  absl::Cord plaintext;
  plaintext.Append("some_plaintext");
  absl::Cord aad;
  aad.Append("some_aad");

  auto encrypt_result = wrapped_aead->Encrypt(plaintext, aad);
  EXPECT_THAT(encrypt_result, IsOk());
  absl::Cord ciphertext = encrypt_result.value();

  auto decrypt_result = wrapped_aead->Decrypt(ciphertext, aad);
  EXPECT_THAT(decrypt_result, IsOk());
  EXPECT_EQ(plaintext, decrypt_result.value());
}

TEST(AeadSetWrapperTest, WrapperEncryptDecryptMultipleKeys) {
  // Prepare key info for the primary key
  uint32_t key_id_0 = 1234543;
  KeysetInfo::KeyInfo key_info_0;
  key_info_0.set_output_prefix_type(OutputPrefixType::TINK);
  key_info_0.set_key_id(key_id_0);
  key_info_0.set_status(KeyStatusType::ENABLED);
  std::string aead_name_0 = "aead0";

  // Build PrimitiveSet with only the primary key
  auto primary_aead_set_builder = PrimitiveSet<CordAead>::Builder();
  std::unique_ptr<CordAead> primary_aead =
      absl::make_unique<DummyCordAead>(aead_name_0);
  primary_aead_set_builder.AddPrimaryPrimitive(std::move(primary_aead),
                                               key_info_0);
  auto primary_aead_set = std::move(primary_aead_set_builder)
                              .Build();
  ASSERT_THAT(primary_aead_set, IsOk());

  // Encrypt with the primary key Aead
  absl::Cord plaintext;
  plaintext.Append("some_plaintext");
  absl::Cord aad;
  aad.Append("some_aad");
  CordAeadWrapper wrapper;
  auto wrapped_primary_aead_result =
      wrapper.Wrap(std::make_unique<PrimitiveSet<CordAead>>(
          *std::move(primary_aead_set)));
  ASSERT_THAT(wrapped_primary_aead_result, IsOk());
  auto wrapped_primary_aead = std::move(wrapped_primary_aead_result.value());
  auto encrypt_result = wrapped_primary_aead->Encrypt(plaintext, aad);
  EXPECT_THAT(encrypt_result, IsOk());
  absl::Cord ciphertext = encrypt_result.value();

  // Builder for the multi-key PrimitiveSet
  auto multi_aead_set_builder = PrimitiveSet<CordAead>::Builder();
  std::unique_ptr<CordAead> aead0 =
      absl::make_unique<DummyCordAead>(aead_name_0);
  multi_aead_set_builder.AddPrimaryPrimitive(std::move(aead0),
                                             key_info_0);
  uint32_t key_id_1 = 42;
  KeysetInfo::KeyInfo key_info_1;
  key_info_1.set_output_prefix_type(OutputPrefixType::TINK);
  key_info_1.set_key_id(key_id_1);
  key_info_1.set_status(KeyStatusType::ENABLED);
  std::string aead_name_1 = "aead1";
  std::unique_ptr<CordAead> aead_1 =
      absl::make_unique<DummyCordAead>(aead_name_1);
  multi_aead_set_builder.AddPrimitive(std::move(aead_1),
                                      key_info_1);
  auto multi_aead_set = std::move(multi_aead_set_builder).Build();
  auto wrapped_multi_aead_result = wrapper.Wrap(
      std::make_unique<PrimitiveSet<CordAead>>(*std::move(multi_aead_set)));
  ASSERT_THAT(wrapped_multi_aead_result, IsOk());
  auto wrapped_multi_aead = std::move(wrapped_multi_aead_result.value());

  auto decrypt_result = wrapped_multi_aead->Decrypt(ciphertext, aad);
  EXPECT_THAT(decrypt_result, IsOk());
  EXPECT_EQ(plaintext, decrypt_result.value());
}

TEST(AeadSetWrapperTest, WrapperEncryptDecryptManyChunks) {
  uint32_t key_id = 1234543;
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_key_id(key_id);
  key_info.set_status(KeyStatusType::ENABLED);
  std::string aead_name = "aead0";
  auto aead_set_builder = PrimitiveSet<CordAead>::Builder();
  std::unique_ptr<CordAead> aead =
      absl::make_unique<DummyCordAead>(aead_name);
  aead_set_builder.AddPrimaryPrimitive(std::move(aead), key_info);
  auto aead_set = std::move(aead_set_builder).Build();

  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(
      std::make_unique<PrimitiveSet<CordAead>>(*std::move(aead_set)));
  ASSERT_THAT(aead_result, IsOk());
  auto wrapped_aead = std::move(aead_result.value());

  std::string plaintext = "";
  for (int i = 0; i < 1000; i++) {
    plaintext += "chunk" + std::to_string(i);
  }
  absl::Cord plaintext_cord =
      absl::MakeFragmentedCord(absl::StrSplit(plaintext, absl::ByLength(5)));
  absl::Cord aad;
  aad.Append("some_aad");

  auto encrypt_result = wrapped_aead->Encrypt(plaintext_cord, aad);
  EXPECT_THAT(encrypt_result, IsOk());
  absl::Cord ciphertext = encrypt_result.value();

  auto decrypt_result = wrapped_aead->Decrypt(ciphertext, aad);
  EXPECT_THAT(decrypt_result, IsOk());
  EXPECT_EQ(plaintext, decrypt_result.value());
}

TEST(AeadSetWrapperTest, WrapperEncryptBadDecrypt) {
  // Wrap aead_set and test the resulting Aead.
  uint32_t key_id = 1234543;
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_key_id(key_id);
  key_info.set_status(KeyStatusType::ENABLED);
  std::string aead_name = "aead0";
  auto aead_set_builder = PrimitiveSet<CordAead>::Builder();
  std::unique_ptr<CordAead> aead =
      absl::make_unique<DummyCordAead>(aead_name);
  aead_set_builder.AddPrimaryPrimitive(std::move(aead), key_info);
  auto aead_set = std::move(aead_set_builder).Build();
  ASSERT_THAT(aead_set, IsOk());

  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(
      std::make_unique<PrimitiveSet<CordAead>>(*std::move(aead_set)));
  ASSERT_THAT(aead_result, IsOk());
  // Encrypt with the primary key
  auto wrapped_aead = std::move(aead_result.value());
  absl::Cord plaintext;
  plaintext.Append("some_plaintext");
  absl::Cord aad;
  aad.Append("some_aad");

  absl::Cord bad_ciphertext;
  bad_ciphertext.Append("some bad ciphertext");
  auto decrypt_result = wrapped_aead->Decrypt(bad_ciphertext, aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, decrypt_result.status().code());
  EXPECT_THAT(decrypt_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("decryption failed")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
