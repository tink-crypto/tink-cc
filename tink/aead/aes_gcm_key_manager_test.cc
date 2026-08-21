// Copyright 2017 Google LLC
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

#include "tink/aead/aes_gcm_key_manager.h"

#include <stdint.h>

#include <memory>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/cord.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/cord_aead_wrapper.h"
#include "tink/aead/internal/cord_aes_gcm_boringssl.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"
#include "tink/config/global_registry.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CordAesGcmBoringSsl;
using ::crypto::tink::util::IstreamInputStream;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;

TEST(AesGcmKeyManagerTest, Basics) {
  EXPECT_THAT(AesGcmKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesGcmKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(AesGcmKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesGcmKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(AesGcmKeyProto()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, ValidateValid16ByteKey) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value("0123456789abcdef");
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(key), IsOk());
}

TEST(AesGcmKeyManagerTest, ValidateValid32ByteKey) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value("01234567890123456789012345678901");
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(key), IsOk());
}

TEST(AesGcmKeyManagerTest, InvalidKeySizes15Bytes) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value("0123456789abcde");
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, InvalidKeySizes17Bytes) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value("0123456789abcdefg");
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, InvalidKeySizes24Bytes) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value("01234567890123");
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, InvalidKeySizes31Bytes) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value("0123456789012345678901234567890");
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, InvalidKeySizes33Bytes) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value("012345678901234567890123456789012");
  EXPECT_THAT(AesGcmKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, ValidateKeyFormat) {
  AesGcmKeyFormat format;

  format.set_key_size(0);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(1);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(15);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(16);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format), IsOk());

  format.set_key_size(17);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(31);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(32);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format), IsOk());

  format.set_key_size(33);
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, Create16ByteKey) {
  AesGcmKeyFormat format;
  format.set_key_size(16);

  absl::StatusOr<AesGcmKeyProto> key_or = AesGcmKeyManager().CreateKey(format);

  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value().size(), Eq(format.key_size()));
}

TEST(AesGcmKeyManagerTest, Create32ByteKey) {
  AesGcmKeyFormat format;
  format.set_key_size(32);

  absl::StatusOr<AesGcmKeyProto> key_or = AesGcmKeyManager().CreateKey(format);

  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value().size(), Eq(format.key_size()));
}

TEST(AesGcmKeyManagerTest, CreateAead) {
  AesGcmKeyFormat format;
  format.set_key_size(32);
  absl::StatusOr<AesGcmKeyProto> key_or = AesGcmKeyManager().CreateKey(format);
  ASSERT_THAT(key_or, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead_or =
      AesGcmKeyManager().GetPrimitive<Aead>(key_or.value());

  ASSERT_THAT(aead_or, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> boring_ssl_aead_or =
      subtle::AesGcmBoringSsl::New(
          util::SecretDataFromStringView(key_or.value().key_value()));
  ASSERT_THAT(boring_ssl_aead_or, IsOk());

  ASSERT_THAT(EncryptThenDecrypt(*aead_or.value(), *boring_ssl_aead_or.value(),
                                 "message", "aad"),
              IsOk());
}

TEST(AesGcmKeyManagerTest, CreateCordAead) {
  AesGcmKeyFormat format;
  format.set_key_size(32);
  absl::StatusOr<AesGcmKeyProto> key_or = AesGcmKeyManager().CreateKey(format);
  ASSERT_THAT(key_or, IsOk());

  absl::StatusOr<std::unique_ptr<CordAead>> aead_or =
      AesGcmKeyManager().GetPrimitive<CordAead>(key_or.value());

  ASSERT_THAT(aead_or, IsOk());

  absl::StatusOr<std::unique_ptr<CordAead>> boring_ssl_aead_or =
      CordAesGcmBoringSsl::New(
          util::SecretDataFromStringView(key_or.value().key_value()));
  ASSERT_THAT(boring_ssl_aead_or, IsOk());

  ASSERT_THAT(EncryptThenDecrypt(*aead_or.value(), *boring_ssl_aead_or.value(),
                                 "message", "aad"),
              IsOk());
}

TEST(AesGcmKeyManagerTest, DeriveShortKey) {
  AesGcmKeyFormat format;
  format.set_key_size(16);
  format.set_version(0);

  IstreamInputStream input_stream{
      std::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};

  absl::StatusOr<AesGcmKeyProto> key_or =
      AesGcmKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(), Eq("0123456789abcdef"));
}

TEST(AesGcmKeyManagerTest, DeriveLongKey) {
  AesGcmKeyFormat format;
  format.set_key_size(32);
  format.set_version(0);

  IstreamInputStream input_stream{std::make_unique<std::stringstream>(
      "0123456789abcdef0123456789abcdefXXX")};

  absl::StatusOr<AesGcmKeyProto> key_or =
      AesGcmKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(),
              Eq("0123456789abcdef0123456789abcdef"));
}

TEST(AesGcmKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  AesGcmKeyFormat format;
  format.set_key_size(16);
  format.set_version(0);

  IstreamInputStream input_stream{
      std::make_unique<std::stringstream>("0123456789")};

  ASSERT_THAT(AesGcmKeyManager().DeriveKey(format, &input_stream).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyManagerTest, DeriveKeyWrongVersion) {
  AesGcmKeyFormat format;
  format.set_key_size(16);
  format.set_version(1);

  IstreamInputStream input_stream{
      std::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};

  ASSERT_THAT(
      AesGcmKeyManager().DeriveKey(format, &input_stream).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("version")));
}

using AesGcmKeyManagerTestVectorTest =
    testing::TestWithParam<internal::AeadTestVector>;

TEST_P(AesGcmKeyManagerTestVectorTest, DecryptAead) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  const internal::AeadTestVector& test_vector = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              test_vector.aead_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> plaintext =
      (*aead)->Decrypt(test_vector.ciphertext, test_vector.associated_data);
  ASSERT_THAT(plaintext, IsOk());
  EXPECT_THAT(*plaintext, Eq(test_vector.plaintext));
}

TEST_P(AesGcmKeyManagerTestVectorTest, DecryptCordAead) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  ASSERT_THAT(
      Registry::RegisterPrimitiveWrapper(std::make_unique<CordAeadWrapper>()),
      IsOk());
  const internal::AeadTestVector& test_vector = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              test_vector.aead_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<CordAead>> cord_aead =
      handle->GetPrimitive<CordAead>(ConfigGlobalRegistry());
  ASSERT_THAT(cord_aead, IsOk());

  absl::StatusOr<absl::Cord> plaintext =
      (*cord_aead)
          ->Decrypt(absl::Cord(test_vector.ciphertext),
                    absl::Cord(test_vector.associated_data));
  ASSERT_THAT(plaintext, IsOk());
  EXPECT_THAT(*plaintext, Eq(absl::Cord(test_vector.plaintext)));
}

INSTANTIATE_TEST_SUITE_P(
    AesGcmKeyManagerTestVectorTestSuite, AesGcmKeyManagerTestVectorTest,
    testing::ValuesIn(internal::CreateAesGcmTestVectors()));

}  // namespace
}  // namespace tink
}  // namespace crypto
