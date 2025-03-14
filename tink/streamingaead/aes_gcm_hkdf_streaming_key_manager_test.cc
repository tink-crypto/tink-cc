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

#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"

#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/keyset_handle.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/internal/testing/aes_gcm_hkdf_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/streamingaead/streaming_aead_config.h"
#include "tink/subtle/aes_gcm_hkdf_streaming.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/subtle/test_util.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::internal::StreamingAeadTestVector;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::google::crypto::tink::AesGcmHkdfStreamingKey;
using ::google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using ::google::crypto::tink::HashType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

namespace {

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKey) {
  AesGcmHkdfStreamingKey key;
  key.set_version(0);
  key.set_key_value("0123456789abcdef");
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->set_ciphertext_segment_size(1024);
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKey(key), IsOk());
}

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKeyDerivedKeySizes) {
  for (int derived_key_size = 0; derived_key_size < 42; derived_key_size++) {
    SCOPED_TRACE(absl::StrCat(" derived_key_size = ", derived_key_size));
    AesGcmHkdfStreamingKey key;
    key.set_version(0);
    key.set_key_value(std::string(derived_key_size, 'a'));  // ikm
    key.mutable_params()->set_derived_key_size(derived_key_size);
    key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
    key.mutable_params()->set_ciphertext_segment_size(1024);
    if (derived_key_size == 16 || derived_key_size == 32) {
      EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKey(key), IsOk());
    } else {
      EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKey(key),
                  StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKeyDerivedKeyWrongVersion) {
  AesGcmHkdfStreamingKey key;
  key.set_version(1);
  key.set_key_value("0123456789abcdef");
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->set_ciphertext_segment_size(1024);
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, GetPrimitive) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";

  AesGcmHkdfStreamingKey key;
  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);

  auto streaming_aead_from_manager_result =
      AesGcmHkdfStreamingKeyManager().GetPrimitive<StreamingAead>(key);
  EXPECT_THAT(streaming_aead_from_manager_result, IsOk());

  int derived_key_size = 16;
  int ciphertext_segment_size = 1024;
  int ciphertext_offset = 0;
  subtle::AesGcmHkdfStreaming::Params params;
  params.ikm = util::SecretDataFromStringView("16 bytes of key ");
  params.hkdf_hash = crypto::tink::subtle::HashType::SHA256;
  params.derived_key_size = derived_key_size;
  params.ciphertext_segment_size = ciphertext_segment_size;
  params.ciphertext_offset = ciphertext_offset;
  auto streaming_aead_direct_result =
      subtle::AesGcmHkdfStreaming::New(std::move(params));
  EXPECT_THAT(streaming_aead_direct_result, IsOk());

  // Check that the two primitives are the same by encrypting with one, and
  // decrypting with the other.
  EXPECT_THAT(
      EncryptThenDecrypt(streaming_aead_from_manager_result.value().get(),
                         streaming_aead_direct_result.value().get(),
                         subtle::Random::GetRandomBytes(10000),
                         "some associated data", ciphertext_offset),
      IsOk());
}

TEST(AesGcmHkdfStreamingKeyManagerTest, Version) {
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().get_version(), Eq(0));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, KeyMaterialType) {
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, KeyType) {
  EXPECT_THAT(
      AesGcmHkdfStreamingKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKeyFormatEmpty) {
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(
                  AesGcmHkdfStreamingKeyFormat()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKeyFormat) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKeyFormatSmallKey) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("derived_key_size")));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKeyFormatWrongHash) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("hkdf_hash_type")));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, ValidateKeyFormatSmallSegment) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(45);
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size")));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, CreateKey) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  auto key_or = AesGcmHkdfStreamingKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().version(), Eq(0));
  EXPECT_THAT(key_or.value().params().ciphertext_segment_size(),
              Eq(key_format.params().ciphertext_segment_size()));
  EXPECT_THAT(key_or.value().params().derived_key_size(),
              Eq(key_format.params().derived_key_size()));
  EXPECT_THAT(key_or.value().params().hkdf_hash_type(),
              Eq(key_format.params().hkdf_hash_type()));
  EXPECT_THAT(key_or.value().key_value().size(), Eq(key_format.key_size()));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, DeriveKey) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("01234567890123456789012345678901")};

  absl::StatusOr<AesGcmHkdfStreamingKey> key_or =
      AesGcmHkdfStreamingKeyManager().DeriveKey(key_format, &input_stream);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(),
              Eq("01234567890123456789012345678901"));
  EXPECT_THAT(key_or.value().params().derived_key_size(),
              Eq(key_format.params().derived_key_size()));
  EXPECT_THAT(key_or.value().params().hkdf_hash_type(),
              Eq(key_format.params().hkdf_hash_type()));
  EXPECT_THAT(key_or.value().params().ciphertext_segment_size(),
              Eq(key_format.params().ciphertext_segment_size()));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789012345678901234567890")};

  ASSERT_THAT(AesGcmHkdfStreamingKeyManager()
                  .DeriveKey(key_format, &input_stream)
                  .status(),
              Not(IsOk()));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, DeriveKeyWrongVersion) {
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_version(1);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcdef")};

  ASSERT_THAT(
      AesGcmHkdfStreamingKeyManager()
          .DeriveKey(key_format, &input_stream)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("version")));
}

using AesGcmHkdfStreamingKeyManagerTestVectorTest =
    testing::TestWithParam<StreamingAeadTestVector>;

TEST_P(AesGcmHkdfStreamingKeyManagerTestVectorTest, Decrypt) {
  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());
  const StreamingAeadTestVector& param = GetParam();
  // Prepare an InputStream with the ciphertext.
  auto ct_bytes = absl::make_unique<std::stringstream>(param.ciphertext);
  auto ct_source =
      absl::make_unique<util::IstreamInputStream>(std::move(ct_bytes));
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.streamingaead_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<StreamingAead>> decrypter =
      handle->GetPrimitive<StreamingAead>(ConfigGlobalRegistry());
  ASSERT_THAT(decrypter, IsOk());
  // Decrypt the ciphertext using the decrypter.
  absl::StatusOr<std::unique_ptr<InputStream>> plaintext_stream =
      (*decrypter)
          ->NewDecryptingStream(std::move(ct_source), param.associated_data);
  ASSERT_THAT(plaintext_stream, IsOk());

  absl::StatusOr<std::string> decryption =
      ReadBytesFromStream(param.plaintext.size(), plaintext_stream->get());
  ASSERT_THAT(decryption, IsOk());
  EXPECT_THAT(*decryption, Eq(param.plaintext));

  EXPECT_THAT(ReadBytesFromStream(1, plaintext_stream->get()),
              StatusIs(absl::StatusCode::kOutOfRange));
}

INSTANTIATE_TEST_SUITE_P(
    AesGcmHkdfStreamingKeyManagerTestVectorTest,
    AesGcmHkdfStreamingKeyManagerTestVectorTest,
    testing::ValuesIn(internal::CreateAesGcmHkdfStreamingTestVectors()));

}  // namespace
}  // namespace tink
}  // namespace crypto
