// Copyright 2019 Google LLC
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

#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/config/global_registry.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/streamingaead/internal/aes_ctr_hmac_streaming.h"
#include "tink/streamingaead/internal/testing/aes_ctr_hmac_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/streamingaead/streaming_aead_config.h"
#include "tink/subtle/random.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"
#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::StreamingAeadTestVector;
using ::google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using ::google::crypto::tink::HashType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

namespace {

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKey) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("0123456789abcdef");
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key), IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyDerivedKeySizes) {
  for (int derived_key_size = 0; derived_key_size < 42; derived_key_size++) {
    SCOPED_TRACE(absl::StrCat(" derived_key_size = ", derived_key_size));
    google::crypto::tink::AesCtrHmacStreamingKey key;
    key.set_version(0);
    key.set_key_value(std::string(derived_key_size, 'a'));  // ikm
    key.mutable_params()->set_derived_key_size(derived_key_size);
    key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
    key.mutable_params()->set_ciphertext_segment_size(1024);
    key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
    key.mutable_params()->mutable_hmac_params()->set_tag_size(32);
    if (derived_key_size == 16 || derived_key_size == 32) {
      EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key), IsOk());
    } else {
      EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key),
                  StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyDerivedKeyWrongVersion) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(1);
  key.set_key_value("0123456789abcdef");
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest, GetPrimitive) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);

  auto streaming_aead_from_manager_result =
      AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key);
  ASSERT_THAT(streaming_aead_from_manager_result, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<crypto::tink::AesCtrHmacStreamingKey> streaming_key =
      crypto::tink::AesCtrHmacStreamingKey::Create(
          *parameters,
          RestrictedData("16 bytes of key ", InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(streaming_key, IsOk());
  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead_direct_result =
      internal::NewAesCtrHmacStreaming(*streaming_key);
  ASSERT_THAT(streaming_aead_direct_result, IsOk());

  // Check that the two primitives are the same by encrypting with one, and
  // decrypting with the other.
  EXPECT_THAT(
      EncryptThenDecrypt(streaming_aead_from_manager_result.value().get(),
                         streaming_aead_direct_result.value().get(),
                         subtle::Random::GetRandomBytes(10000),
                         "some associated data", /*ciphertext_offset=*/0),
      IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, Version) {
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().get_version(), Eq(0));
}

TEST(AesCtrHmacStreamingKeyManagerTest, KeyMaterialType) {
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesCtrHmacStreamingKeyManagerTest, KeyType) {
  EXPECT_THAT(
      AesCtrHmacStreamingKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatEmpty) {
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(
                  AesCtrHmacStreamingKeyFormat()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormat) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatSmallKey) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("derived_key_size")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatWrongHash) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("hkdf_hash_type")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatWrongHmacHash) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("hmac_params.hash")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatSmallSegment) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(45);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatTooLargeSegment) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(2147483648);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size too big")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatSegmentSizeBoundary) {
  // Header size is 1 + derived_key_size (32) + nonce_prefix_size (7) = 40, so
  // ciphertext_segment_size must be > 40 + tag_size (32) = 72.
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_hash(
      HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);

  key_format.mutable_params()->set_ciphertext_segment_size(72);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size")));

  key_format.mutable_params()->set_ciphertext_segment_size(73);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeySegmentSizeBoundary) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value(std::string(32, 'a'));
  key.mutable_params()->set_derived_key_size(32);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);

  key.mutable_params()->set_ciphertext_segment_size(72);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size")));

  key.mutable_params()->set_ciphertext_segment_size(73);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key), IsOk());
}

struct HashCase {
  absl::string_view name;
  HashType proto_hkdf_hash;
  AesCtrHmacStreamingParameters::HashType hkdf_hash;
  HashType proto_hmac_hash;
  AesCtrHmacStreamingParameters::HashType hmac_hash;
};

using AesCtrHmacStreamingKeyManagerHashTypesTest =
    testing::TestWithParam<HashCase>;

TEST_P(AesCtrHmacStreamingKeyManagerHashTypesTest, GetPrimitive) {
  const HashCase& test_case = GetParam();
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(test_case.proto_hkdf_hash);
  key.mutable_params()->mutable_hmac_params()->set_hash(
      test_case.proto_hmac_hash);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(20);

  absl::StatusOr<std::unique_ptr<StreamingAead>> from_manager =
      AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key);
  ASSERT_THAT(from_manager, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(test_case.hkdf_hash)
          .SetHmacHashType(test_case.hmac_hash)
          .SetHmacTagSizeInBytes(20)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<crypto::tink::AesCtrHmacStreamingKey> streaming_key =
      crypto::tink::AesCtrHmacStreamingKey::Create(
          *parameters,
          RestrictedData("16 bytes of key ", InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(streaming_key, IsOk());
  absl::StatusOr<std::unique_ptr<StreamingAead>> direct =
      internal::NewAesCtrHmacStreaming(*streaming_key);
  ASSERT_THAT(direct, IsOk());

  EXPECT_THAT(EncryptThenDecrypt(from_manager->get(), direct->get(),
                                 "some plaintext", "some associated data",
                                 /*ciphertext_offset=*/0),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacStreamingKeyManagerHashTypesTest,
    AesCtrHmacStreamingKeyManagerHashTypesTest,
    testing::Values(HashCase{"HkdfSha1HmacSha256", HashType::SHA1,
                             AesCtrHmacStreamingParameters::HashType::kSha1,
                             HashType::SHA256,
                             AesCtrHmacStreamingParameters::HashType::kSha256},
                    HashCase{"HkdfSha256HmacSha512", HashType::SHA256,
                             AesCtrHmacStreamingParameters::HashType::kSha256,
                             HashType::SHA512,
                             AesCtrHmacStreamingParameters::HashType::kSha512},
                    HashCase{"HkdfSha512HmacSha1", HashType::SHA512,
                             AesCtrHmacStreamingParameters::HashType::kSha512,
                             HashType::SHA1,
                             AesCtrHmacStreamingParameters::HashType::kSha1}),
    [](const testing::TestParamInfo<HashCase>& info) {
      return std::string(info.param.name);
    });

TEST(AesCtrHmacStreamingKeyManagerTest, GetPrimitiveUnsupportedHkdfHash) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);

  key.mutable_params()->set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  key.mutable_params()->set_hkdf_hash_type(HashType::SHA224);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  key.mutable_params()->set_hkdf_hash_type(HashType::SHA384);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest, GetPrimitiveUnsupportedHmacHash) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(16);

  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::UNKNOWN_HASH);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA224);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA384);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest,
     GetPrimitiveInvalidKeyAndDerivedKeySizes) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);

  key.set_key_value(std::string(24, 'a'));
  key.mutable_params()->set_derived_key_size(24);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  key.set_key_value(std::string(16, 'a'));
  key.mutable_params()->set_derived_key_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest, GetPrimitiveInvalidTagSize) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);

  key.mutable_params()->mutable_hmac_params()->set_tag_size(9);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  key.mutable_params()->mutable_hmac_params()->set_tag_size(33);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest, GetPrimitiveSegmentSizeBoundary) {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value(std::string(32, 'a'));
  key.mutable_params()->set_derived_key_size(32);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);

  key.mutable_params()->set_ciphertext_segment_size(72);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              StatusIs(absl::StatusCode::kInvalidArgument));

  key.mutable_params()->set_ciphertext_segment_size(73);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key),
              IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, CreateKey) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  auto key_or = AesCtrHmacStreamingKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().version(), Eq(0));
  EXPECT_THAT(key_or.value().params().ciphertext_segment_size(),
              Eq(key_format.params().ciphertext_segment_size()));
  EXPECT_THAT(key_or.value().params().derived_key_size(),
              Eq(key_format.params().derived_key_size()));
  EXPECT_THAT(key_or.value().params().hkdf_hash_type(),
              Eq(key_format.params().hkdf_hash_type()));
  EXPECT_THAT(key_or.value().key_value().size(), Eq(key_format.key_size()));
  EXPECT_THAT(key_or.value().params().hmac_params().hash(),
              Eq(key_format.params().hmac_params().hash()));
  EXPECT_THAT(key_or.value().params().hmac_params().tag_size(),
              Eq(key_format.params().hmac_params().tag_size()));
}

TEST(AesCtrHmacStreamingKeyManagerTest, DeriveKey) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  util::IstreamInputStream input_stream{
      std::make_unique<std::stringstream>("01234567890123456789012345678901")};

  absl::StatusOr<google::crypto::tink::AesCtrHmacStreamingKey> key_or =
      AesCtrHmacStreamingKeyManager().DeriveKey(key_format, &input_stream);
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

TEST(AesCtrHmacStreamingKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  util::IstreamInputStream input_stream{
      std::make_unique<std::stringstream>("0123456789012345678901234567890")};

  ASSERT_THAT(AesCtrHmacStreamingKeyManager()
                  .DeriveKey(key_format, &input_stream)
                  .status(),
              Not(IsOk()));
}

TEST(AesCtrHmacStreamingKeyManagerTest, DeriveKeyWrongVersion) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_version(1);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  util::IstreamInputStream input_stream{
      std::make_unique<std::stringstream>("0123456789abcdef")};

  ASSERT_THAT(
      AesCtrHmacStreamingKeyManager()
          .DeriveKey(key_format, &input_stream)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("version")));
}

using AesCtrHmacStreamingKeyManagerTestVectorTest =
    testing::TestWithParam<StreamingAeadTestVector>;

TEST_P(AesCtrHmacStreamingKeyManagerTestVectorTest, Decrypt) {
  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());
  const StreamingAeadTestVector& param = GetParam();
  // Prepare an InputStream with the ciphertext.
  auto ct_bytes = std::make_unique<std::stringstream>(param.ciphertext);
  auto ct_source =
      std::make_unique<util::IstreamInputStream>(std::move(ct_bytes));
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
    AesCtrHmacStreamingKeyManagerTestVectorTest,
    AesCtrHmacStreamingKeyManagerTestVectorTest,
    testing::ValuesIn(internal::CreateAesCtrHmacStreamingTestVectors()));

}  // namespace
}  // namespace tink
}  // namespace crypto
