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

#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"

#include <stdint.h>

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/subtle/aes_ctr_boringssl.h"
#include "tink/subtle/encrypt_then_authenticate.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/ind_cpa_cipher.h"
#include "tink/util/enums.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using AesCtrHmacAeadKeyProto = ::google::crypto::tink::AesCtrHmacAeadKey;
using ::google::crypto::tink::AesCtrHmacAeadKeyFormat;
using ::google::crypto::tink::HashType;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(AesCtrHmacAeadKeyManagerTest, Basics) {
  EXPECT_THAT(AesCtrHmacAeadKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesCtrHmacAeadKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"));
  EXPECT_THAT(AesCtrHmacAeadKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesCtrHmacAeadKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKey(AesCtrHmacAeadKeyProto()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

AesCtrHmacAeadKeyProto CreateValidKey() {
  AesCtrHmacAeadKeyProto key;
  key.set_version(0);
  auto aes_ctr_key = key.mutable_aes_ctr_key();
  aes_ctr_key->set_key_value(std::string(16, 'a'));
  aes_ctr_key->mutable_params()->set_iv_size(12);
  auto hmac_key = key.mutable_hmac_key();
  hmac_key->set_key_value(std::string(16, 'b'));
  hmac_key->mutable_params()->set_hash(HashType::SHA1);
  hmac_key->mutable_params()->set_tag_size(10);
  return key;
}

TEST(AesCtrHmacAeadKeyManagerTest, ValidKey) {
  EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKey(CreateValidKey()), IsOk());
}

TEST(AesCtrHmacAeadKeyManagerTest, AesKeySizes) {
  AesCtrHmacAeadKeyProto key = CreateValidKey();
  for (int len = 0; len < 42; len++) {
    key.mutable_aes_ctr_key()->set_key_value(std::string(len, 'a'));
    if (len == 16 || len == 32) {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKey(key), IsOk())
          << " for length " << len;
    } else {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKey(key), Not(IsOk()))
          << " for length " << len;
    }
  }
}

TEST(AesCtrHmacAeadKeyManagerTest, HmacKeySizes) {
  AesCtrHmacAeadKeyProto key = CreateValidKey();
  for (int len = 0; len < 42; len++) {
    key.mutable_hmac_key()->set_key_value(std::string(len, 'b'));
    if (len >= 16) {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKey(key), IsOk())
          << " for length " << len;
    } else {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKey(key), Not(IsOk()))
          << " for length " << len;
    }
  }
}

AesCtrHmacAeadKeyFormat CreateValidKeyFormat() {
  AesCtrHmacAeadKeyFormat key_format;
  auto aes_ctr_key_format = key_format.mutable_aes_ctr_key_format();
  aes_ctr_key_format->set_key_size(16);
  aes_ctr_key_format->mutable_params()->set_iv_size(16);
  auto hmac_key_format = key_format.mutable_hmac_key_format();
  hmac_key_format->set_key_size(21);
  hmac_key_format->mutable_params()->set_hash(HashType::SHA256);
  hmac_key_format->mutable_params()->set_tag_size(16);
  return key_format;
}

TEST(AesCtrHmacAeadKeyManagerTest, ValidateKeyFormat) {
  AesCtrHmacAeadKeyFormat key_format = CreateValidKeyFormat();
  EXPECT_THAT(
      AesCtrHmacAeadKeyManager().ValidateKeyFormat(CreateValidKeyFormat()),
      IsOk());
}

TEST(AesCtrHmacAeadKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(
      AesCtrHmacAeadKeyManager().ValidateKeyFormat(AesCtrHmacAeadKeyFormat()),
      Not(IsOk()));
}

TEST(AesCtrHmacAeadKeyManagerTest, ValidateKeyFormatKeySizes) {
  AesCtrHmacAeadKeyFormat key_format = CreateValidKeyFormat();
  for (int len = 0; len < 42; ++len) {
    key_format.mutable_aes_ctr_key_format()->set_key_size(len);
    IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcde0123456789abcdefghijklmnopqrztuvwxyz0123456789abcde01"
      "23456789abcdefghijklmnopqrztuvwxyz0123456789abcde0123456789abcdefghi"
      "jklmnopqrztuvwxyz")};
    if (len == 16 || len == 32) {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKeyFormat(key_format),
                  IsOk())
          << "for length " << len;
      EXPECT_THAT(
          AesCtrHmacAeadKeyManager().DeriveKey(key_format, &input_stream),
          IsOk());
    } else {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKeyFormat(key_format),
                  Not(IsOk()))
          << "for length " << len;
      EXPECT_THAT(
          AesCtrHmacAeadKeyManager().DeriveKey(key_format, &input_stream),
          Not(IsOk()));
    }
  }
}

TEST(AesCtrHmacAeadKeyManagerTest, ValidateKeyFormatHmacKeySizes) {
  AesCtrHmacAeadKeyFormat key_format = CreateValidKeyFormat();
  for (int len = 0; len < 42; ++len) {
    key_format.mutable_hmac_key_format()->set_key_size(len);
    IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcde0123456789abcdefghijklmnopqrztuvwxyz0123456789abcde01"
      "23456789abcdefghijklmnopqrztuvwxyz0123456789abcde0123456789abcdefghi"
      "jklmnopqrztuvwxyz")};
    if (len >= 16) {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKeyFormat(key_format),
                  IsOk())
          << "for length " << len;
      EXPECT_THAT(
          AesCtrHmacAeadKeyManager().DeriveKey(key_format, &input_stream),
          IsOk());
    } else {
      EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKeyFormat(key_format),
                  Not(IsOk()))
          << "for length " << len;
      EXPECT_THAT(
          AesCtrHmacAeadKeyManager().DeriveKey(key_format, &input_stream),
          Not(IsOk()));
    }
  }
}

TEST(AesCtrHmacAeadKeyManagerTest, CreateKey) {
  AesCtrHmacAeadKeyFormat key_format = CreateValidKeyFormat();
  absl::StatusOr<AesCtrHmacAeadKeyProto> key_or =
      AesCtrHmacAeadKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  const AesCtrHmacAeadKeyProto& key = key_or.value();
  EXPECT_THAT(AesCtrHmacAeadKeyManager().ValidateKey(key),
              IsOk());
  EXPECT_THAT(key.aes_ctr_key().params().iv_size(),
              Eq(key_format.aes_ctr_key_format().params().iv_size()));
  EXPECT_THAT(key.aes_ctr_key().key_value(),
              SizeIs(key_format.aes_ctr_key_format().key_size()));
  EXPECT_THAT(key.hmac_key().params().hash(),
              Eq(key_format.hmac_key_format().params().hash()));
  EXPECT_THAT(key.hmac_key().params().tag_size(),
              Eq(key_format.hmac_key_format().params().tag_size()));
  EXPECT_THAT(key.hmac_key().key_value(),
              SizeIs(key_format.hmac_key_format().key_size()));
}

TEST(AesCtrHmacAeadKeyManagerTest, CreateAead) {
  AesCtrHmacAeadKeyProto key = CreateValidKey();

  absl::StatusOr<std::unique_ptr<Aead>> aead_or =
      AesCtrHmacAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(aead_or, IsOk());

  auto direct_aes_ctr_or = subtle::AesCtrBoringSsl::New(
      util::SecretDataFromStringView(key.aes_ctr_key().key_value()),
      key.aes_ctr_key().params().iv_size());
  ASSERT_THAT(direct_aes_ctr_or, IsOk());

  auto direct_hmac_or = subtle::HmacBoringSsl::New(
      util::Enums::ProtoToSubtle(key.hmac_key().params().hash()),
      key.hmac_key().params().tag_size(),
      util::SecretDataFromStringView(key.hmac_key().key_value()));
  ASSERT_THAT(direct_hmac_or, IsOk());

  auto direct_aead_or = subtle::EncryptThenAuthenticate::New(
      std::move(direct_aes_ctr_or.value()), std::move(direct_hmac_or.value()),
      key.hmac_key().params().tag_size());
  ASSERT_THAT(direct_aead_or, IsOk());

  EXPECT_THAT(EncryptThenDecrypt(*aead_or.value(), *direct_aead_or.value(),
                                 "message", "aad"),
              IsOk());
}

TEST(AesCtrHmacAeadKeyManagerTest, Derive16ByteKey) {
  AesCtrHmacAeadKeyFormat key_format;
  key_format.mutable_aes_ctr_key_format()->set_key_size(16);
  key_format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(16);
  key_format.mutable_hmac_key_format()->set_key_size(16);
  key_format.mutable_hmac_key_format()->mutable_params()->set_tag_size(16);
  key_format.mutable_hmac_key_format()->mutable_params()->set_hash(
      google::crypto::tink::SHA256);
  key_format.mutable_hmac_key_format()->set_version(0);

  IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcde_YELLOW_SUBMARINE_EXTRA")};

  absl::StatusOr<AesCtrHmacAeadKeyProto> derived_key =
      AesCtrHmacAeadKeyManager().DeriveKey(key_format, &input_stream);
  ASSERT_THAT(derived_key, IsOk());
  EXPECT_THAT(derived_key.value().aes_ctr_key().key_value(),
              Eq("0123456789abcde_"));
  EXPECT_THAT(derived_key.value().hmac_key().key_value(),
              Eq("YELLOW_SUBMARINE"));
  EXPECT_THAT(derived_key.value().hmac_key().params().hash(),
              key_format.hmac_key_format().params().hash());
  EXPECT_THAT(derived_key.value().hmac_key().params().tag_size(),
              key_format.hmac_key_format().params().tag_size());
  EXPECT_THAT(derived_key.value().aes_ctr_key().params().iv_size(),
              Eq(key_format.aes_ctr_key_format().params().iv_size()));
}

TEST(AesCtrHmacAeadKeyManagerTest, Derive32ByteKey) {
  AesCtrHmacAeadKeyFormat format;
  format.mutable_aes_ctr_key_format()->set_key_size(32);
  format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(16);
  format.mutable_hmac_key_format()->set_key_size(32);
  format.mutable_hmac_key_format()->mutable_params()->set_tag_size(16);
  format.mutable_hmac_key_format()->mutable_params()->set_hash(
      google::crypto::tink::SHA256);
  format.mutable_hmac_key_format()->set_version(0);

  IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcde0123456789abcdef_YELLOW_SUBMARINE_YELLOW_SUBMARIN")};

  absl::StatusOr<AesCtrHmacAeadKeyProto> derived_key =
      AesCtrHmacAeadKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(derived_key, IsOk());
  EXPECT_THAT(derived_key.value().aes_ctr_key().key_value(),
              Eq("0123456789abcde0123456789abcdef_"));
  EXPECT_THAT(derived_key.value().hmac_key().key_value(),
              Eq("YELLOW_SUBMARINE_YELLOW_SUBMARIN"));
}

TEST(AesCtrHmacAeadKeyManagerTest, DeriveKeyNotEnoughRandomnessForAesCtrKey) {
  AesCtrHmacAeadKeyFormat format;
  format.mutable_aes_ctr_key_format()->set_key_size(32);
  format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(16);
  format.mutable_hmac_key_format()->set_key_size(32);
  format.mutable_hmac_key_format()->mutable_params()->set_tag_size(16);
  format.mutable_hmac_key_format()->mutable_params()->set_hash(
      google::crypto::tink::SHA256);
  format.mutable_hmac_key_format()->set_version(0);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789")};

  ASSERT_THAT(
      AesCtrHmacAeadKeyManager().DeriveKey(format, &input_stream).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacAeadKeyManagerTest, DeriveKeyNotEnoughRandomnessForHmacKey) {
  AesCtrHmacAeadKeyFormat format;
  format.mutable_aes_ctr_key_format()->set_key_size(16);
  format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(16);
  format.mutable_hmac_key_format()->set_key_size(32);
  format.mutable_hmac_key_format()->mutable_params()->set_tag_size(16);
  format.mutable_hmac_key_format()->mutable_params()->set_hash(
      google::crypto::tink::SHA256);
  format.mutable_hmac_key_format()->set_version(0);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("YELLOW_SUBMARINE")};

  ASSERT_THAT(
      AesCtrHmacAeadKeyManager().DeriveKey(format, &input_stream).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
