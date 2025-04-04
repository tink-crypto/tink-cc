// Copyright 2019 Google Inc.
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

#include "tink/signature/ed25519_sign_key_manager.h"

#include <memory>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/config/global_registry.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/signature_config.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ed25519.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::Ed25519KeyFormat;
using Ed25519PrivateKeyProto = ::google::crypto::tink::Ed25519PrivateKey;
using Ed25519PublicKeyProto = ::google::crypto::tink::Ed25519PublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(Ed25519SignKeyManagerTest, Basic) {
  EXPECT_THAT(Ed25519SignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(Ed25519SignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(Ed25519SignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"));
}

TEST(Ed25519SignKeyManagerTest, ValidateKeyFormat) {
  EXPECT_THAT(Ed25519SignKeyManager().ValidateKeyFormat(Ed25519KeyFormat()),
              IsOk());
}

TEST(Ed25519SignKeyManagerTest, CreateKey) {
  absl::StatusOr<Ed25519PrivateKeyProto> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or, IsOk());
  Ed25519PrivateKeyProto key = key_or.value();

  EXPECT_THAT(key.version(), Eq(0));

  EXPECT_THAT(key.public_key().version(), Eq(key.version()));

  EXPECT_THAT(key.key_value(), SizeIs(32));
  EXPECT_THAT(key.public_key().key_value(), SizeIs(32));
}

TEST(Ed25519SignKeyManagerTest, CreateKeyValid) {
  absl::StatusOr<Ed25519PrivateKeyProto> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(Ed25519SignKeyManager().ValidateKey(key_or.value()), IsOk());
}

TEST(Ed25519SignKeyManagerTest, CreateKeyAlwaysNew) {
  absl::flat_hash_set<std::string> keys;
  int num_tests = 100;
  for (int i = 0; i < num_tests; ++i) {
    absl::StatusOr<Ed25519PrivateKeyProto> key_or =
        Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
    ASSERT_THAT(key_or, IsOk());
    keys.insert(std::string(key_or.value().key_value()));
  }
  EXPECT_THAT(keys, SizeIs(num_tests));
}

TEST(Ed25519SignKeyManagerTest, GetPublicKey) {
  absl::StatusOr<Ed25519PrivateKeyProto> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or, IsOk());
  absl::StatusOr<Ed25519PublicKeyProto> public_key_or =
      Ed25519SignKeyManager().GetPublicKey(key_or.value());
  ASSERT_THAT(public_key_or, IsOk());
  EXPECT_THAT(public_key_or.value().version(),
              Eq(key_or.value().public_key().version()));
  EXPECT_THAT(public_key_or.value().key_value(),
              Eq(key_or.value().public_key().key_value()));
}

TEST(Ed25519SignKeyManagerTest, Create) {
  absl::StatusOr<Ed25519PrivateKeyProto> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or, IsOk());
  Ed25519PrivateKeyProto key = key_or.value();

  auto signer_or =
      Ed25519SignKeyManager().GetPrimitive<PublicKeySign>(key);
  ASSERT_THAT(signer_or, IsOk());

  auto direct_verifier_or =
      subtle::Ed25519VerifyBoringSsl::New(key.public_key().key_value());

  ASSERT_THAT(direct_verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.value()->Verify(
                  signer_or.value()->Sign(message).value(), message),
              IsOk());
}

TEST(Ed25519SignKeyManagerTest, CreateDifferentKey) {
  absl::StatusOr<Ed25519PrivateKeyProto> key_or =
      Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat());
  ASSERT_THAT(key_or, IsOk());
  Ed25519PrivateKeyProto key = key_or.value();

  auto signer_or =
      Ed25519SignKeyManager().GetPrimitive<PublicKeySign>(key);
  ASSERT_THAT(signer_or, IsOk());

  auto direct_verifier_or =
      subtle::Ed25519VerifyBoringSsl::New("01234567890123456789012345678901");

  ASSERT_THAT(direct_verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.value()->Verify(
                  signer_or.value()->Sign(message).value(), message),
              Not(IsOk()));
}

TEST(Ed25519SignKeyManagerTest, DeriveKey) {
  Ed25519KeyFormat format;

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  absl::StatusOr<Ed25519PrivateKeyProto> key_or =
      Ed25519SignKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(),
              Eq("0123456789abcdef0123456789abcdef"));
}

TEST(Ed25519SignKeyManagerTest, DeriveKeySignVerify) {
  Ed25519KeyFormat format;

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  Ed25519PrivateKeyProto key =
      Ed25519SignKeyManager().DeriveKey(format, &input_stream).value();
  auto signer_or = Ed25519SignKeyManager().GetPrimitive<PublicKeySign>(key);
  ASSERT_THAT(signer_or, IsOk());

  std::string message = "Some message";
  auto signature = signer_or.value()->Sign(message).value();

  auto verifier_or =
      Ed25519VerifyKeyManager().GetPrimitive<PublicKeyVerify>(key.public_key());

  EXPECT_THAT(verifier_or.value()->Verify(signature, message), IsOk());
}

TEST(Ed25519SignKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  Ed25519KeyFormat format;

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("tooshort")};

  ASSERT_THAT(Ed25519SignKeyManager().DeriveKey(format, &input_stream).status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}


using Ed25519SignKeyManagerTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

// Ed25519 is deterministic, so we can compute the signature.
TEST_P(Ed25519SignKeyManagerTestVectorTest, ComputeSignatureInTestVector) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  const internal::SignatureTestVector& param = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.signature_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      handle->GetPrimitive<PublicKeySign>(ConfigGlobalRegistry());
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, Eq(param.signature));
}

TEST_P(Ed25519SignKeyManagerTestVectorTest, VerifySignatureInTestVector) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  const internal::SignatureTestVector& param = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.signature_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(ConfigGlobalRegistry());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    Ed25519SignKeyManagerTestVectorTest,
    Ed25519SignKeyManagerTestVectorTest,
    testing::ValuesIn(internal::CreateEd25519TestVectors()));

}  // namespace
}  // namespace tink
}  // namespace crypto

