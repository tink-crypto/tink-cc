// Copyright 2024 Google LLC
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

#include "tink/aead/chacha20_poly1305_key.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/opensslv.h"  // To get OPENSSL_IS_BORINGSSL if needed
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/aead.h"
#endif
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/chacha20_poly1305_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using ChaCha20Poly1305KeyTest = TestWithParam<internal::AeadTestVector>;

INSTANTIATE_TEST_SUITE_P(
    ChaCha20Poly1305KeyTestSuite, ChaCha20Poly1305KeyTest,
    ValuesIn(internal::CreateChaCha20Poly1305TestVectors()));

TEST_P(ChaCha20Poly1305KeyTest, CreateSucceeds) {
  const internal::AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);

  absl::StatusOr<ChaCha20Poly1305Key> created_key = ChaCha20Poly1305Key::Create(
      key.GetParameters().GetVariant(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetKeyBytes(GetPartialKeyAccess()),
              Eq(key.GetKeyBytes(GetPartialKeyAccess())));
  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(created_key->GetOutputPrefix(), Eq(key.GetOutputPrefix()));
}

#ifdef OPENSSL_IS_BORINGSSL
TEST_P(ChaCha20Poly1305KeyTest, Decrypt) {
  const internal::AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);

  absl::string_view ciphertext = test_vector.ciphertext;
  absl::string_view output_prefix = key.GetOutputPrefix();
  ASSERT_TRUE(absl::StartsWith(ciphertext, output_prefix));
  ciphertext.remove_prefix(output_prefix.size());

  ASSERT_GE(ciphertext.size(), 12 + 16);
  absl::string_view nonce = ciphertext.substr(0, 12);
  absl::string_view raw_ct_and_tag = ciphertext.substr(12);

  absl::string_view key_bytes = key.GetKeyBytes(GetPartialKeyAccess())
                                    .GetSecret(InsecureSecretKeyAccess::Get());
  internal::SslUniquePtr<EVP_AEAD_CTX> context(
      EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(),
                       reinterpret_cast<const uint8_t*>(key_bytes.data()),
                       key_bytes.size(), /*tag_len=*/16));
  ASSERT_THAT(context, NotNull());

  std::string decrypted;
  decrypted.resize(raw_ct_and_tag.size());
  size_t out_len = 0;
  ASSERT_TRUE(EVP_AEAD_CTX_open(
      context.get(), reinterpret_cast<uint8_t*>(&decrypted[0]), &out_len,
      decrypted.size(), reinterpret_cast<const uint8_t*>(nonce.data()),
      nonce.size(), reinterpret_cast<const uint8_t*>(raw_ct_and_tag.data()),
      raw_ct_and_tag.size(),
      reinterpret_cast<const uint8_t*>(test_vector.associated_data.data()),
      test_vector.associated_data.size()));
  decrypted.resize(out_len);
  EXPECT_THAT(decrypted, Eq(test_vector.plaintext));
}
#endif

TEST(ChaCha20Poly1305KeyTest, CreateKeyWithInvalidVariantFails) {
  RestrictedData secret = dynamic_cast<const ChaCha20Poly1305Key&>(
                              *internal::GetChaCha20Poly1305TestVector(
                                   ChaCha20Poly1305Parameters::Variant::kTink)
                                   .aead_key)
                              .GetKeyBytes(GetPartialKeyAccess());
  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  secret, /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChaCha20Poly1305KeyTest, CreateKeyWithInvalidKeySizeFails) {
  // Key material must be 32 bytes.
  RestrictedData invalid_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::kTink, invalid_secret,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChaCha20Poly1305KeyTest, CreateKeyWithInvalidIdRequirementFails) {
  RestrictedData secret =
      dynamic_cast<const ChaCha20Poly1305Key&>(
          *internal::GetChaCha20Poly1305TestVector(
               ChaCha20Poly1305Parameters::Variant::kNoPrefix)
               .aead_key)
          .GetKeyBytes(GetPartialKeyAccess());

  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::kNoPrefix, secret,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::kTink, secret,
                  /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(ChaCha20Poly1305KeyTest, KeyEquals) {
  const internal::AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);

  absl::StatusOr<ChaCha20Poly1305Key> created_key = ChaCha20Poly1305Key::Create(
      key.GetParameters().GetVariant(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  absl::StatusOr<ChaCha20Poly1305Key> other_key = ChaCha20Poly1305Key::Create(
      key.GetParameters().GetVariant(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*created_key == *other_key);
  EXPECT_TRUE(*other_key == *created_key);
  EXPECT_FALSE(*created_key != *other_key);
  EXPECT_FALSE(*other_key != *created_key);
}

TEST(ChaCha20Poly1305KeyTest, DifferentVariantNotEqual) {
  const ChaCha20Poly1305Key& crunchy_key =
      dynamic_cast<const ChaCha20Poly1305Key&>(
          *internal::GetChaCha20Poly1305TestVector(
               ChaCha20Poly1305Parameters::Variant::kCrunchy)
               .aead_key);
  const ChaCha20Poly1305Key& tink_key =
      dynamic_cast<const ChaCha20Poly1305Key&>(
          *internal::GetChaCha20Poly1305TestVector(
               ChaCha20Poly1305Parameters::Variant::kTink)
               .aead_key);

  EXPECT_TRUE(crunchy_key != tink_key);
  EXPECT_TRUE(tink_key != crunchy_key);
  EXPECT_FALSE(crunchy_key == tink_key);
  EXPECT_FALSE(tink_key == crunchy_key);
}

TEST(ChaCha20Poly1305KeyTest, DifferentSecretDataNotEqual) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret1,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<ChaCha20Poly1305Key> other_key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret2,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(ChaCha20Poly1305KeyTest, DifferentIdRequirementNotEqual) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<ChaCha20Poly1305Key> other_key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(ChaCha20Poly1305KeyTest, CopyConstructor) {
  const ChaCha20Poly1305Key& key = dynamic_cast<const ChaCha20Poly1305Key&>(
      *internal::GetChaCha20Poly1305TestVector(
           ChaCha20Poly1305Parameters::Variant::kTink)
           .aead_key);

  ChaCha20Poly1305Key copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(ChaCha20Poly1305KeyTest, CopyAssignment) {
  const ChaCha20Poly1305Key& key = dynamic_cast<const ChaCha20Poly1305Key&>(
      *internal::GetChaCha20Poly1305TestVector(
           ChaCha20Poly1305Parameters::Variant::kTink)
           .aead_key);
  const ChaCha20Poly1305Key& other_key =
      dynamic_cast<const ChaCha20Poly1305Key&>(
          *internal::GetChaCha20Poly1305TestVector(
               ChaCha20Poly1305Parameters::Variant::kNoPrefix)
               .aead_key);

  ChaCha20Poly1305Key copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(ChaCha20Poly1305KeyTest, MoveConstructor) {
  ChaCha20Poly1305Key key = dynamic_cast<const ChaCha20Poly1305Key&>(
      *internal::GetChaCha20Poly1305TestVector(
           ChaCha20Poly1305Parameters::Variant::kTink)
           .aead_key);

  ChaCha20Poly1305Key expected = key;
  ChaCha20Poly1305Key moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(ChaCha20Poly1305KeyTest, MoveAssignment) {
  ChaCha20Poly1305Key key = dynamic_cast<const ChaCha20Poly1305Key&>(
      *internal::GetChaCha20Poly1305TestVector(
           ChaCha20Poly1305Parameters::Variant::kTink)
           .aead_key);
  ChaCha20Poly1305Key other_key = dynamic_cast<const ChaCha20Poly1305Key&>(
      *internal::GetChaCha20Poly1305TestVector(
           ChaCha20Poly1305Parameters::Variant::kNoPrefix)
           .aead_key);

  ChaCha20Poly1305Key expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(ChaCha20Poly1305KeyTest, Clone) {
  const ChaCha20Poly1305Key& key = dynamic_cast<const ChaCha20Poly1305Key&>(
      *internal::GetChaCha20Poly1305TestVector(
           ChaCha20Poly1305Parameters::Variant::kTink)
           .aead_key);

  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
