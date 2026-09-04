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

#include "tink/signature/internal/ecdsa_raw_sign_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

absl::StatusOr<std::string> ComputeDigest(subtle::HashType hash_type,
                                          absl::string_view data) {
  absl::StatusOr<const EVP_MD *> hash =
      internal::EvpHashFromHashType(hash_type);
  if (!hash.ok()) return hash.status();

  unsigned int digest_size;
  uint8_t digest[EVP_MAX_MD_SIZE];
  if (1 != EVP_Digest(data.data(), data.size(), digest, &digest_size, *hash,
                      nullptr)) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Could not compute digest.");
  }

  return std::string(reinterpret_cast<const char*>(digest), digest_size);
}

TEST(EcdsaRawSignBoringSslTest, VerifySignature) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      subtle::EcdsaSignatureEncoding::DER,
      subtle::EcdsaSignatureEncoding::IEEE_P1363};
  for (subtle::EcdsaSignatureEncoding encoding : encodings) {
    const EcKey& ec_key = GetEcKey(subtle::EllipticCurveType::NIST_P256);

    absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>> signer =
        EcdsaRawSignBoringSsl::New(ec_key, encoding);
    ASSERT_THAT(signer, IsOk());

    absl::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verifier =
        subtle::EcdsaVerifyBoringSsl::New(ec_key, subtle::HashType::SHA256,
                                          encoding);
    ASSERT_THAT(verifier, IsOk());

    std::string message = "some data to be signed";
    absl::StatusOr<std::string> message_digest =
        ComputeDigest(subtle::HashType::SHA256, message);
    ASSERT_THAT(message_digest, IsOk());
    absl::StatusOr<std::string> signature =
        (*signer)->SignDigest(*message_digest);
    ASSERT_THAT(signature, IsOkAndHolds(Not(Eq(message))));
    EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
  }
}

TEST(EcdsaRawSignBoringSslTest, VerifySignatureWithEmptyMessage) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      subtle::EcdsaSignatureEncoding::DER,
      subtle::EcdsaSignatureEncoding::IEEE_P1363};
  for (subtle::EcdsaSignatureEncoding encoding : encodings) {
    const EcKey& ec_key = GetEcKey(subtle::EllipticCurveType::NIST_P256);

    absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>> signer =
        EcdsaRawSignBoringSsl::New(ec_key, encoding);
    ASSERT_THAT(signer, IsOk());

    absl::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verifier =
        subtle::EcdsaVerifyBoringSsl::New(ec_key, subtle::HashType::SHA256,
                                          encoding);
    ASSERT_THAT(verifier, IsOk());

    // Message is a null string_view.
    const absl::string_view empty_message;
    absl::StatusOr<std::string> empty_message_digest =
        ComputeDigest(subtle::HashType::SHA256, empty_message);
    ASSERT_THAT(empty_message_digest, IsOk());
    absl::StatusOr<std::string> empty_msg_signature =
        (*signer)->SignDigest(*empty_message_digest);
    ASSERT_THAT(empty_msg_signature, IsOkAndHolds(Not(Eq(empty_message))));
    EXPECT_THAT((*verifier)->Verify(*empty_msg_signature, empty_message),
                IsOk());
  }
}

TEST(EcdsaRawSignBoringSslTest, VerifyFailsWithInvalidMessageOrSignature) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      subtle::EcdsaSignatureEncoding::DER,
      subtle::EcdsaSignatureEncoding::IEEE_P1363};
  for (subtle::EcdsaSignatureEncoding encoding : encodings) {
    const EcKey& ec_key = GetEcKey(subtle::EllipticCurveType::NIST_P256);

    absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>> signer =
        EcdsaRawSignBoringSsl::New(ec_key, encoding);
    ASSERT_THAT(signer, IsOk());

    absl::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verifier =
        subtle::EcdsaVerifyBoringSsl::New(ec_key, subtle::HashType::SHA256,
                                          encoding);
    ASSERT_THAT(verifier, IsOk());

    std::string message = "some data to be signed";
    absl::StatusOr<std::string> message_digest =
        ComputeDigest(subtle::HashType::SHA256, message);
    ASSERT_THAT(message_digest, IsOk());
    absl::StatusOr<std::string> signature =
        (*signer)->SignDigest(*message_digest);
    ASSERT_THAT(signature, IsOkAndHolds(Not(Eq(message))));
    EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());

    EXPECT_THAT((*verifier)->Verify("some bad signature", message),
                Not(IsOk()));
    EXPECT_THAT((*verifier)->Verify(*signature, "some bad message"),
                Not(IsOk()));
  }
}

TEST(EcdsaRawSignBoringSslTest, VerifyFailsWhenEncodingDoesNotMatch) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      subtle::EcdsaSignatureEncoding::DER,
      subtle::EcdsaSignatureEncoding::IEEE_P1363};
  for (subtle::EcdsaSignatureEncoding encoding : encodings) {
    const EcKey& ec_key = GetEcKey(subtle::EllipticCurveType::NIST_P256);

    absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>> signer =
        EcdsaRawSignBoringSsl::New(ec_key, encoding);
    ASSERT_THAT(signer, IsOk());

    absl::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verifier =
        subtle::EcdsaVerifyBoringSsl::New(
            ec_key, subtle::HashType::SHA256,
            encoding == subtle::EcdsaSignatureEncoding::DER
                ? subtle::EcdsaSignatureEncoding::IEEE_P1363
                : subtle::EcdsaSignatureEncoding::DER);
    ASSERT_THAT(verifier, IsOk());

    std::string message = "some data to be signed";
    absl::StatusOr<std::string> message_digest =
        ComputeDigest(subtle::HashType::SHA256, message);
    ASSERT_THAT(message_digest, IsOk());
    absl::StatusOr<std::string> signature =
        (*signer)->SignDigest(*message_digest);
    ASSERT_THAT(signature, IsOkAndHolds(Not(Eq(message))));
    EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
  }
}

TEST(EcdsaRawSignBoringSslTest,
     SignatureSizesAreCorrectWhenUsingIeeeP136Encoding) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EllipticCurveType curves[3] = {subtle::EllipticCurveType::NIST_P256,
                                         subtle::EllipticCurveType::NIST_P384,
                                         subtle::EllipticCurveType::NIST_P521};
  for (subtle::EllipticCurveType curve : curves) {
    const EcKey& ec_key = GetEcKey(curve);

    absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>> signer =
        EcdsaRawSignBoringSsl::New(ec_key,
                                   subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(signer, IsOk());

    absl::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verifier =
        subtle::EcdsaVerifyBoringSsl::New(
            ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verifier, IsOk());

    std::string message = "some data to be signed";
    absl::StatusOr<std::string> message_digest =
        ComputeDigest(subtle::HashType::SHA256, message);
    ASSERT_THAT(message_digest, IsOk());
    absl::StatusOr<std::string> signature =
        (*signer)->SignDigest(*message_digest);
    ASSERT_THAT(signature, IsOkAndHolds(Not(Eq(message))));
    EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());

    // Check signature size.
    absl::StatusOr<int32_t> field_size_in_bytes =
        internal::EcFieldSizeInBytes(curve);
    ASSERT_THAT(field_size_in_bytes, IsOk());
    EXPECT_THAT(*signature, SizeIs(2 * (*field_size_in_bytes)));
  }
}

TEST(EcdsaRawSignBoringSslTest, CreateFailsWithBadPublicKey) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  EcKey ec_key = GetEcKey(subtle::EllipticCurveType::NIST_P256);

  ec_key.pub_x += "corrupted public key x coordinate";
  EXPECT_THAT(
      EcdsaRawSignBoringSsl::New(ec_key, subtle::EcdsaSignatureEncoding::DER),
      Not(IsOk()));
}

TEST(EcdsaRawSignBoringSslTest, NewWithEcKeySuccess) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  absl::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(group, IsOk());
  internal::SslUniquePtr<EC_KEY> ec_key(EC_KEY_new());
  ASSERT_THAT(EC_KEY_set_group(ec_key.get(), group->get()), Eq(1));
  ASSERT_THAT(EC_KEY_generate_key(ec_key.get()), Eq(1));

  absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>> signer =
      EcdsaRawSignBoringSsl::New(std::move(ec_key),
                                 subtle::EcdsaSignatureEncoding::DER);
  EXPECT_THAT(signer, IsOk());
}

// TODO(bleichen): add Wycheproof tests.

// FIPS-only mode test
TEST(EcdsaRawSignBoringSslTest, FipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const EcKey& p256_key = GetEcKey(subtle::EllipticCurveType::NIST_P256);
  EXPECT_THAT(
      EcdsaRawSignBoringSsl::New(p256_key, subtle::EcdsaSignatureEncoding::DER)
          .status(),
      StatusIs(absl::StatusCode::kInternal));

  const EcKey& p384_key = GetEcKey(subtle::EllipticCurveType::NIST_P384);
  EXPECT_THAT(
      EcdsaRawSignBoringSsl::New(p384_key, subtle::EcdsaSignatureEncoding::DER)
          .status(),
      StatusIs(absl::StatusCode::kInternal));

  const EcKey& p521_key = GetEcKey(subtle::EllipticCurveType::NIST_P521);
  EXPECT_THAT(
      EcdsaRawSignBoringSsl::New(p521_key, subtle::EcdsaSignatureEncoding::DER)
          .status(),
      StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
