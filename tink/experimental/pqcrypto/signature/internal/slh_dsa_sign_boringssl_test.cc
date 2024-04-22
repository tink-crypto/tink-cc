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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/internal/slh_dsa_sign_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "openssl/experimental/spx.h"
#undef OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

// Generates a new SLH-DSA-SHA2-128s private key.
util::StatusOr<SlhDsaPrivateKey> NewSlhDsaPrivateKey() {
  std::string public_key_bytes;
  public_key_bytes.resize(SPX_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SPX_SECRET_KEY_BYTES);

  SPX_generate_key(reinterpret_cast<uint8_t*>(public_key_bytes.data()),
                   reinterpret_cast<uint8_t*>(private_key_bytes.data()));

  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SPX_SECRET_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      *parameters, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return SlhDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
}

TEST(SlhDsaSignBoringSslTest, SignatureLengthIsCorrect) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::StatusOr<SlhDsaPrivateKey> private_key = NewSlhDsaPrivateKey();
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SlhDsaSignBoringSsl::New(*private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Check signature size.
  EXPECT_NE(*signature, message);
  EXPECT_EQ((*signature).size(), SPX_SIGNATURE_BYTES);
}

TEST(SlhDsaSignBoringSslTest, SignatureIsNonDeterministic) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::StatusOr<SlhDsaPrivateKey> private_key = NewSlhDsaPrivateKey();
  ASSERT_THAT(private_key, IsOk());

  // Create a signer based on the private key.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SlhDsaSignBoringSsl::New(*private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign the same message twice, using the same private key.
  std::string message = "message to be signed";
  util::StatusOr<std::string> first_signature = (*signer)->Sign(message);
  ASSERT_THAT(first_signature, IsOk());

  util::StatusOr<std::string> second_signature = (*signer)->Sign(message);
  ASSERT_THAT(second_signature, IsOk());

  // Check the signatures' sizes.
  EXPECT_EQ((*first_signature).size(), SPX_SIGNATURE_BYTES);
  EXPECT_EQ((*second_signature).size(), SPX_SIGNATURE_BYTES);

  EXPECT_NE(*first_signature, *second_signature);
}

TEST(SlhDsaSignBoringSslTest, FipsMode) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::StatusOr<SlhDsaPrivateKey> private_key = NewSlhDsaPrivateKey();
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  EXPECT_THAT(SlhDsaSignBoringSsl::New(*private_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
