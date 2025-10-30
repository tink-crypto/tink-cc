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

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_aes_gcm.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/config/global_registry.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/internal/fips_utils.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

AesGcmParameters CreateAes256GcmParameters() {
  ABSL_CHECK_OK(AeadConfig::Register());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  return *parameters;
}

TEST(MlKemEncapsulateAes256GcmTest, InvalidAesKeySize) {
  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<AesGcmParameters> aes_128_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(aes_128_parameters, IsOk());

  EXPECT_THAT(
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   *aes_128_parameters)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("AES-GCM parameters are not compatible with ML-KEM")));
}

TEST(MlKemEncapsulateAes256GcmTest, InvalidIdRequirementForDerivedKey) {
  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<AesGcmParameters> aes_tink_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(aes_tink_parameters, IsOk());

  EXPECT_THAT(NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                           *aes_tink_parameters)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Keys derived from an ML-KEM shared secret "
                                 "must not have an ID requirement")));
}

TEST(MlKemEncapsulateAes256GcmTest, EncapsulateDeriveAeadWorks) {
  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   CreateAes256GcmParameters());
  ASSERT_THAT(encapsulate, IsOk());

  absl::StatusOr<KemEncapsulation> encapsulation =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulation, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      encapsulation->keyset_handle.GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt("plaintext", "associated data");
  ASSERT_THAT(ciphertext, IsOk());

  absl::StatusOr<std::string> decrypted =
      (*aead)->Decrypt(*ciphertext, "associated data");
  EXPECT_THAT(decrypted, IsOkAndHolds("plaintext"));

  ASSERT_THAT((*aead)->Decrypt(*ciphertext, "bad associated data").status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlKemRawEncapsulateAes256GcmTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                           CreateAes256GcmParameters())
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
