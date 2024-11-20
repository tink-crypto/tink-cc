// Copyright 2024 Google LLC
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

#include "tink/internal/global_serialization_registry.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::TestWithParam;
using ::testing::Values;

struct KeyTestVector {
  std::shared_ptr<const Key> key;
};

std::unique_ptr<const AesCmacPrfKey> CreateAesCmacPrfKey() {
  util::StatusOr<AesCmacPrfKey> key = AesCmacPrfKey::Create(
      RestrictedData(/*num_random_bytes=*/32), GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const AesCmacPrfKey>(*key);
}

std::unique_ptr<const AesCtrHmacAeadKey> CreateAesCtrHmacAeadKey() {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters);

  util::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(RestrictedData(/*num_random_bytes=*/32))
          .SetHmacKeyBytes(RestrictedData(/*num_random_bytes=*/32))
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());

  return absl::make_unique<const AesCtrHmacAeadKey>(*key);
}

std::unique_ptr<const AesGcmKey> CreateAesGcmKey() {
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters);

  util::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/16),
                        /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const AesGcmKey>(*key);
}

std::unique_ptr<const AesGcmSivKey> CreateAesGcmSivKey() {
  util::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/16, AesGcmSivParameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<AesGcmSivKey> key =
      AesGcmSivKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/16),
                           /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const AesGcmSivKey>(*key);
}

std::unique_ptr<const ChaCha20Poly1305Key> CreateChaCha20Poly1305Key() {
  util::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink,
      RestrictedData(/*num_random_bytes=*/32), /*id_requirement=*/123,
      GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const ChaCha20Poly1305Key>(*key);
}

std::unique_ptr<const HkdfPrfKey> CreateHkdfPrfKey() {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  CHECK_OK(parameters);

  util::StatusOr<HkdfPrfKey> key =
      HkdfPrfKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/16),
                         GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const HkdfPrfKey>(*key);
}

std::unique_ptr<const HmacPrfKey> CreateHmacPrfKey() {
  util::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  CHECK_OK(parameters);

  util::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/16),
                         GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const HmacPrfKey>(*key);
}

std::unique_ptr<const LegacyKmsAeadKey> CreateLegacyKmsAeadKey() {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create("key_uri",
                                      LegacyKmsAeadParameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, /*id_requirement=*/123);
  CHECK_OK(key);

  return absl::make_unique<const LegacyKmsAeadKey>(*key);
}

std::unique_ptr<const XAesGcmKey> CreateXAesGcmKey() {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, /*salt_size_bytes=*/12);
  CHECK_OK(parameters);

  util::StatusOr<XAesGcmKey> key =
      XAesGcmKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/32),
                         /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const XAesGcmKey>(*key);
}

std::unique_ptr<const XChaCha20Poly1305Key> CreateXChaCha20Poly1305Key() {
  util::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kTink,
      RestrictedData(/*num_random_bytes=*/32), /*id_requirement=*/123,
      GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const XChaCha20Poly1305Key>(*key);
}

using GlobalSerializationRegistryTest = TestWithParam<KeyTestVector>;

INSTANTIATE_TEST_SUITE_P(GlobalSerializationRegistryTests,
                         GlobalSerializationRegistryTest,
                         Values(KeyTestVector{CreateAesCmacPrfKey()},
                                KeyTestVector{CreateAesCtrHmacAeadKey()},
                                KeyTestVector{CreateAesGcmKey()},
                                KeyTestVector{CreateAesGcmSivKey()},
                                KeyTestVector{CreateChaCha20Poly1305Key()},
                                KeyTestVector{CreateHkdfPrfKey()},
                                KeyTestVector{CreateHmacPrfKey()},
                                KeyTestVector{CreateLegacyKmsAeadKey()},
                                KeyTestVector{CreateXAesGcmKey()},
                                KeyTestVector{CreateXChaCha20Poly1305Key()}));

TEST_P(GlobalSerializationRegistryTest, SerializeAndParse) {
  const KeyTestVector& test_case = GetParam();

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      GlobalSerializationRegistry().SerializeKey<ProtoKeySerialization>(
          *test_case.key, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      GlobalSerializationRegistry().ParseKey(
          **serialization, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(parsed_key, IsOk());

  EXPECT_TRUE(**parsed_key == *test_case.key);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
