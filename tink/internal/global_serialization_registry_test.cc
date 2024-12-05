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
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
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
#include "tink/big_integer.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
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

std::unique_ptr<const AesCmacKey> CreateAesCmacKey() {
  util::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/32),
                         /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const AesCmacKey>(*key);
}

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

std::unique_ptr<const AesEaxKey> CreateAesEaxKey() {
  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters);

  util::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/16),
                        /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const AesEaxKey>(*key);
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

std::unique_ptr<const AesSivKey> CreateAesSivKey() {
  util::StatusOr<AesSivParameters> parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/32, AesSivParameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<AesSivKey> key =
      AesSivKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/32),
                        /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const AesSivKey>(*key);
}

std::unique_ptr<const ChaCha20Poly1305Key> CreateChaCha20Poly1305Key() {
  util::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink,
      RestrictedData(/*num_random_bytes=*/32), /*id_requirement=*/123,
      GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const ChaCha20Poly1305Key>(*key);
}

std::unique_ptr<const EcdsaPrivateKey> CreateEcdsaPrivateKey() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters);

  util::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  CHECK_OK(ec_key);

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(public_key);

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           GetInsecureSecretKeyAccessInternal());

  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  CHECK_OK(private_key);

  return absl::make_unique<const EcdsaPrivateKey>(*private_key);
}

std::unique_ptr<const EcdsaPublicKey> CreateEcdsaPublicKey() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters);

  util::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  CHECK_OK(ec_key);

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(public_key);

  return absl::make_unique<const EcdsaPublicKey>(*public_key);
}

std::unique_ptr<const Ed25519PrivateKey> CreateEd25519PrivateKey() {
  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<std::unique_ptr<Ed25519Key>> key_pair = NewEd25519Key();
  CHECK_OK(key_pair);

  util::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*parameters, (*key_pair)->public_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(public_key);

  RestrictedData private_key_bytes = RestrictedData(
      (*key_pair)->private_key, GetInsecureSecretKeyAccessInternal());

  util::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  CHECK_OK(private_key);

  return absl::make_unique<const Ed25519PrivateKey>(*private_key);
}

std::unique_ptr<const Ed25519PublicKey> CreateEd25519PublicKey() {
  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<Ed25519PublicKey> key =
      Ed25519PublicKey::Create(*parameters, subtle::Random::GetRandomBytes(32),
                               /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const Ed25519PublicKey>(*key);
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

std::unique_ptr<const HmacKey> CreateHmacKey() {
  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<HmacKey> key =
      HmacKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/32),
                      /*id_requirement=*/123, GetPartialKeyAccess());
  CHECK_OK(key);

  return absl::make_unique<const HmacKey>(*key);
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

INSTANTIATE_TEST_SUITE_P(
    GlobalSerializationRegistryTests, GlobalSerializationRegistryTest,
    Values(KeyTestVector{CreateAesCmacKey()},
           KeyTestVector{CreateAesCmacPrfKey()},
           KeyTestVector{CreateAesCtrHmacAeadKey()},
           KeyTestVector{CreateAesEaxKey()},
           KeyTestVector{CreateAesGcmKey()},
           KeyTestVector{CreateAesGcmSivKey()},
           KeyTestVector{CreateAesSivKey()},
           KeyTestVector{CreateChaCha20Poly1305Key()},
           KeyTestVector{CreateEcdsaPrivateKey()},
           KeyTestVector{CreateEcdsaPublicKey()},
           KeyTestVector{CreateEd25519PrivateKey()},
           KeyTestVector{CreateEd25519PublicKey()},
           KeyTestVector{CreateHkdfPrfKey()},
           KeyTestVector{CreateHmacKey()},
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
