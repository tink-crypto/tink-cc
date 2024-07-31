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

#include "tink/kem/internal/kem_encapsulate_wrapper.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_KYBER
#include "openssl/experimental/kyber.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_aes_gcm.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/primitive_set.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;

AesGcmParameters CreateAes256GcmParameters() {
  CHECK_OK(AeadConfig::Register());

  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

std::unique_ptr<KemEncapsulate> CreateMlKemEncapsulateAes256Gcm(
    absl::optional<int> id_requirement) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  CHECK_OK(key_parameters);

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, id_requirement);
  CHECK_OK(private_key);

  util::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   CreateAes256GcmParameters());
  CHECK_OK(encapsulate.status());

  return std::move(*encapsulate);
}

TEST(KemEncapsulateWrapperTest, WrapNullptr) {
  EXPECT_THAT(KemEncapsulateWrapper().Wrap(nullptr).status(),
              StatusIs(absl::StatusCode::kInternal, HasSubstr("non-NULL")));
}

TEST(KemEncapsulateWrapperTest, WrapEmpty) {
  EXPECT_THAT(
      KemEncapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemEncapsulate>>())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("no primary")));
}

TEST(KemEncapsulateWrapperTest, WrapNoPrimary) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(0x1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);

  util::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
      PrimitiveSet<KemEncapsulate>::Builder()
          .AddPrimitive(CreateMlKemEncapsulateAes256Gcm(0x1234), key_info)
          .Build();
  ASSERT_THAT(kem_encapsulate_set.status(), IsOk());

  EXPECT_THAT(
      KemEncapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemEncapsulate>>(
              std::move(*kem_encapsulate_set)))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("no primary")));
}

TEST(KemEncapsulateWrapperTest, WrapNonTinkOutputPrefix) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  uint32_t key_id_0 = 0x1234543;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id_0);
  key_info->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_1 = 0x726329;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info->set_key_id(key_id_1);
  key_info->set_status(KeyStatusType::ENABLED);

  util::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
      PrimitiveSet<KemEncapsulate>::Builder()
          .AddPrimaryPrimitive(CreateMlKemEncapsulateAes256Gcm(key_id_0),
                               keyset_info.key_info(0))
          .AddPrimitive(CreateMlKemEncapsulateAes256Gcm(key_id_1),
                        keyset_info.key_info(1))
          .Build();
  ASSERT_THAT(kem_encapsulate_set.status(), IsOk());

  EXPECT_THAT(
      KemEncapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemEncapsulate>>(
              std::move(*kem_encapsulate_set)))
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("kem_encapsulate_set contains non-Tink prefixed key")));
}

TEST(KemEncapsulateWrapperTest, WrapRepeatedKeyId) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  uint32_t key_id = 0x1234543;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id);
  key_info->set_status(KeyStatusType::ENABLED);

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id);
  key_info->set_status(KeyStatusType::ENABLED);

  util::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
      PrimitiveSet<KemEncapsulate>::Builder()
          .AddPrimaryPrimitive(CreateMlKemEncapsulateAes256Gcm(key_id),
                               keyset_info.key_info(0))
          .AddPrimitive(CreateMlKemEncapsulateAes256Gcm(key_id),
                        keyset_info.key_info(1))
          .Build();
  ASSERT_THAT(kem_encapsulate_set.status(), IsOk());

  EXPECT_THAT(
      KemEncapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemEncapsulate>>(
              std::move(*kem_encapsulate_set)))
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "kem_encapsulate_set contains several keys with the same ID")));
}

TEST(KemEncapsulateWrapperTest, WrapMultiple) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  uint32_t key_id_0 = 0x1234543;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id_0);
  key_info->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_1 = 0x726329;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id_1);
  key_info->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 0x7213743;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id_2);
  key_info->set_status(KeyStatusType::ENABLED);

  util::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
      PrimitiveSet<KemEncapsulate>::Builder()
          .AddPrimitive(CreateMlKemEncapsulateAes256Gcm(key_id_0),
                        keyset_info.key_info(0))
          .AddPrimitive(CreateMlKemEncapsulateAes256Gcm(key_id_1),
                        keyset_info.key_info(1))
          // The last key is the primary.
          .AddPrimaryPrimitive(CreateMlKemEncapsulateAes256Gcm(key_id_2),
                               keyset_info.key_info(2))
          .Build();
  ASSERT_THAT(kem_encapsulate_set.status(), IsOk());

  // Wrap kem_encapsulate_set and test the resulting KemEncapsulate.
  util::StatusOr<std::unique_ptr<KemEncapsulate>> kem_encapsulate =
      KemEncapsulateWrapper().Wrap(
          absl::make_unique<PrimitiveSet<KemEncapsulate>>(
              std::move(*kem_encapsulate_set)));
  ASSERT_THAT(kem_encapsulate, IsOk());

  util::StatusOr<KemEncapsulation> encapsulate_result =
      (*kem_encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulate_result, IsOk());
  EXPECT_THAT(encapsulate_result->ciphertext.size(),
              Eq(KYBER_CIPHERTEXT_BYTES + 5));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
