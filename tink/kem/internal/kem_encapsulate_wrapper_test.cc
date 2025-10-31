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
#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "openssl/mlkem.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_aes_gcm.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_client_mocks.h"
#include "tink/internal/registry_impl.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
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
using ::testing::_;
using ::testing::ByMove;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsNull;
using ::testing::Return;
using ::testing::StrictMock;

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

std::unique_ptr<KemEncapsulate> CreateMlKemEncapsulateAes256Gcm(
    absl::optional<int> id_requirement) {
  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ABSL_CHECK_OK(key_parameters);

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, id_requirement);
  ABSL_CHECK_OK(private_key);

  absl::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   CreateAes256GcmParameters());
  ABSL_CHECK_OK(encapsulate.status());

  return std::move(*encapsulate);
}

KeysetInfo CreateKeysetInfo() {
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

  return keyset_info;
}

class KemEncapsulateWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    KeysetInfo keyset_info = CreateKeysetInfo();

    absl::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
        PrimitiveSet<KemEncapsulate>::Builder()
            .AddPrimitive(CreateMlKemEncapsulateAes256Gcm(0x1234543),
                          keyset_info.key_info(0))
            .AddPrimitive(CreateMlKemEncapsulateAes256Gcm(0x726329),
                          keyset_info.key_info(1))
            // The last key is the primary.
            .AddPrimaryPrimitive(CreateMlKemEncapsulateAes256Gcm(0x7213743),
                                 keyset_info.key_info(2))
            .Build();
    ABSL_CHECK_OK(kem_encapsulate_set.status());

    kem_encapsulate_set_ = absl::make_unique<PrimitiveSet<KemEncapsulate>>(
        std::move(*kem_encapsulate_set));
  }

  static constexpr uint32_t kPrimaryKeyId = 0x7213743;

  std::unique_ptr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set_;
};

TEST_F(KemEncapsulateWrapperTest, WrapNullptr) {
  EXPECT_THAT(KemEncapsulateWrapper().Wrap(nullptr).status(),
              StatusIs(absl::StatusCode::kInternal, HasSubstr("non-NULL")));
}

TEST_F(KemEncapsulateWrapperTest, WrapEmpty) {
  EXPECT_THAT(
      KemEncapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemEncapsulate>>())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("no primary")));
}

TEST_F(KemEncapsulateWrapperTest, WrapNoPrimary) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(0x1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);

  absl::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
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

TEST_F(KemEncapsulateWrapperTest, WrapNonTinkOutputPrefix) {
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

  absl::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
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

TEST_F(KemEncapsulateWrapperTest, WrapRepeatedKeyId) {
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

  absl::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
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

TEST_F(KemEncapsulateWrapperTest, WrapMultiple) {
  // Wrap kem_encapsulate_set and test the resulting KemEncapsulate.
  absl::StatusOr<std::unique_ptr<KemEncapsulate>> kem_encapsulate =
      KemEncapsulateWrapper().Wrap(std::move(kem_encapsulate_set_));
  ASSERT_THAT(kem_encapsulate, IsOk());

  absl::StatusOr<KemEncapsulation> encapsulate_result =
      (*kem_encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulate_result, IsOk());
  EXPECT_THAT(encapsulate_result->ciphertext.size(),
              Eq(MLKEM768_CIPHERTEXT_BYTES + 5));
}

// Tests with monitoring enabled.
class KemEncapsulateWrapperTestWithMonitoring
    : public KemEncapsulateWrapperTest {
 protected:
  void SetUp() override {
    Registry::Reset();
    KemEncapsulateWrapperTest::SetUp();

    auto monitoring_client_factory =
        absl::make_unique<internal::MockMonitoringClientFactory>();

    auto encapsulation_monitoring_client =
        absl::make_unique<StrictMock<internal::MockMonitoringClient>>();
    encapsulation_monitoring_client_ptr_ =
        encapsulation_monitoring_client.get();

    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(Return(
            ByMove(absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>(
                std::move(encapsulation_monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  void TearDown() override { Registry::Reset(); }

  internal::MockMonitoringClient* encapsulation_monitoring_client_ptr_;
};

TEST_F(KemEncapsulateWrapperTestWithMonitoring, Encapsulate) {
  absl::StatusOr<std::unique_ptr<KemEncapsulate>> kem_encapsulate =
      KemEncapsulateWrapper().Wrap(std::move(kem_encapsulate_set_));
  ASSERT_THAT(kem_encapsulate, IsOk());

  EXPECT_CALL(*encapsulation_monitoring_client_ptr_, Log(kPrimaryKeyId, 0));
  absl::StatusOr<KemEncapsulation> encapsulate_result =
      (*kem_encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulate_result, IsOk());
  EXPECT_THAT(encapsulate_result->ciphertext.size(),
              Eq(MLKEM768_CIPHERTEXT_BYTES + 5));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
