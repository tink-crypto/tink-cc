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

#include "tink/kem/internal/kem_decapsulate_wrapper.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/mlkem.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/config/global_registry.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_decapsulate_aes_gcm.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_aes_gcm.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_client_mocks.h"
#include "tink/internal/registry_impl.h"
#include "tink/kem/internal/kem_encapsulate_wrapper.h"
#include "tink/kem/kem_decapsulate.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/keyset_handle.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::ByMove;
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

std::unique_ptr<KemDecapsulate> CreateMlKemDecapsulateAes256Gcm(
    absl::optional<int> id_requirement) {
  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ABSL_CHECK_OK(key_parameters);

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, id_requirement);
  ABSL_CHECK_OK(private_key);

  absl::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters());
  ABSL_CHECK_OK(decapsulate.status());

  return std::move(*decapsulate);
}

std::pair<std::unique_ptr<KemEncapsulate>, std::unique_ptr<KemDecapsulate>>
CreateMlKemPairAes256Gcm(absl::optional<int> id_requirement) {
  AesGcmParameters aes_gcm_parameters = CreateAes256GcmParameters();

  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ABSL_CHECK_OK(key_parameters);

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, id_requirement);
  ABSL_CHECK_OK(private_key);

  absl::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   aes_gcm_parameters);
  ABSL_CHECK_OK(encapsulate.status());

  absl::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, aes_gcm_parameters);
  ABSL_CHECK_OK(decapsulate.status());

  return {std::move(*encapsulate), std::move(*decapsulate)};
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

class KemDecapsulateWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    KeysetInfo keyset_info = CreateKeysetInfo();

    std::pair<std::unique_ptr<KemEncapsulate>, std::unique_ptr<KemDecapsulate>>
        pair0 = CreateMlKemPairAes256Gcm(0x1234543);
    std::pair<std::unique_ptr<KemEncapsulate>, std::unique_ptr<KemDecapsulate>>
        pair1 = CreateMlKemPairAes256Gcm(0x726329);
    std::pair<std::unique_ptr<KemEncapsulate>, std::unique_ptr<KemDecapsulate>>
        pair2 = CreateMlKemPairAes256Gcm(0x7213743);

    absl::StatusOr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set =
        PrimitiveSet<KemEncapsulate>::Builder()
            .AddPrimitive(std::move(pair0.first), keyset_info.key_info(0))
            .AddPrimitive(std::move(pair1.first), keyset_info.key_info(1))
            // The last key is the primary.
            .AddPrimaryPrimitive(std::move(pair2.first),
                                 keyset_info.key_info(2))
            .Build();
    ABSL_CHECK_OK(kem_encapsulate_set.status());

    absl::StatusOr<PrimitiveSet<KemDecapsulate>> kem_decapsulate_set =
        PrimitiveSet<KemDecapsulate>::Builder()
            .AddPrimitive(std::move(pair0.second), keyset_info.key_info(0))
            .AddPrimitive(std::move(pair1.second), keyset_info.key_info(1))
            // The last key is the primary.
            .AddPrimaryPrimitive(std::move(pair2.second),
                                 keyset_info.key_info(2))
            .Build();
    ABSL_CHECK_OK(kem_decapsulate_set.status());

    kem_encapsulate_set_ = absl::make_unique<PrimitiveSet<KemEncapsulate>>(
        std::move(*kem_encapsulate_set));
    kem_decapsulate_set_ = absl::make_unique<PrimitiveSet<KemDecapsulate>>(
        std::move(*kem_decapsulate_set));
  }

  static constexpr uint32_t kPrimaryKeyId = 0x7213743;

  std::unique_ptr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set_;
  std::unique_ptr<PrimitiveSet<KemDecapsulate>> kem_decapsulate_set_;
};

TEST_F(KemDecapsulateWrapperTest, WrapNullptr) {
  EXPECT_THAT(KemDecapsulateWrapper().Wrap(nullptr).status(),
              StatusIs(absl::StatusCode::kInternal, HasSubstr("non-NULL")));
}

TEST_F(KemDecapsulateWrapperTest, WrapEmpty) {
  EXPECT_THAT(
      KemDecapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemDecapsulate>>())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("no primary")));
}

TEST_F(KemDecapsulateWrapperTest, WrapNoPrimary) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(0x1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);

  absl::StatusOr<PrimitiveSet<KemDecapsulate>> kem_decapsulate_set =
      PrimitiveSet<KemDecapsulate>::Builder()
          .AddPrimitive(CreateMlKemDecapsulateAes256Gcm(0x1234), key_info)
          .Build();
  ASSERT_THAT(kem_decapsulate_set.status(), IsOk());

  EXPECT_THAT(
      KemDecapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemDecapsulate>>(
              std::move(*kem_decapsulate_set)))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("no primary")));
}

TEST_F(KemDecapsulateWrapperTest, WrapNonTinkOutputPrefix) {
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

  absl::StatusOr<PrimitiveSet<KemDecapsulate>> kem_decapsulate_set =
      PrimitiveSet<KemDecapsulate>::Builder()
          .AddPrimaryPrimitive(CreateMlKemDecapsulateAes256Gcm(0x1234543),
                               keyset_info.key_info(0))
          .AddPrimitive(CreateMlKemDecapsulateAes256Gcm(0x726329),
                        keyset_info.key_info(1))
          .Build();
  ASSERT_THAT(kem_decapsulate_set.status(), IsOk());

  EXPECT_THAT(
      KemDecapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemDecapsulate>>(
              std::move(*kem_decapsulate_set)))
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("kem_decapsulate_set contains non-Tink prefixed key")));
}

TEST_F(KemDecapsulateWrapperTest, WrapRepeatedKeyId) {
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

  absl::StatusOr<PrimitiveSet<KemDecapsulate>> kem_decapsulate_set =
      PrimitiveSet<KemDecapsulate>::Builder()
          .AddPrimaryPrimitive(CreateMlKemDecapsulateAes256Gcm(0x1234543),
                               keyset_info.key_info(0))
          .AddPrimitive(CreateMlKemDecapsulateAes256Gcm(0x1234543),
                        keyset_info.key_info(1))
          .Build();
  ASSERT_THAT(kem_decapsulate_set.status(), IsOk());

  EXPECT_THAT(
      KemDecapsulateWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KemDecapsulate>>(
              std::move(*kem_decapsulate_set)))
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "kem_decapsulate_set contains several keys with the same ID")));
}

TEST_F(KemDecapsulateWrapperTest, WrapMultiple) {
  absl::StatusOr<std::unique_ptr<KemDecapsulate>> kem_decapsulate =
      KemDecapsulateWrapper().Wrap(std::move(kem_decapsulate_set_));
  EXPECT_THAT(kem_decapsulate, IsOk());
}

TEST_F(KemDecapsulateWrapperTest, DecapsulateUnknownKeyID) {
  absl::StatusOr<std::unique_ptr<KemDecapsulate>> kem_decapsulate =
      KemDecapsulateWrapper().Wrap(std::move(kem_decapsulate_set_));
  ASSERT_THAT(kem_decapsulate, IsOk());

  absl::StatusOr<KeysetHandle> decapsulate =
      (*kem_decapsulate)->Decapsulate("random_bytes");
  EXPECT_THAT(
      decapsulate.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("decapsulation failed: no key found for the given ID")));
}

TEST_F(KemDecapsulateWrapperTest, DecapsulateArbitraryBytes) {
  absl::StatusOr<std::unique_ptr<KemDecapsulate>> kem_decapsulate =
      KemDecapsulateWrapper().Wrap(std::move(kem_decapsulate_set_));
  ASSERT_THAT(kem_decapsulate, IsOk());

  // Decapsulating with the primary key works.
  absl::StatusOr<KeysetHandle> decapsulate =
      (*kem_decapsulate)
          ->Decapsulate(
              absl::StrCat("\x01", HexDecodeOrDie("07213743"),
                           std::string(MLKEM768_CIPHERTEXT_BYTES, 'A')));
  EXPECT_THAT(decapsulate.status(), IsOk());

  // Decapsulating also works with a non-primary key.
  decapsulate = (*kem_decapsulate)
                    ->Decapsulate(absl::StrCat(
                        "\x01", HexDecodeOrDie("01234543"),
                        std::string(MLKEM768_CIPHERTEXT_BYTES, 'A')));
  EXPECT_THAT(decapsulate.status(), IsOk());

  // Decapsulating doesn't work with an unknown prefix.
  decapsulate = (*kem_decapsulate)
                    ->Decapsulate(absl::StrCat(
                        "\x01", HexDecodeOrDie("01234567"),
                        std::string(MLKEM768_CIPHERTEXT_BYTES, 'A')));
  EXPECT_THAT(
      decapsulate.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("decapsulation failed: no key found for the given ID")));
}

TEST_F(KemDecapsulateWrapperTest, EncapsulateDecapsulate) {
  // KEM encapsulate.
  absl::StatusOr<std::unique_ptr<KemEncapsulate>> kem_encapsulate =
      KemEncapsulateWrapper().Wrap(std::move(kem_encapsulate_set_));
  ASSERT_THAT(kem_encapsulate, IsOk());

  // KEM decapsulate.
  absl::StatusOr<std::unique_ptr<KemDecapsulate>> kem_decapsulate =
      KemDecapsulateWrapper().Wrap(std::move(kem_decapsulate_set_));
  ASSERT_THAT(kem_decapsulate, IsOk());

  // Exchange an encapsulation and derive AEAD primitives.
  absl::StatusOr<KemEncapsulation> encapsulation =
      (*kem_encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulation, IsOk());

  absl::StatusOr<KeysetHandle> decapsulation =
      (*kem_decapsulate)->Decapsulate(encapsulation->ciphertext);
  ASSERT_THAT(decapsulation, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> encaps_aead =
      encapsulation->keyset_handle.GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(encaps_aead, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> decaps_aead =
      decapsulation->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(decaps_aead, IsOk());

  // Check that the AEAD primitives are compatible.
  absl::StatusOr<std::string> ciphertext =
      (*encaps_aead)->Encrypt("plaintext", "associated data");
  ASSERT_THAT(ciphertext, IsOk());

  absl::StatusOr<std::string> decrypted =
      (*decaps_aead)->Decrypt(*ciphertext, "associated data");
  EXPECT_THAT(decrypted, IsOkAndHolds("plaintext"));

  EXPECT_THAT(
      (*decaps_aead)->Decrypt(*ciphertext, "bad associated data").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  // The AEAD primitives are also compatible for messages sent in the other
  // direction.
  absl::StatusOr<std::string> ciphertext2 =
      (*decaps_aead)->Encrypt("plaintext 2", "associated data 2");
  ASSERT_THAT(ciphertext2, IsOk());

  absl::StatusOr<std::string> decrypted2 =
      (*encaps_aead)->Decrypt(*ciphertext2, "associated data 2");
  EXPECT_THAT(decrypted2, IsOkAndHolds("plaintext 2"));

  EXPECT_THAT(
      (*encaps_aead)->Decrypt(*ciphertext2, "bad associated data").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

// Tests with monitoring enabled.
class KemDecapsulateWrapperTestWithMonitoring
    : public KemDecapsulateWrapperTest {
 protected:
  void SetUp() override {
    Registry::Reset();
    KemDecapsulateWrapperTest::SetUp();

    auto monitoring_client_factory =
        absl::make_unique<internal::MockMonitoringClientFactory>();

    auto encapsulation_monitoring_client =
        absl::make_unique<StrictMock<internal::MockMonitoringClient>>();
    encapsulation_monitoring_client_ptr_ =
        encapsulation_monitoring_client.get();

    auto decapsulation_monitoring_client =
        absl::make_unique<StrictMock<internal::MockMonitoringClient>>();
    decapsulation_monitoring_client_ptr_ =
        decapsulation_monitoring_client.get();

    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(Return(
            ByMove(absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>(
                std::move(encapsulation_monitoring_client)))))
        .WillOnce(Return(
            ByMove(absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>(
                std::move(decapsulation_monitoring_client)))));

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
  internal::MockMonitoringClient* decapsulation_monitoring_client_ptr_;
};

TEST_F(KemDecapsulateWrapperTestWithMonitoring, EncapsulateDecapsulate) {
  // KEM encapsulate.
  absl::StatusOr<std::unique_ptr<KemEncapsulate>> kem_encapsulate =
      KemEncapsulateWrapper().Wrap(std::move(kem_encapsulate_set_));
  ASSERT_THAT(kem_encapsulate, IsOk());

  // KEM decapsulate.
  absl::StatusOr<std::unique_ptr<KemDecapsulate>> kem_decapsulate =
      KemDecapsulateWrapper().Wrap(std::move(kem_decapsulate_set_));
  ASSERT_THAT(kem_decapsulate, IsOk());

  // Exchange an encapsulation and derive AEAD primitives.
  EXPECT_CALL(*encapsulation_monitoring_client_ptr_, Log(kPrimaryKeyId, 0));
  absl::StatusOr<KemEncapsulation> encapsulation =
      (*kem_encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulation, IsOk());

  EXPECT_CALL(*decapsulation_monitoring_client_ptr_,
              Log(kPrimaryKeyId, encapsulation->ciphertext.size()));
  absl::StatusOr<KeysetHandle> decapsulation =
      (*kem_decapsulate)->Decapsulate(encapsulation->ciphertext);
  ASSERT_THAT(decapsulation, IsOk());
}

TEST_F(KemDecapsulateWrapperTestWithMonitoring, DecapsulateUnknownKeyID) {
  // KEM encapsulate.
  absl::StatusOr<std::unique_ptr<KemEncapsulate>> kem_encapsulate =
      KemEncapsulateWrapper().Wrap(std::move(kem_encapsulate_set_));
  ASSERT_THAT(kem_encapsulate, IsOk());

  // KEM decapsulate.
  absl::StatusOr<std::unique_ptr<KemDecapsulate>> kem_decapsulate =
      KemDecapsulateWrapper().Wrap(std::move(kem_decapsulate_set_));
  ASSERT_THAT(kem_decapsulate, IsOk());

  EXPECT_CALL(*decapsulation_monitoring_client_ptr_, LogFailure());
  absl::StatusOr<KeysetHandle> decapsulate =
      (*kem_decapsulate)->Decapsulate("random_bytes");
  EXPECT_THAT(
      decapsulate.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("decapsulation failed: no key found for the given ID")));
}

TEST_F(KemDecapsulateWrapperTestWithMonitoring, DecapsulateArbitraryBytes) {
  // KEM encapsulate.
  absl::StatusOr<std::unique_ptr<KemEncapsulate>> kem_encapsulate =
      KemEncapsulateWrapper().Wrap(std::move(kem_encapsulate_set_));
  ASSERT_THAT(kem_encapsulate, IsOk());

  // KEM decapsulate.
  absl::StatusOr<std::unique_ptr<KemDecapsulate>> kem_decapsulate =
      KemDecapsulateWrapper().Wrap(std::move(kem_decapsulate_set_));
  ASSERT_THAT(kem_decapsulate, IsOk());

  // Decapsulating with the primary key works.
  EXPECT_CALL(*decapsulation_monitoring_client_ptr_,
              Log(0x07213743, MLKEM768_CIPHERTEXT_BYTES + 5));
  absl::StatusOr<KeysetHandle> decapsulate =
      (*kem_decapsulate)
          ->Decapsulate(
              absl::StrCat("\x01", HexDecodeOrDie("07213743"),
                           std::string(MLKEM768_CIPHERTEXT_BYTES, 'A')));
  EXPECT_THAT(decapsulate.status(), IsOk());

  // Decapsulating also works with a non-primary key.
  EXPECT_CALL(*decapsulation_monitoring_client_ptr_,
              Log(0x01234543, MLKEM768_CIPHERTEXT_BYTES + 5));
  decapsulate = (*kem_decapsulate)
                    ->Decapsulate(absl::StrCat(
                        "\x01", HexDecodeOrDie("01234543"),
                        std::string(MLKEM768_CIPHERTEXT_BYTES, 'A')));
  EXPECT_THAT(decapsulate.status(), IsOk());

  // Decapsulating doesn't work with an unknown prefix.
  EXPECT_CALL(*decapsulation_monitoring_client_ptr_, LogFailure());
  decapsulate = (*kem_decapsulate)
                    ->Decapsulate(absl::StrCat(
                        "\x01", HexDecodeOrDie("01234567"),
                        std::string(MLKEM768_CIPHERTEXT_BYTES, 'A')));
  EXPECT_THAT(
      decapsulate.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("decapsulation failed: no key found for the given ID")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
