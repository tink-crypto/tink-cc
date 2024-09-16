// Copyright 2020 Google LLC
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
#include "tink/prf/prf_config.h"

#include <list>
#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/config/global_registry.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/key_gen_config_v0.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/prf/prf_set.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;
using ::testing::NotNull;

class PrfConfigTest : public ::testing::Test {
 protected:
  PrfConfigTest() {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(PrfConfigTest, RegisterWorks) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<Prf>(HmacPrfKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(PrfConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<Prf>(HmacPrfKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// FIPS-only mode tests
TEST_F(PrfConfigTest, RegisterNonFipsTemplates) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(PrfConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(PrfKeyTemplates::HkdfSha256());
  non_fips_key_templates.push_back(PrfKeyTemplates::AesCmac());

  for (auto key_template : non_fips_key_templates) {
    auto new_keyset_handle_result =
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
    EXPECT_THAT(new_keyset_handle_result.status(),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST_F(PrfConfigTest, RegisterFipsValidTemplates) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(PrfConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> fips_key_templates;
  fips_key_templates.push_back(PrfKeyTemplates::HmacSha256());
  fips_key_templates.push_back(PrfKeyTemplates::HmacSha512());

  for (auto key_template : fips_key_templates) {
    auto new_keyset_handle_result =
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
    EXPECT_THAT(new_keyset_handle_result, IsOk());
  }
}

TEST_F(PrfConfigTest, AesCmacPrfProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              PrfKeyTemplates::AesCmac());
  ASSERT_THAT(proto_params_serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(PrfConfig::Register(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(PrfConfigTest, AesCmacPrfProtoKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<KeysetHandle>> before_handle =
      KeysetHandle::GenerateNew(PrfKeyTemplates::AesCmac(),
                                KeyGenConfigPrfV0());
  ASSERT_THAT(before_handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*before_handle)->GetPrimary().GetKey().get()),
              NotNull());

  util::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(RestrictedData(subtle::Random::GetRandomBytes(32),
                                           InsecureSecretKeyAccess::Get()),
                            GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(PrfConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> after_handle =
      KeysetHandle::GenerateNew(PrfKeyTemplates::AesCmac(),
                                KeyGenConfigPrfV0());
  ASSERT_THAT(after_handle, IsOk());

  EXPECT_THAT(dynamic_cast<const AesCmacPrfKey*>(
                  (*after_handle)->GetPrimary().GetKey().get()),
              NotNull());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

TEST_F(PrfConfigTest, HmacPrfProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              PrfKeyTemplates::HmacSha256());
  ASSERT_THAT(proto_params_serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/32, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(PrfConfig::Register(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(PrfConfigTest, HmacPrfProtoKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<KeysetHandle>> before_handle =
      KeysetHandle::GenerateNew(PrfKeyTemplates::HmacSha256(),
                                KeyGenConfigPrfV0());
  ASSERT_THAT(before_handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*before_handle)->GetPrimary().GetKey().get()),
              NotNull());

  util::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/32, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters,
                         RestrictedData(subtle::Random::GetRandomBytes(32),
                                        InsecureSecretKeyAccess::Get()),
                         GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(PrfConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> after_handle =
      KeysetHandle::GenerateNew(PrfKeyTemplates::HmacSha256(),
                                KeyGenConfigPrfV0());
  ASSERT_THAT(after_handle, IsOk());

  EXPECT_THAT(dynamic_cast<const HmacPrfKey*>(
                  (*after_handle)->GetPrimary().GetKey().get()),
              NotNull());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

TEST_F(PrfConfigTest, HkdfPrfProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              PrfKeyTemplates::HkdfSha256());
  ASSERT_THAT(proto_params_serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/32, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(PrfConfig::Register(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(PrfConfigTest, HkdfPrfProtoKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<KeysetHandle>> before_handle =
      KeysetHandle::GenerateNew(PrfKeyTemplates::HkdfSha256(),
                                KeyGenConfigPrfV0());
  ASSERT_THAT(before_handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*before_handle)->GetPrimary().GetKey().get()),
              NotNull());

  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/32, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<HkdfPrfKey> key =
      HkdfPrfKey::Create(*parameters,
                         RestrictedData(subtle::Random::GetRandomBytes(32),
                                        InsecureSecretKeyAccess::Get()),
                         GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(PrfConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> after_handle =
      KeysetHandle::GenerateNew(PrfKeyTemplates::HkdfSha256(),
                                KeyGenConfigPrfV0());
  ASSERT_THAT(after_handle, IsOk());

  EXPECT_THAT(dynamic_cast<const HkdfPrfKey*>(
                  (*after_handle)->GetPrimary().GetKey().get()),
              NotNull());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
