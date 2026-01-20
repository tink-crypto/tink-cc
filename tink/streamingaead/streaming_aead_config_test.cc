// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/streaming_aead_config.h"

#include <list>
#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/config/global_registry.h"
#include "tink/config/tink_fips.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/partial_key_access.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/streamingaead/key_gen_config_v0.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyStreamingAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;
using ::testing::IsNull;

class StreamingAeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(StreamingAeadConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesGcmHkdfStreamingKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesCtrHmacStreamingKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(StreamingAeadConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesGcmHkdfStreamingKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesCtrHmacStreamingKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the StreamingAeadWrapper has been properly registered
// and we can wrap primitives.
TEST_F(StreamingAeadConfigTest, WrappersRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  PrimitiveSet<StreamingAead>::Builder saead_set_builder;
  saead_set_builder.AddPrimaryPrimitive(
      absl::make_unique<DummyStreamingAead>("dummy"), key_info);
  absl::StatusOr<PrimitiveSet<StreamingAead>> primitive_set =
      std::move(saead_set_builder).Build();
  ASSERT_THAT(primitive_set, IsOk());

  auto primitive_result = Registry::Wrap(
      std::make_unique<PrimitiveSet<StreamingAead>>(*std::move(primitive_set)));
  ASSERT_THAT(primitive_result, IsOk()) << primitive_result.status();
}

// FIPS-only mode tests
TEST_F(StreamingAeadConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(StreamingAeadConfig::Register(), IsOk());

  // Check that we can not retrieve non-FIPS keyset handle
  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes128GcmHkdf4KB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes256GcmHkdf1MB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes256GcmHkdf4KB());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry())
            .status(),
        StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST_F(StreamingAeadConfigTest,
       AesCtrHmacStreamingProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB());
  ASSERT_THAT(proto_params_serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(4096)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(StreamingAeadConfigTest,
       AesCtrHmacStreamingProtoKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<std::unique_ptr<KeysetHandle>> before_handle =
      KeysetHandle::GenerateNew(
          StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB(),
          KeyGenConfigStreamingAeadV0());
  ASSERT_THAT(before_handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*before_handle)->GetPrimary().GetKey().get()),
              Not(IsNull()));

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(4096)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters,
      RestrictedData(subtle::Random::GetRandomBytes(35),
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

  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> after_handle =
      KeysetHandle::GenerateNew(
          StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB(),
          KeyGenConfigStreamingAeadV0());
  ASSERT_THAT(after_handle, IsOk());

  EXPECT_THAT(dynamic_cast<const AesCtrHmacStreamingKey*>(
                  (*after_handle)->GetPrimary().GetKey().get()),
              Not(IsNull()));

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

TEST_F(StreamingAeadConfigTest,
       AesGcmHkdfStreamingProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              StreamingAeadKeyTemplates::Aes128GcmHkdf4KB());
  ASSERT_THAT(proto_params_serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(4096)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(StreamingAeadConfigTest,
       AesGcmHkdfStreamingProtoKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<std::unique_ptr<KeysetHandle>> before_handle =
      KeysetHandle::GenerateNew(StreamingAeadKeyTemplates::Aes128GcmHkdf4KB(),
                                KeyGenConfigStreamingAeadV0());
  ASSERT_THAT(before_handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*before_handle)->GetPrimary().GetKey().get()),
              Not(IsNull()));

  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(4096)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters,
      RestrictedData(subtle::Random::GetRandomBytes(35),
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

  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> after_handle =
      KeysetHandle::GenerateNew(StreamingAeadKeyTemplates::Aes128GcmHkdf4KB(),
                                KeyGenConfigStreamingAeadV0());
  ASSERT_THAT(after_handle, IsOk());

  EXPECT_THAT(dynamic_cast<const AesGcmHkdfStreamingKey*>(
                  (*after_handle)->GetPrimary().GetKey().get()),
              Not(IsNull()));

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
