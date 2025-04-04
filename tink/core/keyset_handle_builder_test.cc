// Copyright 2022 Google LLC
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

#include "tink/keyset_handle_builder.h"

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/config/global_registry.h"
#include "tink/config/tink_config.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/partial_key_access.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_cmac.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCmacParams;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::testing::_;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::SizeIs;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::Values;

class KeysetHandleBuilderTest : public Test {
 protected:
  void SetUp() override {
    absl::Status status = TinkConfig::Register();
    ASSERT_TRUE(status.ok()) << status;
  }
};

using KeysetHandleBuilderDeathTest = KeysetHandleBuilderTest;

absl::StatusOr<internal::LegacyProtoParameters> CreateLegacyProtoParameters(
    KeyTemplate key_template) {
  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(key_template);
  if (!serialization.ok()) return serialization.status();

  return internal::LegacyProtoParameters(*serialization);
}

// Creates an XChaCha20Poly1305Key from the given parameters.
absl::StatusOr<std::unique_ptr<XChaCha20Poly1305Key>>
CreateXChaCha20Poly1305Key(const XChaCha20Poly1305Parameters& params,
                           absl::optional<int> id_requirement) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      params.GetVariant(), secret, id_requirement, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<crypto::tink::XChaCha20Poly1305Key>(*key);
}

// Creates an AesGcmSivKey from the given parameters.
absl::StatusOr<std::unique_ptr<AesGcmSivKey>> CreateAesGcmSivKey(
    const AesGcmSivParameters& params, absl::optional<int> id_requirement) {
  RestrictedData secret =
      RestrictedData(/*num_random_bytes=*/params.KeySizeInBytes());
  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      params, secret, id_requirement, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<crypto::tink::AesGcmSivKey>(*key);
}

TEST_F(KeysetHandleBuilderTest, BuildWithSingleKey) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  EXPECT_THAT(*handle, SizeIs(1));

  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[0].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());
}

TEST_F(KeysetHandleBuilderTest, BuildWithMultipleKeys) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDisabled,
          /*is_primary=*/false, /*id=*/789);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build();
  ASSERT_THAT(handle.status(), IsOk());
  EXPECT_THAT(*handle, SizeIs(3));

  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kDestroyed));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[0].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());

  EXPECT_THAT((*handle)[1].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[1].GetId(), Eq(456));
  EXPECT_THAT((*handle)[1].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[1].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());

  EXPECT_THAT((*handle)[2].GetStatus(), Eq(KeyStatus::kDisabled));
  EXPECT_THAT((*handle)[2].GetId(), Eq(789));
  EXPECT_THAT((*handle)[2].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[2].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());
}

using KeysetHandleBuilderCustomConfigTest =
    TestWithParam<XChaCha20Poly1305Parameters::Variant>;

INSTANTIATE_TEST_SUITE_P(
    KeysetHandleBuilderCustomConfigTestSuite,
    KeysetHandleBuilderCustomConfigTest,
    Values(XChaCha20Poly1305Parameters::Variant::kTink,
           XChaCha20Poly1305Parameters::Variant::kNoPrefix));

TEST_P(KeysetHandleBuilderCustomConfigTest, BuildWithSingleKey) {
  XChaCha20Poly1305Parameters::Variant variant = GetParam();

  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(variant);
  ASSERT_THAT(params.status(), IsOk());

  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_creator_config),
              IsOk());

  KeyGenConfiguration key_manager_config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyTypeManager(
          absl::make_unique<XChaCha20Poly1305KeyManager>(), key_manager_config),
      IsOk());

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);
  absl::StatusOr<KeysetHandle> handle1 = KeysetHandleBuilder()
                                             .AddEntry(std::move(entry1))
                                             .Build(key_creator_config);
  ASSERT_THAT(handle1.status(), IsOk());

  EXPECT_THAT(*handle1, SizeIs(1));
  EXPECT_THAT((*handle1)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle1)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle1)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle1)[0].GetKey()->GetParameters(), Eq(*params));

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);
  absl::StatusOr<KeysetHandle> handle2 = KeysetHandleBuilder()
                                             .AddEntry(std::move(entry2))
                                             .Build(key_manager_config);
  ASSERT_THAT(handle2.status(), IsOk());

  EXPECT_THAT(*handle2, SizeIs(1));
  EXPECT_THAT((*handle2)[0].GetStatus(), Eq((*handle1)[0].GetStatus()));
  EXPECT_THAT((*handle2)[0].GetId(), Eq((*handle1)[0].GetId()));
  EXPECT_THAT((*handle2)[0].IsPrimary(), Eq((*handle1)[0].IsPrimary()));
  EXPECT_THAT((*handle2)[0].GetKey()->GetParameters(), Eq((*params)));
}

TEST(KeysetHandleBuilderCustomConfigTest, BuildWithEmptyConfigFails) {
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(params.status(), IsOk());

  KeyGenConfiguration config;

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build(config);
  EXPECT_THAT(handle.status(), StatusIs(absl::StatusCode::kNotFound));
}

TEST(KeysetHandleBuilderCustomConfigTest,
     BuildWithMultipleKeysUsingKeyCreators) {
  absl::StatusOr<XChaCha20Poly1305Parameters> xchacha_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(xchacha_parameters.status(), IsOk());

  absl::StatusOr<AesGcmSivParameters> aes_gcm_siv_parameters =
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/32,
                                  AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(aes_gcm_siv_parameters.status(), IsOk());

  KeyGenConfiguration config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyCreator<
          XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key, config),
      IsOk());
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyCreator<AesGcmSivParameters>(
          CreateAesGcmSivKey, config),
      IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *xchacha_parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *aes_gcm_siv_parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *xchacha_parameters, KeyStatus::kDisabled,
          /*is_primary=*/false);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build(config);
  ASSERT_THAT(handle.status(), IsOk());
  EXPECT_THAT(*handle, SizeIs(3));

  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kDestroyed));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[0].GetKey()->GetParameters(), Eq(*xchacha_parameters));

  EXPECT_THAT((*handle)[1].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[1].GetId(), Eq(456));
  EXPECT_THAT((*handle)[1].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[1].GetKey()->GetParameters(),
              Eq(*aes_gcm_siv_parameters));

  EXPECT_THAT((*handle)[2].GetStatus(), Eq(KeyStatus::kDisabled));
  EXPECT_THAT((*handle)[2].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[2].GetKey()->GetParameters(), Eq(*xchacha_parameters));
}

TEST(KeysetHandleBuilderCustomConfigTest,
     BuildWithMultipleKeysUsingKeyManagers) {
  absl::StatusOr<XChaCha20Poly1305Parameters> xchacha_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(xchacha_parameters.status(), IsOk());

  absl::StatusOr<AesGcmSivParameters> aes_gcm_siv_parameters =
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/32,
                                  AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(aes_gcm_siv_parameters.status(), IsOk());

  KeyGenConfiguration config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<XChaCha20Poly1305KeyManager>(), config),
              IsOk());
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmSivKeyManager>(), config),
              IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *xchacha_parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *aes_gcm_siv_parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *xchacha_parameters, KeyStatus::kDisabled,
          /*is_primary=*/false);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build(config);
  ASSERT_THAT(handle.status(), IsOk());
  EXPECT_THAT(*handle, SizeIs(3));

  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kDestroyed));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[0].GetKey()->GetParameters(), Eq(*xchacha_parameters));

  EXPECT_THAT((*handle)[1].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[1].GetId(), Eq(456));
  EXPECT_THAT((*handle)[1].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[1].GetKey()->GetParameters(),
              Eq(*aes_gcm_siv_parameters));

  EXPECT_THAT((*handle)[2].GetStatus(), Eq(KeyStatus::kDisabled));
  EXPECT_THAT((*handle)[2].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[2].GetKey()->GetParameters(), Eq(*xchacha_parameters));
}

TEST_F(KeysetHandleBuilderTest, BuildCopy) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDisabled,
          /*is_primary=*/false, /*id=*/789);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build();
  ASSERT_THAT(handle.status(), IsOk());

  absl::StatusOr<KeysetHandle> copy = KeysetHandleBuilder(*handle).Build();
  ASSERT_THAT(copy.status(), IsOk());
  EXPECT_THAT(copy->size(), Eq(3));

  EXPECT_THAT((*copy)[0].GetStatus(), Eq(KeyStatus::kDestroyed));
  EXPECT_THAT((*copy)[0].GetId(), Eq(123));
  EXPECT_THAT((*copy)[0].IsPrimary(), IsFalse());
  EXPECT_THAT((*copy)[0].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());

  EXPECT_THAT((*copy)[1].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*copy)[1].GetId(), Eq(456));
  EXPECT_THAT((*copy)[1].IsPrimary(), IsTrue());
  EXPECT_THAT((*copy)[1].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());

  EXPECT_THAT((*copy)[2].GetStatus(), Eq(KeyStatus::kDisabled));
  EXPECT_THAT((*copy)[2].GetId(), Eq(789));
  EXPECT_THAT((*copy)[2].IsPrimary(), IsFalse());
  EXPECT_THAT((*copy)[2].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());
}

TEST_F(KeysetHandleBuilderTest, IsPrimary) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(*parameters,
                                                           KeyStatus::kEnabled,
                                                           /*is_primary=*/false,
                                                           /*id=*/123);
  EXPECT_THAT(entry.IsPrimary(), IsFalse());

  entry.SetPrimary();
  EXPECT_THAT(entry.IsPrimary(), IsTrue());
}

TEST_F(KeysetHandleBuilderTest, SetAndGetStatus) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/123);

  entry.SetStatus(KeyStatus::kDisabled);
  EXPECT_THAT(entry.GetStatus(), Eq(KeyStatus::kDisabled));
  entry.SetStatus(KeyStatus::kEnabled);
  EXPECT_THAT(entry.GetStatus(), Eq(KeyStatus::kEnabled));
  entry.SetStatus(KeyStatus::kDestroyed);
  EXPECT_THAT(entry.GetStatus(), Eq(KeyStatus::kDestroyed));
}

TEST_F(KeysetHandleBuilderTest, BuildWithRandomId) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry primary =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  KeysetHandleBuilder builder;
  builder.AddEntry(std::move(primary));

  int num_non_primary_entries = 1 << 16;
  for (int i = 0; i < num_non_primary_entries; ++i) {
    KeysetHandleBuilder::Entry non_primary =
        KeysetHandleBuilder::Entry::CreateFromCopyableParams(
            *parameters, KeyStatus::kEnabled, /*is_primary=*/false);
    builder.AddEntry(std::move(non_primary));
  }

  absl::StatusOr<KeysetHandle> handle = builder.Build();
  ASSERT_THAT(handle.status(), IsOk());

  std::set<int> ids;
  for (int i = 0; i < handle->size(); ++i) {
    ids.insert((*handle)[i].GetId());
  }
  EXPECT_THAT(ids, SizeIs(num_non_primary_entries + 1));
}

TEST_F(KeysetHandleBuilderTest, BuildWithRandomIdAfterFixedId) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry fixed =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder::Entry random =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(fixed))
                                            .AddEntry(std::move(random))
                                            .Build();
  ASSERT_THAT(handle.status(), IsOk());

  EXPECT_THAT(*handle, SizeIs(2));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
}

TEST_F(KeysetHandleBuilderTest, BuildWithFixedIdAfterRandomIdFails) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry random =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false);

  KeysetHandleBuilder::Entry fixed =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(random))
                                            .AddEntry(std::move(fixed))
                                            .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleBuilderDeathTest, AddEntryToAnotherBuilderCrashes) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder builder0;
  builder0.AddEntry(std::move(entry));
  KeysetHandleBuilder builder1;
  EXPECT_DEATH_IF_SUPPORTED(
      builder1.AddEntry(std::move(builder0[0])),
      "Keyset handle builder entry already added to a builder.");
}

TEST_F(KeysetHandleBuilderDeathTest, ReAddEntryToSameBuilderCrashes) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder builder;
  builder.AddEntry(std::move(entry));
  EXPECT_DEATH_IF_SUPPORTED(
      builder.AddEntry(std::move(builder[0])),
      "Keyset handle builder entry already added to a builder.");
}

TEST_F(KeysetHandleBuilderDeathTest,
       AddDereferencedEntryToAnotherBuilderCrashes) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder builder0;
  builder0.AddEntry(std::move(entry));
  KeysetHandleBuilder builder1;
  EXPECT_DEATH_IF_SUPPORTED(
      builder1.AddEntry(std::move(*&(builder0[0]))),
      "Keyset handle builder entry already added to a builder.");
}

TEST_F(KeysetHandleBuilderTest, RemoveEntry) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false, /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/456);

  absl::StatusOr<KeysetHandle> handle0 = KeysetHandleBuilder()
                                             .AddEntry(std::move(entry0))
                                             .AddEntry(std::move(entry1))
                                             .Build();
  ASSERT_THAT(handle0.status(), IsOk());
  ASSERT_THAT(*handle0, SizeIs(2));

  absl::StatusOr<KeysetHandle> handle1 =
      KeysetHandleBuilder(*handle0).RemoveEntry(0).Build();
  ASSERT_THAT(handle1.status(), IsOk());
  ASSERT_THAT(*handle1, SizeIs(1));

  EXPECT_THAT((*handle1)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle1)[0].GetId(), Eq(456));
  EXPECT_THAT((*handle1)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle1)[0].GetKey()->GetParameters().HasIdRequirement(),
              IsTrue());
}

TEST_F(KeysetHandleBuilderDeathTest, RemoveOutofRangeIndexEntryCrashes) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  ASSERT_THAT(*handle, SizeIs(1));

  EXPECT_DEATH_IF_SUPPORTED(
      KeysetHandleBuilder(*handle).RemoveEntry(1),
      "Keyset handle builder entry removal index out of range.");
}

TEST_F(KeysetHandleBuilderTest, Size) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder builder;
  ASSERT_THAT(builder, SizeIs(0));
  builder.AddEntry(std::move(entry0));
  ASSERT_THAT(builder, SizeIs(1));
  builder.AddEntry(std::move(entry1));
  EXPECT_THAT(builder, SizeIs(2));
}

TEST_F(KeysetHandleBuilderTest, NoPrimaryFails) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/456);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleBuilderTest, RemovePrimaryFails) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/456);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .RemoveEntry(0)
                                            .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleBuilderTest, AddPrimaryClearsOtherPrimary) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder builder;
  builder.AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
      *parameters, KeyStatus::kEnabled,
      /*is_primary=*/true,
      /*id=*/123));
  builder.AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
      *parameters, KeyStatus::kEnabled,
      /*is_primary=*/true,
      /*id=*/456));

  ASSERT_THAT(builder[0].IsPrimary(), IsFalse());
  ASSERT_THAT(builder[1].IsPrimary(), IsTrue());
}

TEST_F(KeysetHandleBuilderTest, NoIdStrategySucceeds) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle, IsOk());
}

TEST_F(KeysetHandleBuilderTest, DuplicateId) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled,
              /*is_primary=*/true,
              /*id=*/123))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled,
              /*is_primary=*/false,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromParams) {
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromParams(
          absl::make_unique<AesCmacParameters>(std::move(*params)),
          KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromLegacyKey) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::DISABLED,
             KeyData::SYMMETRIC, &keyset);

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          key.key_data().type_url(),
          RestrictedData(key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          static_cast<KeyMaterialTypeEnum>(key.key_data().key_material_type()),
          static_cast<OutputPrefixTypeEnum>(key.output_prefix_type()),
          key.key_id());

  absl::StatusOr<internal::LegacyProtoKey> proto_key =
      internal::LegacyProtoKey::Create(*serialization,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(proto_key.status(), IsOk());

  KeysetHandleBuilder::Entry entry = KeysetHandleBuilder::Entry::CreateFromKey(
      absl::make_unique<internal::LegacyProtoKey>(std::move(*proto_key)),
      KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromKey) {
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(32);
  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  KeysetHandleBuilder::Entry entry = KeysetHandleBuilder::Entry::CreateFromKey(
      absl::make_unique<AesCmacKey>(std::move(*key)), KeyStatus::kEnabled,
      /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest,
       MergeTwoKeysetsWithTheSameIdButNoIdRequirementWorks) {
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromParams(
          absl::make_unique<AesCmacParameters>(std::move(*params)),
          KeyStatus::kEnabled, /*is_primary=*/true);
  entry1.SetFixedId(123);
  absl::StatusOr<KeysetHandle> handle1 =
      KeysetHandleBuilder().AddEntry(std::move(entry1)).Build();
  ASSERT_THAT(handle1.status(), IsOk());

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromParams(
          absl::make_unique<AesCmacParameters>(std::move(*params)),
          KeyStatus::kEnabled, /*is_primary=*/true);
  entry2.SetFixedId(123);
  absl::StatusOr<KeysetHandle> handle2 =
      KeysetHandleBuilder().AddEntry(std::move(entry2)).Build();
  ASSERT_THAT(handle2.status(), IsOk());

  // handle1 and handle2 each contain one key with the same ID, but no ID
  // requirement. We can add them to a new keyset because they will get new,
  // random and distinct IDs.
  absl::StatusOr<KeysetHandle> handle12 =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              (*handle1)[0].GetKey(), KeyStatus::kEnabled, /*is_primary=*/true))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              (*handle2)[0].GetKey(), KeyStatus::kEnabled,
              /*is_primary=*/false))
          .Build();
  ASSERT_THAT(handle12.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromCopyableKey) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::DISABLED,
             KeyData::SYMMETRIC, &keyset);

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          key.key_data().type_url(),
          RestrictedData(key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          static_cast<KeyMaterialTypeEnum>(key.key_data().key_material_type()),
          static_cast<OutputPrefixTypeEnum>(key.output_prefix_type()),
          key.key_id());

  absl::StatusOr<internal::LegacyProtoKey> proto_key =
      internal::LegacyProtoKey::Create(*serialization,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(proto_key.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *proto_key, KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromParameters) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromParams(
          absl::make_unique<internal::LegacyProtoParameters>(*parameters),
          KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromCopyableParameters) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, UsePrimitiveFromLegacyProtoParams) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      handle->GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac("some input");
  ASSERT_THAT(tag.status(), IsOk());
  absl::Status verified = (*mac)->VerifyMac(*tag, "some input");
  EXPECT_THAT(verified, IsOk());
}

TEST_F(KeysetHandleBuilderTest, UsePrimitiveFromParams) {
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromParams(
          absl::make_unique<AesCmacParameters>(std::move(*params)),
          KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      handle->GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac("some input");
  ASSERT_THAT(tag.status(), IsOk());
  absl::Status verified = (*mac)->VerifyMac(*tag, "some input");
  EXPECT_THAT(verified, IsOk());
}

TEST_F(KeysetHandleBuilderTest, UsePrimitiveFromLegacyProtoKey) {
  AesCmacParams params;
  params.set_tag_size(16);
  google::crypto::tink::AesCmacKey key;
  *key.mutable_params() = params;
  key.set_version(0);
  key.set_key_value(subtle::Random::GetRandomBytes(32));

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey",
          RestrictedData(key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<internal::LegacyProtoKey> proto_key =
      internal::LegacyProtoKey::Create(*serialization,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(proto_key.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *proto_key, KeyStatus::kEnabled, /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      handle->GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac("some input");
  ASSERT_THAT(tag.status(), IsOk());
  absl::Status verified = (*mac)->VerifyMac(*tag, "some input");
  EXPECT_THAT(verified, IsOk());
}

TEST_F(KeysetHandleBuilderTest, UsePrimitiveFromKey) {
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(32);
  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  KeysetHandleBuilder::Entry entry = KeysetHandleBuilder::Entry::CreateFromKey(
      absl::make_unique<AesCmacKey>(std::move(*key)), KeyStatus::kEnabled,
      /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      handle->GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac("some input");
  ASSERT_THAT(tag.status(), IsOk());
  absl::Status verified = (*mac)->VerifyMac(*tag, "some input");
  EXPECT_THAT(verified, IsOk());
}

TEST_F(KeysetHandleBuilderTest, BuildTwiceFails) {
  absl::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);

  KeysetHandleBuilder builder;
  builder.AddEntry(std::move(entry));

  EXPECT_THAT(builder.Build(), IsOk());
  EXPECT_THAT(builder.Build().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleBuilderTest, BuildEmptyKeysetHandleFails) {
  EXPECT_THAT(KeysetHandleBuilder().Build().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("Cannot build empty keyset.")));
}

TEST_F(KeysetHandleBuilderTest, UsePrimitivesFromSplitKeyset) {
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *params, KeyStatus::kEnabled, /*is_primary=*/false))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *params, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOkAndHolds(SizeIs(2)));

  absl::StatusOr<KeysetHandle> handle0 =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              (*handle)[0].GetKey(), KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle0, IsOkAndHolds(SizeIs(1)));
  ASSERT_THAT((*handle)[0].GetId(), Eq((*handle0)[0].GetId()));

  absl::StatusOr<KeysetHandle> handle1 =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              (*handle)[1].GetKey(), KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle1, IsOkAndHolds(SizeIs(1)));
  ASSERT_THAT((*handle)[1].GetId(), Eq((*handle1)[0].GetId()));

  absl::StatusOr<std::unique_ptr<Mac>> mac0 =
      handle0->GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac0.status(), IsOk());
  absl::StatusOr<std::string> tag0 = (*mac0)->ComputeMac("some input");
  ASSERT_THAT(tag0.status(), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac1 =
      handle1->GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac1.status(), IsOk());
  absl::StatusOr<std::string> tag1 = (*mac1)->ComputeMac("some other input");
  ASSERT_THAT(tag1.status(), IsOk());

  // Use original keyset to verify tags computed from new keysets.
  absl::StatusOr<std::unique_ptr<Mac>> mac =
      handle->GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag0, "some input"), IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag1, "some other input"), IsOk());
}

class MockAeadPrimitiveWrapper : public PrimitiveWrapper<Aead, Aead> {
 public:
  MOCK_METHOD(absl::StatusOr<std::unique_ptr<Aead>>, Wrap,
              (std::unique_ptr<PrimitiveSet<Aead>> primitive_set),
              (const, override));
};

class FakeAeadKeyManager
    : public KeyTypeManager<AesGcmKeyProto, AesGcmKeyFormat, List<Aead>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
   public:
    explicit AeadFactory(absl::string_view key_type) : key_type_(key_type) {}

    absl::StatusOr<std::unique_ptr<Aead>> Create(
        const AesGcmKeyProto& key) const override {
      return {absl::make_unique<test::DummyAead>(key_type_)};
    }

   private:
    const std::string key_type_;
  };

  explicit FakeAeadKeyManager(absl::string_view key_type)
      : KeyTypeManager(absl::make_unique<AeadFactory>(key_type)),
        key_type_(key_type) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  uint32_t get_version() const override { return 0; }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(const AesGcmKeyProto& key) const override {
    return absl::OkStatus();
  }

  absl::Status ValidateKeyFormat(
      const AesGcmKeyFormat& key_format) const override {
    return absl::OkStatus();
  }

  absl::StatusOr<AesGcmKeyProto> CreateKey(
      const AesGcmKeyFormat& key_format) const override {
    return AesGcmKeyProto();
  }

  absl::StatusOr<AesGcmKeyProto> DeriveKey(
      const AesGcmKeyFormat& key_format,
      InputStream* input_stream) const override {
    return AesGcmKeyProto();
  }

 private:
  const std::string key_type_;
};

TEST_F(KeysetHandleBuilderTest, BuildWithAnnotations) {
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};
  absl::StatusOr<AesGcmParameters> aes_128_gcm =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(aes_128_gcm, IsOk());

  absl::StatusOr<KeysetHandle> keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *aes_128_gcm, crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .SetMonitoringAnnotations(kAnnotations)
          .Build();
  ASSERT_THAT(keyset_handle, IsOk());

  // In order to validate annotations are set correctly, we need acceess to the
  // generated primitive set, which is populated by KeysetWrapperImpl and passed
  // to the primitive wrapper. We thus register a mock primitive wrapper for
  // Aead so that we can copy the annotations and later check them.
  auto primitive_wrapper = absl::make_unique<MockAeadPrimitiveWrapper>();
  absl::flat_hash_map<std::string, std::string> generated_annotations;
  EXPECT_CALL(*primitive_wrapper, Wrap(_))
      .WillOnce(
          [&generated_annotations](
              std::unique_ptr<PrimitiveSet<Aead>> generated_primitive_set) {
            generated_annotations = generated_primitive_set->get_annotations();
            std::unique_ptr<Aead> aead = absl::make_unique<test::DummyAead>("");
            return aead;
          });
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(std::move(primitive_wrapper)),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<FakeAeadKeyManager>(
                      "type.googleapis.com/google.crypto.tink.AesGcmKey"),
                  /*new_key_allowed=*/true),
              IsOk());

  ASSERT_THAT(
      keyset_handle->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()),
      IsOk());
  EXPECT_EQ(generated_annotations, kAnnotations);
  // This is needed to cleanup mocks.
  Registry::Reset();
}

}  // namespace
}  // namespace tink
}  // namespace crypto
