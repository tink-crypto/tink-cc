// Copyright 2026 Google LLC
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

#include "tink/internal/testing/test_only_key.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/configuration.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "proto/test_proto.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestProto;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::Values;

struct ParametersTestCase {
  TestOnlyParameters::Variant variant;
  bool has_id_requirement;
};

using TestOnlyParametersVariantTest = TestWithParam<ParametersTestCase>;

INSTANTIATE_TEST_SUITE_P(
    TestOnlyParametersVariantTestSuite, TestOnlyParametersVariantTest,
    Values(ParametersTestCase{TestOnlyParameters::Variant::kTink, true},
           ParametersTestCase{TestOnlyParameters::Variant::kCrunchy, true},
           ParametersTestCase{TestOnlyParameters::Variant::kLegacy, true},
           ParametersTestCase{TestOnlyParameters::Variant::kNoPrefix, false}));

TEST_P(TestOnlyParametersVariantTest, Create) {
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetVariant(), Eq(GetParam().variant));
  EXPECT_THAT(parameters->HasIdRequirement(),
              Eq(GetParam().has_id_requirement));
}

TEST_P(TestOnlyParametersVariantTest, ProtoSerializationRoundTrip) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();

  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTestOnlyKeyTypeUrl));
  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(**serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*parameters));
}

TEST(TestOnlyParametersTest, ParseInvalidKeyFormatFails) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  TestProto wrong_key_size;
  wrong_key_size.set_num(kTestOnlyKeySizeInBytes + 1);
  TestProto unexpected_field;
  unexpected_field.set_num(kTestOnlyKeySizeInBytes);
  unexpected_field.set_str("unexpected");

  for (const TestProto& key_format : {wrong_key_size, unexpected_field}) {
    KeyTemplate key_template;
    key_template.set_type_url(kTestOnlyKeyTypeUrl);
    key_template.set_output_prefix_type(OutputPrefixType::TINK);
    key_template.set_value(key_format.SerializeAsString());
    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(key_template);
    ASSERT_THAT(serialization, IsOk());

    EXPECT_THAT(MutableSerializationRegistry::GlobalInstance().ParseParameters(
                    *serialization),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TestOnlyParametersTest, InvalidVariantFails) {
  EXPECT_THAT(TestOnlyParameters::Create(
                  TestOnlyParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements),
              Not(IsOk()));
}

TEST(TestOnlyParametersTest, ParametersWithDifferentVariantsAreNotEqual) {
  absl::StatusOr<TestOnlyParameters> tink_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyParameters> other_tink_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(other_tink_parameters, IsOk());
  absl::StatusOr<TestOnlyParameters> crunchy_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_parameters, IsOk());

  EXPECT_THAT(*tink_parameters == *other_tink_parameters, IsTrue());
  EXPECT_THAT(*tink_parameters != *crunchy_parameters, IsTrue());
}

constexpr int kKeyId = 0x01020304;

struct KeyTestCase {
  TestOnlyParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using TestOnlySymmetricKeyVariantTest = TestWithParam<KeyTestCase>;

INSTANTIATE_TEST_SUITE_P(
    TestOnlySymmetricKeyVariantTestSuite, TestOnlySymmetricKeyVariantTest,
    Values(KeyTestCase{TestOnlyParameters::Variant::kTink, kKeyId,
                       "\x01\x01\x02\x03\x04"},
           KeyTestCase{TestOnlyParameters::Variant::kCrunchy, kKeyId,
                       std::string("\x00\x01\x02\x03\x04", 5)},
           KeyTestCase{TestOnlyParameters::Variant::kLegacy, kKeyId,
                       std::string("\x00\x01\x02\x03\x04", 5)},
           KeyTestCase{TestOnlyParameters::Variant::kNoPrefix, std::nullopt,
                       ""}));

TEST_P(TestOnlySymmetricKeyVariantTest, Create) {
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  RestrictedData key_bytes("key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<TestOnlySymmetricKey> key = TestOnlySymmetricKey::Create(
      *parameters, key_bytes, GetParam().id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(key_bytes));
  EXPECT_THAT(key->GetIdRequirement(), Eq(GetParam().id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(GetParam().output_prefix));
}

TEST_P(TestOnlySymmetricKeyVariantTest, ProtoSerializationRoundTrip) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();

  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<TestOnlySymmetricKey> key = TestOnlySymmetricKey::Create(
      *parameters, RestrictedData("key", InsecureSecretKeyAccess::Get()),
      GetParam().id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTestOnlyKeyTypeUrl));
  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(**serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*key));
}

TEST(TestOnlySymmetricKeyTest, IdRequirementMismatchFails) {
  absl::StatusOr<TestOnlyParameters> tink_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyParameters> no_prefix_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_parameters, IsOk());
  RestrictedData key_bytes("key", InsecureSecretKeyAccess::Get());

  EXPECT_THAT(TestOnlySymmetricKey::Create(*tink_parameters, key_bytes,
                                           std::nullopt, GetPartialKeyAccess()),
              Not(IsOk()));
  EXPECT_THAT(TestOnlySymmetricKey::Create(*no_prefix_parameters, key_bytes,
                                           kKeyId, GetPartialKeyAccess()),
              Not(IsOk()));
}

TEST(TestOnlySymmetricKeyTest, KeysWithDifferentKeyBytesAreNotEqual) {
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<TestOnlySymmetricKey> key1 = TestOnlySymmetricKey::Create(
      *parameters, RestrictedData("key1", InsecureSecretKeyAccess::Get()),
      kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<TestOnlySymmetricKey> key2 = TestOnlySymmetricKey::Create(
      *parameters, RestrictedData("key2", InsecureSecretKeyAccess::Get()),
      kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(key2, IsOk());

  EXPECT_THAT(*key1 == *key2, Eq(false));
  EXPECT_THAT(*key1 != *key2, IsTrue());
}

TEST(TestOnlySymmetricKeyTest, GenerateFromParametersAndGetPrimitive) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<TestOnlyParameters>(
                  CreateTestOnlyKey, key_gen_config),
              IsOk());
  Configuration config;
  ASSERT_THAT(ConfigurationImpl::AddPrimitiveWrapper(
                  std::make_unique<AeadWrapper>(), config),
              IsOk());
  absl::Status status =
      ConfigurationImpl::AddPrimitiveGetter<Aead, TestOnlySymmetricKey>(
          NewTestOnlyAead, config);
  ASSERT_THAT(status, IsOk());

  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(1));
  const TestOnlySymmetricKey* key =
      dynamic_cast<const TestOnlySymmetricKey*>((*handle)[0].GetKey().get());
  ASSERT_THAT(key, NotNull());
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()).size(),
              Eq(kTestOnlyKeySizeInBytes));

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      handle->GetPrimitive<Aead>(config);
  ASSERT_THAT(aead, IsOk());
  absl::StatusOr<std::string> ciphertext = (*aead)->Encrypt("plaintext", "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "ad"), IsOkAndHolds("plaintext"));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
