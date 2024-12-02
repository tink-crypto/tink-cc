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

#include "tink/aead/legacy_kms_aead_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/kms_aead.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KmsAeadKey;
using ::google::crypto::tink::KmsAeadKeyFormat;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.KmsAeadKey";

const absl::string_view kKeyUri = "some://arbitrary.key.uri?q=123#xyz";

struct TestCase {
  LegacyKmsAeadParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
};

class LegacyKmsAeadProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(LegacyKmsAeadProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterLegacyKmsAeadProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterLegacyKmsAeadProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsAeadProtoSerializationTestSuite,
    LegacyKmsAeadProtoSerializationTest,
    Values(TestCase{LegacyKmsAeadParameters::Variant::kTink,
                    OutputPrefixType::TINK,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{LegacyKmsAeadParameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(LegacyKmsAeadProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsAeadProtoSerialization(), IsOk());

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const LegacyKmsAeadParameters* kms_aead_params =
      dynamic_cast<const LegacyKmsAeadParameters*>(params->get());
  ASSERT_THAT(kms_aead_params, NotNull());
  EXPECT_THAT(kms_aead_params->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(kms_aead_params->GetVariant(), Eq(test_case.variant));
}

TEST_P(LegacyKmsAeadProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsAeadProtoSerialization(), IsOk());

  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  KmsAeadKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.key_uri(), Eq(kKeyUri));
}

TEST_P(LegacyKmsAeadProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsAeadProtoSerialization(), IsOk());

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);
  KmsAeadKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_params() = key_format_proto;
  RestrictedData serialized_key =
      RestrictedData(key_proto.SerializeAsString(),
                     internal::GetInsecureSecretKeyAccessInternal());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::REMOTE,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<LegacyKmsAeadParameters> expected_parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> expected_key =
      LegacyKmsAeadKey::Create(*expected_parameters, test_case.id);
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(LegacyKmsAeadProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsAeadProtoSerialization(), IsOk());

  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, test_case.id);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::REMOTE));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  KmsAeadKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      internal::GetInsecureSecretKeyAccessInternal())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.params().key_uri(), Eq(kKeyUri));
}

}  // namespace
}  // namespace tink
}  // namespace crypto