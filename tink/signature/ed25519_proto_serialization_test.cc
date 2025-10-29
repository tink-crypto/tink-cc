// Copyright 2023 Google LLC
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

#include "tink/signature/ed25519_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/ed25519.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::Ed25519KeyFormat;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kPrivateKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

struct TestCase {
  Ed25519Parameters::Variant variant;
  OutputPrefixTypeEnum output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
};

class Ed25519ProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(Ed25519ProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    Ed25519ProtoSerializationTestSuite, Ed25519ProtoSerializationTest,
    Values(TestCase{Ed25519Parameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{Ed25519Parameters::Variant::kCrunchy,
                    OutputPrefixTypeEnum::kCrunchy, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{Ed25519Parameters::Variant::kLegacy,
                    OutputPrefixTypeEnum::kLegacy, /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{Ed25519Parameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(Ed25519ProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  Ed25519KeyFormat key_format_proto;
  key_format_proto.set_version(0);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateKeyTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const Ed25519Parameters* ed25519_params =
      dynamic_cast<const Ed25519Parameters*>(params->get());
  ASSERT_THAT(ed25519_params, NotNull());
  EXPECT_THAT(ed25519_params->GetVariant(), Eq(test_case.variant));
}

TEST_F(Ed25519ProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(kPrivateKeyTypeUrl,
                                                     OutputPrefixTypeEnum::kRaw,
                                                     "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  Ed25519KeyFormat key_format_proto;
  key_format_proto.set_version(0);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateKeyTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  Ed25519KeyFormat key_format_proto;
  key_format_proto.set_version(1);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateKeyTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(Ed25519ProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateKeyTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  const internal::ProtoKeyTemplate& key_template =
      proto_serialization->GetProtoKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateKeyTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));

  Ed25519KeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
}

TEST_P(Ed25519ProtoSerializationTest, ParsePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::Ed25519PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          serialized_key, KeyMaterialTypeEnum::kAsymmetricPublic,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<Ed25519Parameters> expected_parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<Ed25519PublicKey> expected_key = Ed25519PublicKey::Create(
      *expected_parameters, raw_key_bytes, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          serialized_key, KeyMaterialTypeEnum::kAsymmetricPublic,
          OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::Ed25519PublicKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          serialized_key, KeyMaterialTypeEnum::kAsymmetricPublic,
          OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(Ed25519ProtoSerializationTest, SerializePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  absl::StatusOr<Ed25519PublicKey> key = Ed25519PublicKey::Create(
      *parameters, raw_key_bytes, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PublicKey"));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PublicKey"));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::Ed25519PublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
}

TEST_P(Ed25519ProtoSerializationTest, ParsePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::Ed25519PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value((*key_pair)->public_key);

  google::crypto::tink::Ed25519PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(
      util::SecretDataAsStringView((*key_pair)->private_key));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateKeyTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, test_case.output_prefix_type,
          test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<Ed25519Parameters> expected_parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<Ed25519PublicKey> expected_public_key =
      Ed25519PublicKey::Create(*expected_parameters, (*key_pair)->public_key,
                               test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<Ed25519PrivateKey> expected_private_key =
      Ed25519PrivateKey::Create(*expected_public_key,
                                RestrictedData((*key_pair)->private_key,
                                               InsecureSecretKeyAccess::Get()),
                                GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateKeyTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePrivateKeyWithNoPublicKeyFails) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::Ed25519PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_key_value(
      util::SecretDataAsStringView((*key_pair)->private_key));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateKeyTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::Ed25519PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value((*key_pair)->public_key);

  google::crypto::tink::Ed25519PrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(
      util::SecretDataAsStringView((*key_pair)->private_key));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateKeyTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(Ed25519ProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersion) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::Ed25519PublicKey public_key_proto;
  public_key_proto.set_version(1);  // invalid version
  public_key_proto.set_key_value((*key_pair)->public_key);

  google::crypto::tink::Ed25519PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(
      util::SecretDataAsStringView((*key_pair)->private_key));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateKeyTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               testing::HasSubstr("Only version 0 public keys are accepted")));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::Ed25519PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value((*key_pair)->public_key);

  google::crypto::tink::Ed25519PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(
      util::SecretDataAsStringView((*key_pair)->private_key));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateKeyTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(Ed25519ProtoSerializationTest, SerializePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*parameters, (*key_pair)->public_key,
                               test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key,
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateKeyTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPrivateKeyTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::Ed25519PrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(),
              Eq(util::SecretDataAsStringView((*key_pair)->private_key)));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().key_value(), Eq((*key_pair)->public_key));
}

TEST_F(Ed25519ProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*parameters, (*key_pair)->public_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key,
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
