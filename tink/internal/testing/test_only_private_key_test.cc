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

#include "tink/internal/testing/test_only_private_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/configuration.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/internal/testing/test_only_public_key.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::internal::KeyDataTP;
using ::google::crypto::tink::internal::OutputPrefixTypeTP;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::SizeIs;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::Values;
using TestOnlyPrivateKeyProto = ::google::crypto::tink::TestOnlyPrivateKey;

constexpr int kKeyId = 0x01020304;
constexpr absl::string_view kPrivateKeyBytes = "private key";
constexpr absl::string_view kPublicKeyBytes = "yek etavirp";

struct KeyTestCase {
  TestOnlyParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using TestOnlyPrivateKeyVariantTest = TestWithParam<KeyTestCase>;

INSTANTIATE_TEST_SUITE_P(
    TestOnlyPrivateKeyVariantTestSuite, TestOnlyPrivateKeyVariantTest,
    Values(KeyTestCase{TestOnlyParameters::Variant::kTink, kKeyId,
                       "\x01\x01\x02\x03\x04"},
           KeyTestCase{TestOnlyParameters::Variant::kCrunchy, kKeyId,
                       std::string("\x00\x01\x02\x03\x04", 5)},
           KeyTestCase{TestOnlyParameters::Variant::kLegacy, kKeyId,
                       std::string("\x00\x01\x02\x03\x04", 5)},
           KeyTestCase{TestOnlyParameters::Variant::kNoPrefix, std::nullopt,
                       ""}));

TEST_P(TestOnlyPrivateKeyVariantTest, CreateFromParameters) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  RestrictedData private_key_bytes(kPrivateKeyBytes,
                                   InsecureSecretKeyAccess::Get());

  absl::StatusOr<TestOnlyPrivateKey> private_key = TestOnlyPrivateKey::Create(
      *parameters, private_key_bytes, GetParam().id_requirement,
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(GetParam().id_requirement));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(GetParam().output_prefix));
  EXPECT_THAT(
      private_key->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()),
      Eq(kPublicKeyBytes));
  EXPECT_THAT(private_key->GetPublicKey().GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetPublicKey().GetIdRequirement(),
              Eq(GetParam().id_requirement));
}

TEST_P(TestOnlyPrivateKeyVariantTest, CreateFromPublicKey) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<TestOnlyPublicKey> public_key = TestOnlyPublicKey::Create(
      *parameters, kPublicKeyBytes, GetParam().id_requirement,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  RestrictedData private_key_bytes(kPrivateKeyBytes,
                                   InsecureSecretKeyAccess::Get());

  absl::StatusOr<TestOnlyPrivateKey> private_key = TestOnlyPrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(GetParam().id_requirement));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(GetParam().output_prefix));
  absl::StatusOr<TestOnlyPrivateKey> other_private_key =
      TestOnlyPrivateKey::Create(*parameters, private_key_bytes,
                                 GetParam().id_requirement,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());
  EXPECT_THAT(*private_key, Eq(*other_private_key));
}

TEST_P(TestOnlyPrivateKeyVariantTest, ProtoSerializationRoundTrip) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();

  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<TestOnlyPrivateKey> private_key = TestOnlyPrivateKey::Create(
      *parameters,
      RestrictedData(kPrivateKeyBytes, InsecureSecretKeyAccess::Get()),
      GetParam().id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq(kTestOnlyPrivateKeyTypeUrl));
  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyDataTP::KeyMaterialTypeTP::kAsymmetricPrivate));
  TestOnlyPrivateKeyProto proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(kPrivateKeyBytes));
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().key_value(), Eq(kPublicKeyBytes));

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(**serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*private_key));
}

TEST_P(TestOnlyPrivateKeyVariantTest, GenerateFromParametersAndGetPrimitives) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(
      KeyGenConfigurationImpl::AddKeyCreator<TestOnlyAsymmetricParameters>(
          CreateTestOnlyPrivateKey, key_gen_config),
      IsOk());
  Configuration config;
  ASSERT_THAT(ConfigurationImpl::AddPrimitiveWrapper(
                  std::make_unique<PublicKeySignWrapper>(), config),
              IsOk());
  ASSERT_THAT(ConfigurationImpl::AddPrimitiveWrapper(
                  std::make_unique<PublicKeyVerifyWrapper>(), config),
              IsOk());
  absl::Status status =
      ConfigurationImpl::AddPrimitiveGetter<PublicKeySign, TestOnlyPrivateKey>(
          NewTestOnlyPublicKeySign, config);
  ASSERT_THAT(status, IsOk());
  status =
      ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify, TestOnlyPublicKey>(
          NewTestOnlyPublicKeyVerify, config);
  ASSERT_THAT(status, IsOk());

  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<KeysetHandle> private_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/kKeyId))
          .Build(key_gen_config);
  ASSERT_THAT(private_handle, IsOk());
  ASSERT_THAT(*private_handle, SizeIs(1));
  const TestOnlyPrivateKey* private_key =
      dynamic_cast<const TestOnlyPrivateKey*>(
          (*private_handle)[0].GetKey().get());
  ASSERT_THAT(private_key, NotNull());
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(GetParam().output_prefix));
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      private_handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());
  ASSERT_THAT(**public_handle, SizeIs(1));
  EXPECT_THAT(*(**public_handle)[0].GetKey(), Eq(private_key->GetPublicKey()));

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      private_handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());
  absl::StatusOr<std::string> signature = (*sign)->Sign("data");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, StartsWith(GetParam().output_prefix));
  EXPECT_THAT((*verify)->Verify(*signature, "data"), IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "other data"), Not(IsOk()));
}

TEST(TestOnlyPrivateKeyTest, IdRequirementMismatchFails) {
  absl::StatusOr<TestOnlyAsymmetricParameters> tink_parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyAsymmetricParameters> no_prefix_parameters =
      TestOnlyAsymmetricParameters::Create(
          TestOnlyParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_parameters, IsOk());
  RestrictedData private_key_bytes(kPrivateKeyBytes,
                                   InsecureSecretKeyAccess::Get());

  EXPECT_THAT(TestOnlyPrivateKey::Create(*tink_parameters, private_key_bytes,
                                         std::nullopt, GetPartialKeyAccess()),
              Not(IsOk()));
  EXPECT_THAT(
      TestOnlyPrivateKey::Create(*no_prefix_parameters, private_key_bytes,
                                 kKeyId, GetPartialKeyAccess()),
      Not(IsOk()));
}

TEST(TestOnlyPrivateKeyTest, CreateWithMismatchedPublicKeyFails) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  // The public key material must be the reversed private key material.
  absl::StatusOr<TestOnlyPublicKey> public_key = TestOnlyPublicKey::Create(
      *parameters, kPrivateKeyBytes, kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(
      TestOnlyPrivateKey::Create(
          *public_key,
          RestrictedData(kPrivateKeyBytes, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TestOnlyPrivateKeyTest, Equality) {
  absl::StatusOr<TestOnlyAsymmetricParameters> tink_parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyAsymmetricParameters> crunchy_parameters =
      TestOnlyAsymmetricParameters::Create(
          TestOnlyParameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_parameters, IsOk());
  auto create_key = [](const TestOnlyAsymmetricParameters& parameters,
                       absl::string_view private_key_bytes, int id) {
    return TestOnlyPrivateKey::Create(
        parameters,
        RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()), id,
        GetPartialKeyAccess());
  };
  absl::StatusOr<TestOnlyPrivateKey> key =
      create_key(*tink_parameters, "key1", kKeyId);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<TestOnlyPrivateKey> same_key =
      create_key(*tink_parameters, "key1", kKeyId);
  ASSERT_THAT(same_key, IsOk());
  absl::StatusOr<TestOnlyPrivateKey> other_key_bytes =
      create_key(*tink_parameters, "key2", kKeyId);
  ASSERT_THAT(other_key_bytes, IsOk());
  absl::StatusOr<TestOnlyPrivateKey> other_id =
      create_key(*tink_parameters, "key1", kKeyId + 1);
  ASSERT_THAT(other_id, IsOk());
  absl::StatusOr<TestOnlyPrivateKey> other_parameters =
      create_key(*crunchy_parameters, "key1", kKeyId);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_THAT(*key == *same_key, IsTrue());
  EXPECT_THAT(key->GetPublicKey() == same_key->GetPublicKey(), IsTrue());
  EXPECT_THAT(*key != *other_key_bytes, IsTrue());
  EXPECT_THAT(key->GetPublicKey() != other_key_bytes->GetPublicKey(), IsTrue());
  EXPECT_THAT(*key != *other_id, IsTrue());
  EXPECT_THAT(key->GetPublicKey() != other_id->GetPublicKey(), IsTrue());
  EXPECT_THAT(*key != *other_parameters, IsTrue());
  EXPECT_THAT(key->GetPublicKey() != other_parameters->GetPublicKey(),
              IsTrue());
  EXPECT_THAT(*key != key->GetPublicKey(), IsTrue());
  EXPECT_THAT(key->GetPublicKey() != *key, IsTrue());
}

absl::StatusOr<ProtoKeySerialization> CreatePrivateKeySerialization(
    const TestOnlyPrivateKeyProto& proto_key) {
  return ProtoKeySerialization::Create(
      kTestOnlyPrivateKeyTypeUrl,
      RestrictedData(proto_key.SerializeAsString(),
                     InsecureSecretKeyAccess::Get()),
      KeyDataTP::KeyMaterialTypeTP::kAsymmetricPrivate,
      OutputPrefixTypeTP::kTink, kKeyId);
}

TEST(TestOnlyPrivateKeyTest, ParseInvalidKeyFails) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();
  TestOnlyPrivateKeyProto proto_key;
  proto_key.set_key_value(kPrivateKeyBytes);
  proto_key.mutable_public_key()->set_key_value(kPublicKeyBytes);
  absl::StatusOr<ProtoKeySerialization> serialization =
      CreatePrivateKeySerialization(proto_key);
  ASSERT_THAT(serialization, IsOk());
  ASSERT_THAT(registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  TestOnlyPrivateKeyProto wrong_version = proto_key;
  wrong_version.set_version(1);
  TestOnlyPrivateKeyProto wrong_public_key_version = proto_key;
  wrong_public_key_version.mutable_public_key()->set_version(1);
  TestOnlyPrivateKeyProto wrong_public_key = proto_key;
  wrong_public_key.mutable_public_key()->set_key_value(kPrivateKeyBytes);
  for (const auto& [name, invalid_proto_key] :
       std::vector<std::pair<absl::string_view, TestOnlyPrivateKeyProto>>{
           {"wrong_version", wrong_version},
           {"wrong_public_key_version", wrong_public_key_version},
           {"wrong_public_key", wrong_public_key}}) {
    SCOPED_TRACE(name);
    absl::StatusOr<ProtoKeySerialization> invalid_serialization =
        CreatePrivateKeySerialization(invalid_proto_key);
    ASSERT_THAT(invalid_serialization, IsOk());
    EXPECT_THAT(registry.ParseKey(*invalid_serialization,
                                  InsecureSecretKeyAccess::Get()),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }

  // A truncated proto.
  absl::StatusOr<ProtoKeySerialization> truncated_serialization =
      ProtoKeySerialization::Create(
          kTestOnlyPrivateKeyTypeUrl,
          RestrictedData("\x12\x05", InsecureSecretKeyAccess::Get()),
          KeyDataTP::KeyMaterialTypeTP::kAsymmetricPrivate,
          OutputPrefixTypeTP::kTink, kKeyId);
  ASSERT_THAT(truncated_serialization, IsOk());
  EXPECT_THAT(registry.ParseKey(*truncated_serialization,
                                InsecureSecretKeyAccess::Get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TestOnlyPrivateKeyTest, SerializationRequiresSecretAccess) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();
  TestOnlyPrivateKeyProto proto_key;
  proto_key.set_key_value(kPrivateKeyBytes);
  proto_key.mutable_public_key()->set_key_value(kPublicKeyBytes);
  absl::StatusOr<ProtoKeySerialization> serialization =
      CreatePrivateKeySerialization(proto_key);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT(registry.ParseKey(*serialization, std::nullopt),
              StatusIs(absl::StatusCode::kPermissionDenied));

  absl::StatusOr<std::unique_ptr<Key>> private_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(
      registry.SerializeKey<ProtoKeySerialization>(**private_key, std::nullopt),
      StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(TestOnlyPrivateKeyTest, CreateTestOnlyPrivateKey) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateTestOnlyPrivateKey(*parameters, kKeyId);
  ASSERT_THAT(key, IsOk());
  const TestOnlyPrivateKey* private_key =
      dynamic_cast<const TestOnlyPrivateKey*>(key->get());
  ASSERT_THAT(private_key, NotNull());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(kKeyId));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()).size(),
              Eq(kTestOnlyKeySizeInBytes));

  absl::StatusOr<std::unique_ptr<Key>> other_key =
      CreateTestOnlyPrivateKey(*parameters, kKeyId);
  ASSERT_THAT(other_key, IsOk());
  EXPECT_THAT(**key != **other_key, IsTrue());
  EXPECT_THAT(CreateTestOnlyPrivateKey(*parameters, std::nullopt), Not(IsOk()));
}

TEST(TestOnlyPrivateKeyTest, PublicKeyVerifiesSignaturesOfPrivateKey) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(
          TestOnlyParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateTestOnlyPrivateKey(*parameters, std::nullopt);
  ASSERT_THAT(key, IsOk());
  const auto* private_key = dynamic_cast<const TestOnlyPrivateKey*>(key->get());
  ASSERT_THAT(private_key, NotNull());
  absl::StatusOr<std::unique_ptr<Key>> other_key =
      CreateTestOnlyPrivateKey(*parameters, std::nullopt);
  ASSERT_THAT(other_key, IsOk());
  const auto* other_private_key =
      dynamic_cast<const TestOnlyPrivateKey*>(other_key->get());
  ASSERT_THAT(other_private_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      NewTestOnlyPublicKeySign(*private_key);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      NewTestOnlyPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verify, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> other_verify =
      NewTestOnlyPublicKeyVerify(other_private_key->GetPublicKey());
  ASSERT_THAT(other_verify, IsOk());

  absl::StatusOr<std::string> signature = (*sign)->Sign("data");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "data"), IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "other data"), Not(IsOk()));
  EXPECT_THAT((*other_verify)->Verify(*signature, "data"), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
