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

#include "tink/internal/testing/test_only_public_key.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"
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
using ::testing::TestWithParam;
using ::testing::Values;
using TestOnlyPublicKeyProto = ::google::crypto::tink::TestOnlyPublicKey;

constexpr int kKeyId = 0x01020304;
constexpr absl::string_view kPublicKeyBytes = "yek etavirp";

struct KeyTestCase {
  TestOnlyParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using TestOnlyPublicKeyVariantTest = TestWithParam<KeyTestCase>;

INSTANTIATE_TEST_SUITE_P(
    TestOnlyPublicKeyVariantTestSuite, TestOnlyPublicKeyVariantTest,
    Values(KeyTestCase{TestOnlyParameters::Variant::kTink, kKeyId,
                       "\x01\x01\x02\x03\x04"},
           KeyTestCase{TestOnlyParameters::Variant::kCrunchy, kKeyId,
                       std::string("\x00\x01\x02\x03\x04", 5)},
           KeyTestCase{TestOnlyParameters::Variant::kLegacy, kKeyId,
                       std::string("\x00\x01\x02\x03\x04", 5)},
           KeyTestCase{TestOnlyParameters::Variant::kNoPrefix, std::nullopt,
                       ""}));

TEST_P(TestOnlyPublicKeyVariantTest, Create) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<TestOnlyPublicKey> public_key = TestOnlyPublicKey::Create(
      *parameters, kPublicKeyBytes, GetParam().id_requirement,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(kPublicKeyBytes));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(GetParam().id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(GetParam().output_prefix));
}

TEST_P(TestOnlyPublicKeyVariantTest, ProtoSerializationRoundTrip) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();

  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<TestOnlyPublicKey> public_key = TestOnlyPublicKey::Create(
      *parameters, kPublicKeyBytes, GetParam().id_requirement,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Public keys need no secret key access.
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*public_key, std::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq(kTestOnlyPublicKeyTypeUrl));
  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyDataTP::KeyMaterialTypeTP::kAsymmetricPublic));
  TestOnlyPublicKeyProto proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(kPublicKeyBytes));

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(**serialization, std::nullopt);
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*public_key));
}

TEST(TestOnlyPublicKeyTest, IdRequirementMismatchFails) {
  absl::StatusOr<TestOnlyAsymmetricParameters> tink_parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyAsymmetricParameters> no_prefix_parameters =
      TestOnlyAsymmetricParameters::Create(
          TestOnlyParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  EXPECT_THAT(TestOnlyPublicKey::Create(*tink_parameters, kPublicKeyBytes,
                                        std::nullopt, GetPartialKeyAccess()),
              Not(IsOk()));
  EXPECT_THAT(TestOnlyPublicKey::Create(*no_prefix_parameters, kPublicKeyBytes,
                                        kKeyId, GetPartialKeyAccess()),
              Not(IsOk()));
}

TEST(TestOnlyPublicKeyTest, Equality) {
  absl::StatusOr<TestOnlyAsymmetricParameters> tink_parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyAsymmetricParameters> crunchy_parameters =
      TestOnlyAsymmetricParameters::Create(
          TestOnlyParameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_parameters, IsOk());
  absl::StatusOr<TestOnlyPublicKey> key = TestOnlyPublicKey::Create(
      *tink_parameters, "key1", kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<TestOnlyPublicKey> same_key = TestOnlyPublicKey::Create(
      *tink_parameters, "key1", kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(same_key, IsOk());
  absl::StatusOr<TestOnlyPublicKey> other_key_bytes = TestOnlyPublicKey::Create(
      *tink_parameters, "key2", kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(other_key_bytes, IsOk());
  absl::StatusOr<TestOnlyPublicKey> other_id = TestOnlyPublicKey::Create(
      *tink_parameters, "key1", kKeyId + 1, GetPartialKeyAccess());
  ASSERT_THAT(other_id, IsOk());
  absl::StatusOr<TestOnlyPublicKey> other_parameters =
      TestOnlyPublicKey::Create(*crunchy_parameters, "key1", kKeyId,
                                GetPartialKeyAccess());
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_THAT(*key == *same_key, IsTrue());
  EXPECT_THAT(*key != *other_key_bytes, IsTrue());
  EXPECT_THAT(*key != *other_id, IsTrue());
  EXPECT_THAT(*key != *other_parameters, IsTrue());
}

TEST(TestOnlyPublicKeyTest, KeyIsNotEqualToSymmetricKey) {
  absl::StatusOr<TestOnlyAsymmetricParameters> asymmetric_parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(asymmetric_parameters, IsOk());
  absl::StatusOr<TestOnlyPublicKey> key = TestOnlyPublicKey::Create(
      *asymmetric_parameters, "key", kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<TestOnlyParameters> symmetric_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(symmetric_parameters, IsOk());
  absl::StatusOr<TestOnlySymmetricKey> symmetric_key =
      TestOnlySymmetricKey::Create(
          *symmetric_parameters,
          RestrictedData("key", InsecureSecretKeyAccess::Get()), kKeyId,
          GetPartialKeyAccess());
  ASSERT_THAT(symmetric_key, IsOk());

  EXPECT_THAT(*key != *symmetric_key, IsTrue());
}

TEST(TestOnlyPublicKeyTest, ParseKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  TestOnlyPublicKeyProto proto_key;
  proto_key.set_version(1);
  proto_key.set_key_value(kPublicKeyBytes);
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kTestOnlyPublicKeyTypeUrl,
          RestrictedData(proto_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyDataTP::KeyMaterialTypeTP::kAsymmetricPublic,
          OutputPrefixTypeTP::kTink, kKeyId);
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *serialization, std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TestOnlyPublicKeyTest, VerifiesSignaturesOfTheDummySignOfItsKeyBytes) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(
          TestOnlyParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<TestOnlyPublicKey> key = TestOnlyPublicKey::Create(
      *parameters, kPublicKeyBytes, std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      NewTestOnlyPublicKeyVerify(*key);
  ASSERT_THAT(verify, IsOk());

  absl::StatusOr<std::string> signature =
      test::DummyPublicKeySign(absl::BytesToHexString(kPublicKeyBytes))
          .Sign("data");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "data"), IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "other data"), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
