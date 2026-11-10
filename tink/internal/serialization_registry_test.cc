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

#include "tink/internal/serialization_registry.h"

#include <memory>
#include <string_view>
#include <typeindex>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_test_util.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::KeyMaterialTypeTP;
using ::crypto::tink::internal::OutputPrefixTypeTP;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(SerializationRegistryTest, ParseParameters) {
  SerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersParserImpl<IdParamsSerialization, IdParams> parser2(kIdTypeUrl,
                                                                ParseIdParams);
  ASSERT_THAT(registry.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(registry.RegisterParametersParser(&parser2), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> no_id_params =
      registry.ParseParameters(NoIdSerialization());
  ASSERT_THAT(no_id_params, IsOk());
  EXPECT_THAT((*no_id_params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**no_id_params)),
              std::type_index(typeid(NoIdParams)));

  absl::StatusOr<std::unique_ptr<Parameters>> id_params =
      registry.ParseParameters(IdParamsSerialization());
  ASSERT_THAT(id_params, IsOk());
  EXPECT_THAT((*id_params)->HasIdRequirement(), IsTrue());
  EXPECT_THAT(std::type_index(typeid(**id_params)),
              std::type_index(typeid(IdParams)));
}

TEST(MutableSerializationRegistryTest, ParseParametersWithLegacyFallback) {
  SerializationRegistry registry;
  ParametersParserImpl<IdParamsSerialization, IdParams> parser(kIdTypeUrl,
                                                               ParseIdParams);
  ASSERT_THAT(registry.RegisterParametersParser(&parser), IsOk());

  // Parse parameters with registered parameters parser.
  absl::StatusOr<std::unique_ptr<Parameters>> id_params =
      registry.ParseParameters(IdParamsSerialization());
  ASSERT_THAT(id_params, IsOk());
  EXPECT_THAT((*id_params)->HasIdRequirement(), IsTrue());
  EXPECT_THAT(std::type_index(typeid(**id_params)),
              std::type_index(typeid(IdParams)));

  // Parse parameters without registered parameters parser.
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type_url", OutputPrefixTypeTP::kTink, "serialized_proto");
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT(registry.ParseParameters(*serialization).status(),
              StatusIs(absl::StatusCode::kNotFound));

  // Fall back to legacy proto parameters.
  absl::StatusOr<std::unique_ptr<Parameters>> proto_parameters =
      registry.ParseParametersWithLegacyFallback(*serialization);
  ASSERT_THAT(proto_parameters, IsOk());
  EXPECT_THAT((*proto_parameters)->HasIdRequirement(), IsTrue());
}

TEST(SerializationRegistryTest, ParseParametersWithoutRegistration) {
  SerializationRegistry registry;

  ASSERT_THAT(registry.ParseParameters(NoIdSerialization()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameParametersParser) {
  SerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser(kNoIdTypeUrl,
                                                             ParseNoIdParams);

  EXPECT_THAT(registry.RegisterParametersParser(&parser), IsOk());
  EXPECT_THAT(registry.RegisterParametersParser(&parser), IsOk());
}

TEST(SerializationRegistryTest,
     RegisterDifferentParametersParserWithSameIndex) {
  SerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser2(kNoIdTypeUrl,
                                                              ParseNoIdParams);

  EXPECT_THAT(registry.RegisterParametersParser(&parser1), IsOk());
  EXPECT_THAT(registry.RegisterParametersParser(&parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, SerializeParameters) {
  SerializationRegistry registry;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ParametersSerializerImpl<IdParams, IdParamsSerialization> serializer2(
      kIdTypeUrl, SerializeIdParams);
  ASSERT_THAT(registry.RegisterParametersSerializer(&serializer1), IsOk());
  ASSERT_THAT(registry.RegisterParametersSerializer(&serializer2), IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization1 =
      registry.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(serialization1, IsOk());
  EXPECT_THAT((*serialization1)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  absl::StatusOr<std::unique_ptr<Serialization>> serialization2 =
      registry.SerializeParameters<IdParamsSerialization>(IdParams());
  ASSERT_THAT(serialization2, IsOk());
  EXPECT_THAT((*serialization2)->ObjectIdentifier(), Eq(kIdTypeUrl));
}

TEST(SerializationRegistryTest, SerializeParametersWithoutRegistration) {
  SerializationRegistry registry;

  ASSERT_THAT(
      registry.SerializeParameters<NoIdSerialization>(NoIdParams()).status(),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameParametersSerializer) {
  SerializationRegistry registry;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer(
      kNoIdTypeUrl, SerializeNoIdParams);

  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer), IsOk());
  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer), IsOk());
}

TEST(SerializationRegistryTest,
     RegisterDifferentParametersSerializerWithSameIndex) {
  SerializationRegistry registry;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer2(
      kNoIdTypeUrl, SerializeNoIdParams);

  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer1), IsOk());
  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, ParseKey) {
  SerializationRegistry registry;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser1(kNoIdTypeUrl, ParseNoIdKey);
  KeyParserImpl<IdKeySerialization, IdKey> parser2(kIdTypeUrl, ParseIdKey);
  ASSERT_THAT(registry.RegisterKeyParser(&parser1), IsOk());
  ASSERT_THAT(registry.RegisterKeyParser(&parser2), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> no_id_key =
      registry.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(no_id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**no_id_key)),
              std::type_index(typeid(NoIdKey)));

  absl::StatusOr<std::unique_ptr<Key>> id_key = registry.ParseKey(
      IdKeySerialization(/*id=*/123), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**id_key)),
              std::type_index(typeid(IdKey)));
  EXPECT_THAT((*id_key)->GetIdRequirement(), Eq(123));
}

TEST(SerializationRegistryTest, ParseKeyWithLegacyFallback) {
  SerializationRegistry registry;
  KeyParserImpl<IdKeySerialization, IdKey> parser(kIdTypeUrl, ParseIdKey);
  ASSERT_THAT(registry.RegisterKeyParser(&parser), IsOk());

  // Parse key with registered key parser.
  absl::StatusOr<std::unique_ptr<Key>> id_key =
      registry.ParseKeyWithLegacyFallback(IdKeySerialization(/*id=*/123),
                                          InsecureSecretKeyAccess::Get());
  ASSERT_THAT(id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**id_key)),
              std::type_index(typeid(IdKey)));
  EXPECT_THAT((*id_key)->GetIdRequirement(), Eq(123));

  // Parse key without registered key parser.
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/456);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT(registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  // Fall back to legacy proto key.
  absl::StatusOr<std::unique_ptr<Key>> proto_key =
      registry.ParseKeyWithLegacyFallback(*serialization,
                                          InsecureSecretKeyAccess::Get());
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT((*proto_key)->GetIdRequirement(), Eq(456));
}

TEST(SerializationRegistryTest, ParseKeyNoSecretAccess) {
  SerializationRegistry registry;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser(kNoIdTypeUrl, ParseNoIdKey);
  ASSERT_THAT(registry.RegisterKeyParser(&parser), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> no_id_public_key =
      registry.ParseKey(NoIdSerialization(), std::nullopt);
  ASSERT_THAT(no_id_public_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**no_id_public_key)),
              std::type_index(typeid(NoIdKey)));
}

TEST(SerializationRegistryTest, ParseKeyWithoutRegistration) {
  SerializationRegistry registry;

  ASSERT_THAT(
      registry.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameKeyParser) {
  SerializationRegistry registry;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser(kNoIdTypeUrl, ParseNoIdKey);

  EXPECT_THAT(registry.RegisterKeyParser(&parser), IsOk());
  EXPECT_THAT(registry.RegisterKeyParser(&parser), IsOk());
}

TEST(SerializationRegistryTest, RegisterDifferentKeyParserWithSameIndex) {
  SerializationRegistry registry;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser1(kNoIdTypeUrl, ParseNoIdKey);
  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);

  EXPECT_THAT(registry.RegisterKeyParser(&parser1), IsOk());
  EXPECT_THAT(registry.RegisterKeyParser(&parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, SerializeKey) {
  SerializationRegistry registry;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer1(SerializeNoIdKey);
  KeySerializerImpl<IdKey, IdKeySerialization> serializer2(SerializeIdKey);
  ASSERT_THAT(registry.RegisterKeySerializer(&serializer1), IsOk());
  ASSERT_THAT(registry.RegisterKeySerializer(&serializer2), IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization1 =
      registry.SerializeKey<NoIdSerialization>(NoIdKey(),
                                               InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization1, IsOk());
  EXPECT_THAT((*serialization1)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  absl::StatusOr<std::unique_ptr<Serialization>> serialization2 =
      registry.SerializeKey<IdKeySerialization>(IdKey(123),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization2, IsOk());
  EXPECT_THAT((*serialization2)->ObjectIdentifier(), Eq(kIdTypeUrl));
}

TEST(SerializationRegistryTest, SerializeKeyNoSecretAccess) {
  SerializationRegistry registry;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer(SerializeNoIdKey);
  ASSERT_THAT(registry.RegisterKeySerializer(&serializer), IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<NoIdSerialization>(NoIdKey(), std::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(SerializationRegistryTest, SerializeKeyWithoutRegistration) {
  SerializationRegistry registry;

  ASSERT_THAT(registry
                  .SerializeKey<NoIdSerialization>(
                      NoIdKey(), InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameKeySerializer) {
  SerializationRegistry registry;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer(SerializeNoIdKey);

  EXPECT_THAT(registry.RegisterKeySerializer(&serializer), IsOk());
  EXPECT_THAT(registry.RegisterKeySerializer(&serializer), IsOk());
}

TEST(SerializationRegistryTest, RegisterDifferentKeySerializerWithSameIndex) {
  SerializationRegistry registry;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer1(SerializeNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);

  EXPECT_THAT(registry.RegisterKeySerializer(&serializer1), IsOk());
  EXPECT_THAT(registry.RegisterKeySerializer(&serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, RegistryCopy) {
  SerializationRegistry registry1;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);
  ASSERT_THAT(registry1.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(registry1.RegisterParametersSerializer(&serializer1), IsOk());
  ASSERT_THAT(registry1.RegisterKeyParser(&parser2), IsOk());
  ASSERT_THAT(registry1.RegisterKeySerializer(&serializer2), IsOk());

  SerializationRegistry registry2 = registry1;

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry2.ParseParameters(NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**params)),
              std::type_index(typeid(NoIdParams)));

  absl::StatusOr<std::unique_ptr<Serialization>> params_serialization =
      registry2.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(params_serialization, IsOk());
  EXPECT_THAT((*params_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry2.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**key)), std::type_index(typeid(NoIdKey)));

  absl::StatusOr<std::unique_ptr<Serialization>> key_serialization =
      registry2.SerializeKey<NoIdSerialization>(NoIdKey(),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization, IsOk());
  EXPECT_THAT((*key_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(SerializationRegistryTest, RegistryMove) {
  SerializationRegistry registry1;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);
  ASSERT_THAT(registry1.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(registry1.RegisterParametersSerializer(&serializer1), IsOk());
  ASSERT_THAT(registry1.RegisterKeyParser(&parser2), IsOk());
  ASSERT_THAT(registry1.RegisterKeySerializer(&serializer2), IsOk());

  SerializationRegistry registry2 = std::move(registry1);

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry2.ParseParameters(NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**params)),
              std::type_index(typeid(NoIdParams)));

  absl::StatusOr<std::unique_ptr<Serialization>> params_serialization =
      registry2.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(params_serialization, IsOk());
  EXPECT_THAT((*params_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry2.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**key)), std::type_index(typeid(NoIdKey)));

  absl::StatusOr<std::unique_ptr<Serialization>> key_serialization =
      registry2.SerializeKey<NoIdSerialization>(NoIdKey(),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization, IsOk());
  EXPECT_THAT((*key_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(SerializationRegistryTest, DirectRegistrationAndRoundTrip) {
  SerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> params_parser(
      kNoIdTypeUrl, ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> params_serializer(
      kNoIdTypeUrl, SerializeNoIdParams);
  KeyParserImpl<IdKeySerialization, IdKey> key_parser(kIdTypeUrl, ParseIdKey);
  KeySerializerImpl<IdKey, IdKeySerialization> key_serializer(SerializeIdKey);

  ASSERT_THAT(registry.RegisterParametersParser(&params_parser), IsOk());
  ASSERT_THAT(registry.RegisterParametersSerializer(&params_serializer),
              IsOk());
  ASSERT_THAT(registry.RegisterKeyParser(&key_parser), IsOk());
  ASSERT_THAT(registry.RegisterKeySerializer(&key_serializer), IsOk());

  // Re-registering the exact same instances is idempotent.
  EXPECT_THAT(registry.RegisterParametersParser(&params_parser), IsOk());
  EXPECT_THAT(registry.RegisterParametersSerializer(&params_serializer),
              IsOk());
  EXPECT_THAT(registry.RegisterKeyParser(&key_parser), IsOk());
  EXPECT_THAT(registry.RegisterKeySerializer(&key_serializer), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT(std::type_index(typeid(**params)),
              Eq(std::type_index(typeid(NoIdParams))));

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      registry.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(serialized_params, IsOk());
  EXPECT_THAT((*serialized_params)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  absl::StatusOr<std::unique_ptr<Key>> key = registry.ParseKey(
      IdKeySerialization(/*id=*/42), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(42));

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      registry.SerializeKey<IdKeySerialization>(IdKey(42),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key, IsOk());
  EXPECT_THAT((*serialized_key)->ObjectIdentifier(), Eq(kIdTypeUrl));
}

TEST(SerializationRegistryTest, DirectRegistrationRejectsConflicts) {
  SerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> params_parser1(
      kNoIdTypeUrl, ParseNoIdParams);
  ParametersParserImpl<NoIdSerialization, NoIdParams> params_parser2(
      kNoIdTypeUrl, ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> params_serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> params_serializer2(
      kNoIdTypeUrl, SerializeNoIdParams);
  KeyParserImpl<NoIdSerialization, NoIdKey> key_parser1(kNoIdTypeUrl,
                                                        ParseNoIdKey);
  KeyParserImpl<NoIdSerialization, NoIdKey> key_parser2(kNoIdTypeUrl,
                                                        ParseNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> key_serializer1(
      SerializeNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> key_serializer2(
      SerializeNoIdKey);

  ASSERT_THAT(registry.RegisterParametersParser(&params_parser1), IsOk());
  ASSERT_THAT(registry.RegisterParametersSerializer(&params_serializer1),
              IsOk());
  ASSERT_THAT(registry.RegisterKeyParser(&key_parser1), IsOk());
  ASSERT_THAT(registry.RegisterKeySerializer(&key_serializer1), IsOk());

  EXPECT_THAT(registry.RegisterParametersParser(&params_parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(registry.RegisterParametersSerializer(&params_serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(registry.RegisterKeyParser(&key_parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(registry.RegisterKeySerializer(&key_serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
