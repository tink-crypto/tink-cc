// Copyright 2021 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/config/global_registry.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_client_mocks.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/primitive_set.h"
#include "tink/internal/registry_impl.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"
#include "tink/jwt/internal/jwt_public_key_verify_impl.h"
#include "tink/jwt/internal/jwt_public_key_verify_internal.h"
#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_proto_serialization.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_signature_config_2026.h"
#include "tink/jwt/jwt_signature_key_gen_config_2026.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/signature/failing_signature.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

using ::absl_testing::IsOk;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::absl_testing::IsOkAndHolds;
using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::ByMove;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::Test;
using ::testing::Values;

absl::StatusOr<JwtEcdsaPrivateKey> CreatePrivateKey(
    JwtEcdsaParameters::KidStrategy kid_strategy,
    std::optional<int> id_requirement = std::nullopt,
    subtle::EllipticCurveType curve = subtle::EllipticCurveType::NIST_P256) {
  absl::Status reg_status = RegisterJwtEcdsaProtoSerialization();
  if (!reg_status.ok()) return reg_status;

  const internal::EcKey& ec_key = internal::GetEcKey(curve);
  JwtEcdsaParameters::Algorithm algorithm;
  if (curve == subtle::EllipticCurveType::NIST_P384) {
    algorithm = JwtEcdsaParameters::Algorithm::kEs384;
  } else if (curve == subtle::EllipticCurveType::NIST_P521) {
    algorithm = JwtEcdsaParameters::Algorithm::kEs512;
  } else {
    algorithm = JwtEcdsaParameters::Algorithm::kEs256;
  }
  absl::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(kid_strategy, algorithm);
  if (!params.ok()) return params.status();

  EcPoint public_point(BigInteger(ec_key.pub_x), BigInteger(ec_key.pub_y));
  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params).SetPublicPoint(
          public_point);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  if (!public_key.ok()) return public_key.status();

  RestrictedData private_key_value =
      RestrictedData(ec_key.priv, InsecureSecretKeyAccess::Get());
  return JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                    GetPartialKeyAccess());
}

KeysetHandleBuilder::Entry CreateKeysetEntry(
    const JwtEcdsaPrivateKey& key, KeyStatus status, bool is_primary,
    std::optional<int> id = std::nullopt) {
  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(key, status,
                                                        is_primary);
  if (id.has_value()) {
    entry.SetFixedId(*id);
  }
  return entry;
}

absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> CreateSign(
    const KeysetHandle& handle) {
  return handle.GetPrimitive<crypto::tink::JwtPublicKeySign>(
      ConfigJwtSignature2026());
}

absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> CreateVerify(
    const KeysetHandle& handle) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle.GetPublicKeysetHandle(KeyGenConfigJwtSignature2026());
  if (!public_handle.ok()) {
    return public_handle.status();
  }
  return (*public_handle)
      ->GetPrimitive<crypto::tink::JwtPublicKeyVerify>(
          ConfigJwtSignature2026());
}

KeyTemplate CreateTemplate(OutputPrefixType output_prefix) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey");
  key_template.set_output_prefix_type(output_prefix);
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

class JwtPublicKeyWrappersTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Reset the serialization registry to prevent proto serialization
    // registered in individual tests from leaking into legacy template tests
    // (such as CannotWrapPrimitivesFromNonRawOrTinkKeys).
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
    ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                    std::make_unique<JwtPublicKeySignWrapper>()),
                IsOk());
    ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                    std::make_unique<JwtPublicKeyVerifyWrapper>()),
                IsOk());
    ASSERT_THAT(Registry::RegisterAsymmetricKeyManagers(
                    std::make_unique<JwtEcdsaSignKeyManager>(),
                    std::make_unique<JwtEcdsaVerifyKeyManager>(), true),
                IsOk());
  }
};

TEST_F(JwtPublicKeyWrappersTest, WrapNullptrSign) {
  EXPECT_THAT(JwtPublicKeySignWrapper().Wrap(nullptr), Not(IsOk()));
}

TEST_F(JwtPublicKeyWrappersTest, WrapNullptrVerify) {
  EXPECT_THAT(JwtPublicKeyVerifyWrapper().Wrap(nullptr), Not(IsOk()));
}

TEST_F(JwtPublicKeyWrappersTest, WrapEmptySign) {
  auto jwt_sign_set =
      std::make_unique<PrimitiveSet<JwtPublicKeySignInternal>>();
  auto result = JwtPublicKeySignWrapper().Wrap(std::move(jwt_sign_set));
  EXPECT_THAT(result, Not(IsOk()));
}

TEST_F(JwtPublicKeyWrappersTest, CannotWrapPrimitivesFromNonRawOrTinkKeys) {
  KeyTemplate tink_key_template = CreateTemplate(OutputPrefixType::LEGACY);

  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(tink_key_template,
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keyset_handle, IsOk());
  EXPECT_THAT((*keyset_handle)
                  ->GetPrimitive<crypto::tink::JwtPublicKeySign>(
                      ConfigGlobalRegistry()),
              Not(IsOk()));

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*keyset_handle)->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());
  EXPECT_THAT((*public_handle)
                  ->GetPrimitive<crypto::tink::JwtPublicKeyVerify>(
                      ConfigGlobalRegistry()),
              Not(IsOk()));
}

TEST_F(JwtPublicKeyWrappersTest, GenerateRawSignVerifySuccess) {
  absl::StatusOr<JwtEcdsaPrivateKey> private_key =
      CreatePrivateKey(JwtEcdsaParameters::KidStrategy::kIgnored);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*private_key, KeyStatus::kEnabled,
                                      /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign =
      CreateSign(*handle);
  ASSERT_THAT(jwt_sign, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify =
      CreateVerify(*handle);
  ASSERT_THAT(jwt_verify, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact = (*jwt_sign)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_verify)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  absl::StatusOr<JwtValidator> validator2 = JwtValidatorBuilder()
                                                .ExpectIssuer("unknown")
                                                .AllowMissingExpiration()
                                                .Build();
  ASSERT_THAT(validator2, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt2 =
      (*jwt_verify)->VerifyAndDecode(*compact, *validator2);
  EXPECT_THAT(verified_jwt2, Not(IsOk()));
  // Make sure the error message is interesting
  EXPECT_THAT(verified_jwt2.status().message(), Eq("wrong issuer"));

  // Raw primitives don't add a kid header, Tink primitives require a kid
  // header to be set. Therefore, verifying with a Tink key makes the
  // validation fail.
  absl::StatusOr<JwtEcdsaPrivateKey> tink_key =
      CreatePrivateKey(JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
                       /*id_requirement=*/123);
  ASSERT_THAT(tink_key, IsOk());
  absl::StatusOr<KeysetHandle> tink_handle =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*tink_key, KeyStatus::kEnabled,
                                      /*is_primary=*/true, /*id=*/123))
          .Build();
  ASSERT_THAT(tink_handle, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> tink_verify =
      CreateVerify(*tink_handle);
  ASSERT_THAT(tink_verify, IsOk());

  EXPECT_THAT((*tink_verify)->VerifyAndDecode(*compact, *validator),
              Not(IsOk()));
}

TEST_F(JwtPublicKeyWrappersTest, GenerateTinkSignVerifySuccess) {
  constexpr uint32_t kKeyId = 123;
  absl::StatusOr<JwtEcdsaPrivateKey> private_key = CreatePrivateKey(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId, kKeyId);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*private_key, KeyStatus::kEnabled,
                                      /*is_primary=*/true, kKeyId))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign =
      CreateSign(*handle);
  ASSERT_THAT(jwt_sign, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify =
      CreateVerify(*handle);
  ASSERT_THAT(jwt_verify, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact = (*jwt_sign)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_verify)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  // Parse header to make sure that key ID is correctly encoded.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigJwtSignature2026());
  ASSERT_THAT(public_handle, IsOk());
  KeysetHandle::Entry primary_entry = (*public_handle)->GetPrimary();
  EXPECT_THAT(primary_entry.GetId(), Eq(kKeyId));
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts, SizeIs(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  absl::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header, IsOk());
  google::protobuf::Value value = (*header).fields().find("kid")->second;
  EXPECT_THAT(GetKeyId(value.string_value()), Eq(kKeyId));

  // For Tink primitives, the kid must be correctly set and verified.
  // Therefore, changing the key_id makes the validation fail.
  constexpr uint32_t kNewKeyId = kKeyId ^ 0xdeadbeef;
  absl::StatusOr<JwtEcdsaPrivateKey> private_key_with_new_key_id =
      CreatePrivateKey(JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
                       kNewKeyId);
  ASSERT_THAT(private_key_with_new_key_id, IsOk());
  absl::StatusOr<KeysetHandle> handle_with_new_key_id =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*private_key_with_new_key_id,
                                      KeyStatus::kEnabled, /*is_primary=*/true,
                                      kNewKeyId))
          .Build();
  ASSERT_THAT(handle_with_new_key_id, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>>
      jwt_verify_with_new_key_id = CreateVerify(*handle_with_new_key_id);
  ASSERT_THAT(jwt_verify_with_new_key_id, IsOk());

  absl::StatusOr<VerifiedJwt> verified_jwt_2 =
      (*jwt_verify_with_new_key_id)->VerifyAndDecode(*compact, *validator);
  EXPECT_THAT(verified_jwt_2, Not(IsOk()));
}

struct KeyRotationTestCase {
  JwtEcdsaParameters::KidStrategy kid_strategy;
  std::optional<int> id1;
  std::optional<int> id2;
};

class JwtPublicKeyWrappersKeyRotationTest
    : public JwtPublicKeyWrappersTest,
      public ::testing::WithParamInterface<KeyRotationTestCase> {};

INSTANTIATE_TEST_SUITE_P(
    JwtPublicKeyWrappersKeyRotationTestSuite,
    JwtPublicKeyWrappersKeyRotationTest,
    Values(KeyRotationTestCase{JwtEcdsaParameters::KidStrategy::kIgnored,
                               std::nullopt, std::nullopt},
           KeyRotationTestCase{
               JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId, 1234543,
               726329}));

TEST_P(JwtPublicKeyWrappersKeyRotationTest, KeyRotation) {
  KeyRotationTestCase test_case = GetParam();
  absl::StatusOr<JwtEcdsaPrivateKey> key1 =
      CreatePrivateKey(test_case.kid_strategy, test_case.id1,
                       subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<JwtEcdsaPrivateKey> key2 =
      CreatePrivateKey(test_case.kid_strategy, test_case.id2,
                       subtle::EllipticCurveType::NIST_P384);
  ASSERT_THAT(key2, IsOk());

  // Handle 1: key1 enabled and primary.
  absl::StatusOr<KeysetHandle> handle1 =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*key1, KeyStatus::kEnabled,
                                      /*is_primary=*/true, test_case.id1))
          .Build();
  ASSERT_THAT(handle1, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign1 =
      CreateSign(*handle1);
  ASSERT_THAT(jwt_sign1, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify1 =
      CreateVerify(*handle1);
  ASSERT_THAT(jwt_verify1, IsOk());

  // Handle 2: key1 primary, key2 added.
  absl::StatusOr<KeysetHandle> handle2 =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*key1, KeyStatus::kEnabled,
                                      /*is_primary=*/true, test_case.id1))
          .AddEntry(CreateKeysetEntry(*key2, KeyStatus::kEnabled,
                                      /*is_primary=*/false, test_case.id2))
          .Build();
  ASSERT_THAT(handle2, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign2 =
      CreateSign(*handle2);
  ASSERT_THAT(jwt_sign2, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify2 =
      CreateVerify(*handle2);
  ASSERT_THAT(jwt_verify2, IsOk());

  // Handle 3: key2 is primary.
  absl::StatusOr<KeysetHandle> handle3 =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*key1, KeyStatus::kEnabled,
                                      /*is_primary=*/false, test_case.id1))
          .AddEntry(CreateKeysetEntry(*key2, KeyStatus::kEnabled,
                                      /*is_primary=*/true, test_case.id2))
          .Build();
  ASSERT_THAT(handle3, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign3 =
      CreateSign(*handle3);
  ASSERT_THAT(jwt_sign3, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify3 =
      CreateVerify(*handle3);
  ASSERT_THAT(jwt_verify3, IsOk());

  // Handle 4: key1 disabled.
  absl::StatusOr<KeysetHandle> handle4 =
      KeysetHandleBuilder()
          .AddEntry(CreateKeysetEntry(*key1, KeyStatus::kDisabled,
                                      /*is_primary=*/false, test_case.id1))
          .AddEntry(CreateKeysetEntry(*key2, KeyStatus::kEnabled,
                                      /*is_primary=*/true, test_case.id2))
          .Build();
  ASSERT_THAT(handle4, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign4 =
      CreateSign(*handle4);
  ASSERT_THAT(jwt_sign4, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify4 =
      CreateVerify(*handle4);
  ASSERT_THAT(jwt_verify4, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetJwtId("id123").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());
  absl::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact1 = (*jwt_sign1)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact1, IsOk());

  absl::StatusOr<std::string> compact2 = (*jwt_sign2)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact2, IsOk());

  absl::StatusOr<std::string> compact3 = (*jwt_sign3)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact3, IsOk());

  absl::StatusOr<std::string> compact4 = (*jwt_sign4)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact4, IsOk());

  EXPECT_THAT((*jwt_verify1)->VerifyAndDecode(*compact1, *validator), IsOk());
  EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact1, *validator), IsOk());
  EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact1, *validator), IsOk());
  EXPECT_THAT((*jwt_verify4)->VerifyAndDecode(*compact1, *validator),
              Not(IsOk()));

  EXPECT_THAT((*jwt_verify1)->VerifyAndDecode(*compact2, *validator), IsOk());
  EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact2, *validator), IsOk());
  EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact2, *validator), IsOk());
  EXPECT_THAT((*jwt_verify4)->VerifyAndDecode(*compact2, *validator),
              Not(IsOk()));

  EXPECT_THAT((*jwt_verify1)->VerifyAndDecode(*compact3, *validator),
              Not(IsOk()));
  EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact3, *validator), IsOk());
  EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact3, *validator), IsOk());
  EXPECT_THAT((*jwt_verify4)->VerifyAndDecode(*compact3, *validator), IsOk());

  EXPECT_THAT((*jwt_verify1)->VerifyAndDecode(*compact4, *validator),
              Not(IsOk()));
  EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact4, *validator), IsOk());
  EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact4, *validator), IsOk());
  EXPECT_THAT((*jwt_verify4)->VerifyAndDecode(*compact4, *validator), IsOk());
}

KeysetInfo::KeyInfo PopulateKeyInfo(uint32_t key_id,
                                    OutputPrefixType out_prefix_type,
                                    KeyStatusType status) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(out_prefix_type);
  key_info.set_key_id(key_id);
  key_info.set_status(status);
  return key_info;
}

// Creates a test keyset info object.
KeysetInfo CreateTestKeysetInfo() {
  KeysetInfo keyset_info;
  *keyset_info.add_key_info() =
      PopulateKeyInfo(/*key_id=*/1234543, OutputPrefixType::TINK,
                      /*status=*/KeyStatusType::ENABLED);
  *keyset_info.add_key_info() =
      PopulateKeyInfo(/*key_id=*/726329, OutputPrefixType::RAW,
                      /*status=*/KeyStatusType::ENABLED);
  *keyset_info.add_key_info() =
      PopulateKeyInfo(/*key_id=*/7213743, OutputPrefixType::TINK,
                      /*status=*/KeyStatusType::ENABLED);
  return keyset_info;
}

// Tests for the monitoring behavior.
class JwtPublicKeySetWrapperWithMonitoringTest : public Test {
 protected:
  // Perform some common initialization: reset the global registry, set expected
  // calls for the mock monitoring factory and the returned clients.
  void SetUp() override {
    Registry::Reset();

    // Setup mocks for catching Monitoring calls.
    auto monitoring_client_factory =
        std::make_unique<internal::MockMonitoringClientFactory>();
    auto monitoring_client =
        std::make_unique<StrictMock<internal::MockMonitoringClient>>();
    monitoring_client_ = monitoring_client.get();

    // Monitoring tests expect that the client factory will create the
    // corresponding internal::MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(Return(
            ByMove(absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>(
                std::move(monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  ~JwtPublicKeySetWrapperWithMonitoringTest() override { Registry::Reset(); }

  internal::MockMonitoringClient *monitoring_client_;
};

// Test that successful sign operations are logged.
TEST_F(JwtPublicKeySetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringSignSuccess) {
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  PrimitiveSet<JwtPublicKeySignInternal>::Builder sign_set_builder;
  sign_set_builder.AddAnnotations(kAnnotations);

  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign0 = JwtPublicKeySignImpl::Raw(
      std::make_unique<DummyPublicKeySign>("sign0"), "jwtsign0");
  sign_set_builder.AddPrimitive(std::move(jwt_sign0), keyset_info.key_info(0));
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign1 = JwtPublicKeySignImpl::Raw(
      std::make_unique<DummyPublicKeySign>("sign1"), "jwtsign1");
  sign_set_builder.AddPrimitive(std::move(jwt_sign1), keyset_info.key_info(1));
  // Set the last as primary.
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign2 = JwtPublicKeySignImpl::Raw(
      std::make_unique<DummyPublicKeySign>("sign2"), "jwtsign2");
  sign_set_builder.AddPrimaryPrimitive(std::move(jwt_sign2),
                                       keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<JwtPublicKeySignInternal>>
      public_key_sign_primitive_set = std::move(sign_set_builder).Build();
  ASSERT_THAT(public_key_sign_primitive_set, IsOk());

  // Record the ID of the primary key.
  const uint32_t kPrimaryKeyId = keyset_info.key_info(2).key_id();

  // Create a PublicKeySign primitive and sign some data.
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> public_key_sign =
      JwtPublicKeySignWrapper().Wrap(
          std::make_unique<PrimitiveSet<JwtPublicKeySignInternal>>(
              *std::move(public_key_sign_primitive_set)));
  ASSERT_THAT(public_key_sign, IsOkAndHolds(NotNull()));

  absl::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();

  ASSERT_THAT(raw_jwt, IsOk());

  // Check that calling Sign triggers a Log() call.
  EXPECT_CALL(*monitoring_client_, Log(kPrimaryKeyId, 1));
  EXPECT_THAT((*public_key_sign)->SignAndEncode(*raw_jwt), IsOk());
}

TEST_F(JwtPublicKeySetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringSignFailures) {
  KeysetInfo keyset_info = CreateTestKeysetInfo();

  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  PrimitiveSet<JwtPublicKeySignInternal>::Builder sign_set_builder;
  sign_set_builder.AddAnnotations(kAnnotations);
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign0 = JwtPublicKeySignImpl::Raw(
      CreateAlwaysFailingPublicKeySign("sign0"), "jwtsign0");
  sign_set_builder.AddPrimitive(std::move(jwt_sign0), keyset_info.key_info(0));
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign1 = JwtPublicKeySignImpl::Raw(
      CreateAlwaysFailingPublicKeySign("sign1"), "jwtsign1");
  sign_set_builder.AddPrimitive(std::move(jwt_sign1), keyset_info.key_info(1));
  // Set the last as primary.
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign2 = JwtPublicKeySignImpl::Raw(
      CreateAlwaysFailingPublicKeySign("sign2"), "jwtsign2");
  sign_set_builder.AddPrimaryPrimitive(std::move(jwt_sign2),
                                       keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<JwtPublicKeySignInternal>>
      public_key_sign_primitive_set = std::move(sign_set_builder).Build();
  ASSERT_THAT(public_key_sign_primitive_set, IsOk());

  // Create a PublicKeySign primitive and sign some data.
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> public_key_sign =
      JwtPublicKeySignWrapper().Wrap(
          std::make_unique<PrimitiveSet<JwtPublicKeySignInternal>>(
              *std::move(public_key_sign_primitive_set)));
  ASSERT_THAT(public_key_sign, IsOkAndHolds(NotNull()));

  absl::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();

  ASSERT_THAT(raw_jwt, IsOk());

  // Check that calling Sign triggers a LogFailure() call.
  EXPECT_CALL(*monitoring_client_, LogFailure());
  EXPECT_THAT((*public_key_sign)->SignAndEncode(*raw_jwt), Not(IsOk()));
}

// Test that successful verify operations are logged.
TEST_F(JwtPublicKeySetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringVerifySuccess) {
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  PrimitiveSet<JwtPublicKeyVerifyInternal>::Builder verify_set_builder;
  verify_set_builder.AddAnnotations(kAnnotations);
  verify_set_builder.AddPrimitive(
      JwtPublicKeyVerifyImpl::Raw(
          std::make_unique<DummyPublicKeyVerify>("verify0"), "jwtverify0"),
      keyset_info.key_info(0));
  verify_set_builder.AddPrimitive(
      JwtPublicKeyVerifyImpl::Raw(
          std::make_unique<DummyPublicKeyVerify>("verify1"), "jwtverify1"),
      keyset_info.key_info(1));
  // Set the last as primary.
  verify_set_builder.AddPrimaryPrimitive(
      JwtPublicKeyVerifyImpl::Raw(
          std::make_unique<DummyPublicKeyVerify>("verify2"), "jwtverify2"),
      keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<JwtPublicKeyVerifyInternal>>
      public_key_verify_primitive_set = std::move(verify_set_builder).Build();
  ASSERT_THAT(public_key_verify_primitive_set, IsOk());

  // Record the ID of the primary key.
  const uint32_t kPrimaryKeyId = keyset_info.key_info(2).key_id();

  // Create a PublicKeyVerify primitive and verify some data.
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> public_key_verify =
      JwtPublicKeyVerifyWrapper().Wrap(
          std::make_unique<PrimitiveSet<JwtPublicKeyVerifyInternal>>(
              *std::move(public_key_verify_primitive_set)));
  ASSERT_THAT(public_key_verify, IsOkAndHolds(NotNull()));

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();

  constexpr absl::string_view compact =
      "eyJ0eXAiOiJ0eXBlSGVhZGVyIiwiYWxnIjoiand0dmVyaWZ5MiIsImtpZCI6IkFHNFNydyJ9"
      ".eyJqdGkiOiJpZDEyMyJ9."
      "MTc6OTM6RHVtbXlTaWduOnZlcmlmeTJleUowZVhBaU9pSjBlWEJsU0dWaFpHVnlJaXdpWVd4"
      "bklqb2lhbmQwZG1WeWFXWjVNaUlzSW10cFpDSTZJa0ZITkZOeWR5SjkuZXlKcWRHa2lPaUpw"
      "WkRFeU15Sjk";

  // Check that calling Sign triggers a Log() call.
  EXPECT_CALL(*monitoring_client_, Log(kPrimaryKeyId, 1));
  EXPECT_THAT((*public_key_verify)->VerifyAndDecode(compact, *validator),
              IsOk());
}

// Test that successful verify operations are logged.
TEST_F(JwtPublicKeySetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringVerifyFailure) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  PrimitiveSet<JwtPublicKeyVerifyInternal>::Builder verify_set_builder;
  verify_set_builder.AddAnnotations(kAnnotations);
  verify_set_builder.AddPrimitive(
      JwtPublicKeyVerifyImpl::Raw(
          std::make_unique<DummyPublicKeyVerify>("verify0"), "jwtverify0"),
      keyset_info.key_info(0));
  verify_set_builder.AddPrimitive(
      JwtPublicKeyVerifyImpl::Raw(
          std::make_unique<DummyPublicKeyVerify>("verify1"), "jwtverify1"),
      keyset_info.key_info(1));
  // Set the last as primary.
  verify_set_builder.AddPrimaryPrimitive(
      JwtPublicKeyVerifyImpl::Raw(
          std::make_unique<DummyPublicKeyVerify>("verify2"), "jwtverify2"),
      keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<JwtPublicKeyVerifyInternal>>
      public_key_verify_primitive_set = std::move(verify_set_builder).Build();
  ASSERT_THAT(public_key_verify_primitive_set, IsOk());

  // Create a PublicKeyVerify primitive and verify some data.
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> public_key_verify =
      JwtPublicKeyVerifyWrapper().Wrap(
          std::make_unique<PrimitiveSet<JwtPublicKeyVerifyInternal>>(
              *std::move(public_key_verify_primitive_set)));
  ASSERT_THAT(public_key_verify, IsOkAndHolds(NotNull()));

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();

  constexpr absl::string_view compact =
      "eyJ0eXAiOiJ0eXBlSGVhZGVyIiwiYWxnIjoiand0dmVyaWZ5MiIsImtpZCI6IkFHNFNydyJ9"
      ".eyJqdGkiOiJpZDEyMyJ9."
      "MTc6OTM6RHVtbXlTaWduOnZlcmlmeTJleUowZVhBaU9pSjBlWEJsU0dWaFpHVnlJaXdpWVd4"
      "bklqb2lhbmQwZG1WeWFXWjVNaUlzSW10cFpDSTZJa0ZITkZOeWR5SjkuZXlKcWRHa2lPaUpw"
      "XXXXXXXXXXX";  // Wrong signature

  // Check that calling Sign triggers a Log() call.
  EXPECT_CALL(*monitoring_client_, LogFailure());
  EXPECT_THAT((*public_key_verify)->VerifyAndDecode(compact, *validator),
              Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
