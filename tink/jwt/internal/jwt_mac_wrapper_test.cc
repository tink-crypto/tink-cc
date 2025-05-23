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

#include "tink/jwt/internal/jwt_mac_wrapper.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/config/global_registry.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_client_mocks.h"
#include "tink/internal/registry_impl.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_hmac_key_manager.h"
#include "tink/jwt/internal/jwt_mac_impl.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/keyset_manager.h"
#include "tink/mac/failing_mac.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::JwtHmacAlgorithm;
using google::crypto::tink::JwtHmacKeyFormat;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::test::DummyMac;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::Test;

KeyTemplate createTemplate(OutputPrefixType output_prefix) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtHmacKey");
  key_template.set_output_prefix_type(output_prefix);
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

std::unique_ptr<KeysetHandle> KeysetHandleWithNewKeyId(
    const KeysetHandle& keyset_handle) {
  Keyset keyset(CleartextKeysetHandle::GetKeyset(keyset_handle));
  uint32_t new_key_id = keyset.mutable_key(0)->key_id() ^ 0xdeadbeef;
  keyset.mutable_key(0)->set_key_id(new_key_id);
  keyset.set_primary_key_id(new_key_id);
  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

std::unique_ptr<KeysetHandle> KeysetHandleWithTinkPrefix(
    const KeysetHandle& keyset_handle) {
  Keyset keyset(CleartextKeysetHandle::GetKeyset(keyset_handle));
  keyset.mutable_key(0)->set_output_prefix_type(OutputPrefixType::TINK);
  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

class JwtMacWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(
        Registry::RegisterPrimitiveWrapper(absl::make_unique<JwtMacWrapper>()),
        IsOk());
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    absl::make_unique<JwtHmacKeyManager>(), true),
                IsOk());
  }
};

TEST_F(JwtMacWrapperTest, WrapNullptr) {
  absl::StatusOr<std::unique_ptr<JwtMac>> mac_result =
      JwtMacWrapper().Wrap(nullptr);
  EXPECT_FALSE(mac_result.ok());
}

TEST_F(JwtMacWrapperTest, WrapEmpty) {
  auto jwt_mac_set = absl::make_unique<PrimitiveSet<JwtMacInternal>>();
  absl::StatusOr<std::unique_ptr<crypto::tink::JwtMac>> jwt_mac_result =
      JwtMacWrapper().Wrap(std::move(jwt_mac_set));
  EXPECT_FALSE(jwt_mac_result.ok());
}

TEST_F(JwtMacWrapperTest, CannotWrapPrimitivesFromNonRawOrTinkKeys) {
  KeyTemplate tink_key_template = createTemplate(OutputPrefixType::LEGACY);

  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(tink_key_template,
                                KeyGenConfigGlobalRegistry());
  EXPECT_THAT(keyset_handle, IsOk());

  EXPECT_FALSE((*keyset_handle)
                   ->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry())
                   .status()
                   .ok());
}

TEST_F(JwtMacWrapperTest, GenerateRawComputeVerifySuccess) {
  KeyTemplate key_template = createTemplate(OutputPrefixType::RAW);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  EXPECT_THAT(keyset_handle, IsOk());
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry());
  EXPECT_THAT(jwt_mac, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("issuer"));

  absl::StatusOr<JwtValidator> validator2 = JwtValidatorBuilder()
                                                .ExpectIssuer("unknown")
                                                .AllowMissingExpiration()
                                                .Build();
  ASSERT_THAT(validator2, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt2 =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator2);
  EXPECT_FALSE(verified_jwt2.ok());
  // Make sure the error message is interesting
  EXPECT_THAT(verified_jwt2.status().message(), Eq("wrong issuer"));

  // Raw primitives don't add a kid header, Tink primitives require a kid
  // header to be set. Thefore, changing the output prefix to TINK makes the
  // validation fail.
  std::unique_ptr<KeysetHandle> tink_keyset_handle =
      KeysetHandleWithTinkPrefix(**keyset_handle);
  absl::StatusOr<std::unique_ptr<JwtMac>> tink_jwt_mac =
      tink_keyset_handle->GetPrimitive<crypto::tink::JwtMac>(
          ConfigGlobalRegistry());
  ASSERT_THAT(tink_jwt_mac, IsOk());

  EXPECT_THAT(
      (*tink_jwt_mac)->VerifyMacAndDecode(*compact, *validator).status(),
      Not(IsOk()));
}

TEST_F(JwtMacWrapperTest, GenerateTinkComputeVerifySuccess) {
  KeyTemplate key_template = createTemplate(OutputPrefixType::TINK);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  EXPECT_THAT(keyset_handle, IsOk());
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry());
  EXPECT_THAT(jwt_mac, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  // Parse header to make sure that key ID is correctly encoded.
  google::crypto::tink::KeysetInfo keyset_info =
      (*keyset_handle)->GetKeysetInfo();
  uint32_t key_id = keyset_info.key_info(0).key_id();
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  absl::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header, IsOk());
  EXPECT_THAT(GetKeyId((*header).fields().find("kid")->second.string_value()),
              key_id);

  // For Tink primitives, the kid must be correctly set and is verified.
  // Therefore, changing the key_id makes the validation fail.
  std::unique_ptr<KeysetHandle> keyset_handle_with_new_key_id =
      KeysetHandleWithNewKeyId(**keyset_handle);
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac_with_new_key_id =
      keyset_handle_with_new_key_id->GetPrimitive<crypto::tink::JwtMac>(
          ConfigGlobalRegistry());
  ASSERT_THAT(jwt_mac_with_new_key_id, IsOk());

  absl::StatusOr<VerifiedJwt> verified_jwt_2 =
      (*jwt_mac_with_new_key_id)->VerifyMacAndDecode(*compact, *validator);
  EXPECT_FALSE(verified_jwt_2.ok());
}

TEST_F(JwtMacWrapperTest, KeyRotation) {
  std::vector<OutputPrefixType> prefixes = {OutputPrefixType::RAW,
                                            OutputPrefixType::TINK};
  for (OutputPrefixType prefix : prefixes) {
    SCOPED_TRACE(absl::StrCat("Testing with prefix ", prefix));
    KeyTemplate key_template = createTemplate(prefix);
    KeysetManager manager;

    absl::StatusOr<uint32_t> old_id = manager.Add(key_template);
    ASSERT_THAT(old_id, IsOk());
    ASSERT_THAT(manager.SetPrimary(*old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle1 = manager.GetKeysetHandle();
    absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac1 =
        handle1->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry());
    ASSERT_THAT(jwt_mac1, IsOk());

    absl::StatusOr<uint32_t> new_id = manager.Add(key_template);
    ASSERT_THAT(new_id, IsOk());
    std::unique_ptr<KeysetHandle> handle2 = manager.GetKeysetHandle();
    absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac2 =
        handle2->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry());
    ASSERT_THAT(jwt_mac2, IsOk());

    ASSERT_THAT(manager.SetPrimary(*new_id), IsOk());
    std::unique_ptr<KeysetHandle> handle3 = manager.GetKeysetHandle();
    absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac3 =
        handle3->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry());
    ASSERT_THAT(jwt_mac3, IsOk());

    ASSERT_THAT(manager.Disable(*old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle4 = manager.GetKeysetHandle();
    absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac4 =
        handle4->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry());
    ASSERT_THAT(jwt_mac4, IsOk());

    absl::StatusOr<RawJwt> raw_jwt =
        RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
    ASSERT_THAT(raw_jwt, IsOk());
    absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                                 .ExpectIssuer("issuer")
                                                 .AllowMissingExpiration()
                                                 .Build();
    ASSERT_THAT(validator, IsOk());

    absl::StatusOr<std::string> compact1 =
        (*jwt_mac1)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact1, IsOk());

    absl::StatusOr<std::string> compact2 =
        (*jwt_mac2)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact2, IsOk());

    absl::StatusOr<std::string> compact3 =
        (*jwt_mac3)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact3, IsOk());

    absl::StatusOr<std::string> compact4 =
        (*jwt_mac4)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact4, IsOk());

    EXPECT_THAT((*jwt_mac1)->VerifyMacAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_FALSE((*jwt_mac4)->VerifyMacAndDecode(*compact1, *validator).ok());

    EXPECT_THAT((*jwt_mac1)->VerifyMacAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_FALSE((*jwt_mac4)->VerifyMacAndDecode(*compact2, *validator).ok());

    EXPECT_FALSE((*jwt_mac1)->VerifyMacAndDecode(*compact3, *validator).ok());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact3, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact3, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac4)->VerifyMacAndDecode(*compact3, *validator).status(),
                IsOk());

    EXPECT_FALSE((*jwt_mac1)->VerifyMacAndDecode(*compact4, *validator).ok());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact4, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact4, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac4)->VerifyMacAndDecode(*compact4, *validator).status(),
                IsOk());
  }
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
class JwtMacSetWrapperWithMonitoringTest : public Test {
 protected:
  // Perform some common initialization: reset the global registry, set expected
  // calls for the mock monitoring factory and the returned clients.
  void SetUp() override {
    Registry::Reset();

    // Setup mocks for catching Monitoring calls.
    auto monitoring_client_factory =
        absl::make_unique<internal::MockMonitoringClientFactory>();
    auto compute_monitoring_client =
        absl::make_unique<NiceMock<internal::MockMonitoringClient>>();
    compute_monitoring_client_ = compute_monitoring_client.get();
    auto verify_monitoring_client =
        absl::make_unique<NiceMock<internal::MockMonitoringClient>>();
    verify_monitoring_client_ = verify_monitoring_client.get();

    // Monitoring tests expect that the client factory will create the
    // corresponding internal::MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(Return(
            ByMove(absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>(
                std::move(compute_monitoring_client)))))
        .WillOnce(Return(
            ByMove(absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>(
                std::move(verify_monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  ~JwtMacSetWrapperWithMonitoringTest() override { Registry::Reset(); }

  internal::MockMonitoringClient* compute_monitoring_client_;
  internal::MockMonitoringClient* verify_monitoring_client_;
};

// Tests that successful ComputeMac operations are logged.
TEST_F(JwtMacSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringComputeSuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto jwt_mac_primitive_set =
      absl::make_unique<PrimitiveSet<JwtMacInternal>>(annotations);

  ASSERT_THAT(
      jwt_mac_primitive_set
          ->AddPrimitive(
              JwtMacImpl::Raw(absl::make_unique<DummyMac>("mac0"), "jwtmac0"),
              keyset_info.key_info(0))
          .status(),
      IsOk());
  ASSERT_THAT(
      jwt_mac_primitive_set
          ->AddPrimitive(
              JwtMacImpl::Raw(absl::make_unique<DummyMac>("mac1"), "jwtmac1"),
              keyset_info.key_info(1))
          .status(),
      IsOk());
  // Set the last as primary.
  absl::StatusOr<PrimitiveSet<JwtMacInternal>::Entry<JwtMacInternal>*> last =
      jwt_mac_primitive_set->AddPrimitive(
          JwtMacImpl::Raw(absl::make_unique<DummyMac>("mac2"), "jwtmac2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last.status(), IsOk());
  ASSERT_THAT(jwt_mac_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t primary_key_id = keyset_info.key_info(2).key_id();

  // Create a JWT and compute an authentication tag
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      JwtMacWrapper().Wrap(std::move(jwt_mac_primitive_set));
  ASSERT_THAT(jwt_mac, IsOkAndHolds(NotNull()));

  absl::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();

  ASSERT_THAT(raw_jwt, IsOk());

  // Check that calling ComputeMac triggers a Log() call.
  EXPECT_CALL(*compute_monitoring_client_, Log(primary_key_id, 1));
  EXPECT_THAT((*jwt_mac)->ComputeMacAndEncode(*raw_jwt).status(), IsOk());
}

// Test that successful VerifyMac operations are logged.
TEST_F(JwtMacSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringVerifySuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto jwt_mac_primitive_set =
      absl::make_unique<PrimitiveSet<JwtMacInternal>>(annotations);

  ASSERT_THAT(
      jwt_mac_primitive_set
          ->AddPrimitive(
              JwtMacImpl::Raw(absl::make_unique<DummyMac>("mac0"), "jwtmac0"),
              keyset_info.key_info(0))
          .status(),
      IsOk());
  ASSERT_THAT(
      jwt_mac_primitive_set
          ->AddPrimitive(
              JwtMacImpl::Raw(absl::make_unique<DummyMac>("mac1"), "jwtmac1"),
              keyset_info.key_info(1))
          .status(),
      IsOk());
  // Set the last as primary.
  absl::StatusOr<PrimitiveSet<JwtMacInternal>::Entry<JwtMacInternal>*> last =
      jwt_mac_primitive_set->AddPrimitive(
          JwtMacImpl::Raw(absl::make_unique<DummyMac>("mac2"), "jwtmac2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last.status(), IsOk());
  ASSERT_THAT(jwt_mac_primitive_set->set_primary(*last), IsOk());

  // Record the ID of the primary key.
  const uint32_t primary_key_id = keyset_info.key_info(2).key_id();

  // Create a MAC, compute a Mac and verify it.
  absl::StatusOr<std::unique_ptr<JwtMac>> mac =
      JwtMacWrapper().Wrap(std::move(jwt_mac_primitive_set));
  ASSERT_THAT(mac, IsOkAndHolds(NotNull()));

  absl::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();

  ASSERT_THAT(raw_jwt, IsOk());

  // Check that calling VerifyMac triggers a Log() call.
  absl::StatusOr<std::string> compact = (*mac)->ComputeMacAndEncode(*raw_jwt);
  EXPECT_THAT(compact.status(), IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  // In the log expect the size of the message without the non-raw prefix.
  EXPECT_CALL(*verify_monitoring_client_, Log(primary_key_id, 1));
  EXPECT_THAT((*mac)->VerifyMacAndDecode(*compact, *validator), IsOk());
}

TEST_F(JwtMacSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringComputeFailures) {
  // Create a primitive set and fill it with some entries.
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};

  auto jwt_mac_primitive_set =
      absl::make_unique<PrimitiveSet<JwtMacInternal>>(annotations);

  ASSERT_THAT(jwt_mac_primitive_set
                  ->AddPrimitive(JwtMacImpl::Raw(CreateAlwaysFailingMac("mac0"),
                                                 "jwtmac0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(jwt_mac_primitive_set
                  ->AddPrimitive(JwtMacImpl::Raw(CreateAlwaysFailingMac("mac1"),
                                                 "jwtmac1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  absl::StatusOr<PrimitiveSet<JwtMacInternal>::Entry<JwtMacInternal>*> last =
      jwt_mac_primitive_set->AddPrimitive(
          JwtMacImpl::Raw(CreateAlwaysFailingMac("mac2"), "jwtmac2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last.status(), IsOk());
  ASSERT_THAT(jwt_mac_primitive_set->set_primary(*last), IsOk());

  // Create a JWT and compute an authentication tag
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      JwtMacWrapper().Wrap(std::move(jwt_mac_primitive_set));
  ASSERT_THAT(jwt_mac, IsOkAndHolds(NotNull()));

  absl::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .WithoutExpiration()
                                       .Build();

  ASSERT_THAT(raw_jwt, IsOk());

  // Check that calling ComputeMac triggers a LogFailure() call.
  EXPECT_CALL(*compute_monitoring_client_, LogFailure());
  EXPECT_FALSE((*jwt_mac)->ComputeMacAndEncode(*raw_jwt).status().ok());
}

// Test that monitoring logs verify failures correctly.
TEST_F(JwtMacSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringVerifyFailures) {
  // Create a primitive set and fill it with some entries.
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};

  auto jwt_mac_primitive_set =
      absl::make_unique<PrimitiveSet<JwtMacInternal>>(annotations);

  ASSERT_THAT(jwt_mac_primitive_set
                  ->AddPrimitive(JwtMacImpl::Raw(CreateAlwaysFailingMac("mac0"),
                                                 "jwtmac0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(jwt_mac_primitive_set
                  ->AddPrimitive(JwtMacImpl::Raw(CreateAlwaysFailingMac("mac1"),
                                                 "jwtmac1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  absl::StatusOr<PrimitiveSet<JwtMacInternal>::Entry<JwtMacInternal>*> last =
      jwt_mac_primitive_set->AddPrimitive(
          JwtMacImpl::Raw(CreateAlwaysFailingMac("mac2"), "jwtmac2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last.status(), IsOk());
  ASSERT_THAT(jwt_mac_primitive_set->set_primary(*last), IsOk());

  // Create a JWT and verify it
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      JwtMacWrapper().Wrap(std::move(jwt_mac_primitive_set));
  ASSERT_THAT(jwt_mac, IsOkAndHolds(NotNull()));

  constexpr absl::string_view invalid_compact = "something is wrong here";

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  // Check that calling VerifyMac triggers a LogFailure() call.
  EXPECT_CALL(*verify_monitoring_client_, LogFailure());
  EXPECT_FALSE(
      (*jwt_mac)->VerifyMacAndDecode(invalid_compact, *validator).ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
