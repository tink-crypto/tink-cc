// Copyright 2022 Google LLC
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

#include "tink/mac/internal/chunked_mac_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/chunked_mac.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretDataFromStringView;
using AesCmacKeyProto = ::google::crypto::tink::AesCmacKey;
using ::google::crypto::tink::AesCmacParams;
using ::google::crypto::tink::HashType;
using HmacKeyProto = ::google::crypto::tink::HmacKey;
using ::google::crypto::tink::HmacParams;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;

class MockStatefulMac : public StatefulMac {
 public:
  MOCK_METHOD(absl::Status, Update, (absl::string_view), (override));
  MOCK_METHOD(absl::StatusOr<SecretData>, FinalizeAsSecretData, (), (override));
};

class MockStatefulMacFactory : public StatefulMacFactory {
 public:
  MOCK_METHOD(absl::StatusOr<std::unique_ptr<StatefulMac>>, Create, (),
              (const, override));
};

TEST(ChunkedMacFactoryTest, NewChunkedCmacSucceeds) {
  AesCmacParams params;
  params.set_tag_size(16);
  AesCmacKeyProto key;
  *key.mutable_params() = params;

  EXPECT_THAT(NewChunkedCmac(key), IsOk());
}

TEST(ChunkedMacFactoryTest, NewChunkedCmacWithMissingKeyParamsFails) {
  EXPECT_THAT(NewChunkedCmac(AesCmacKeyProto()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChunkedMacFactoryTest, NewChunkedHmacSucceeds) {
  HmacParams params;
  params.set_hash(HashType::SHA256);
  params.set_tag_size(16);
  HmacKeyProto key;
  *key.mutable_params() = params;

  EXPECT_THAT(NewChunkedHmac(key), IsOk());
}

TEST(ChunkedMacFactoryTest, NewChunkedHmacWithMissingKeyParamsFails) {
  EXPECT_THAT(NewChunkedHmac(HmacKeyProto()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChunkedMacImplTest, CreateComputationSucceeds) {
  auto factory = absl::make_unique<MockStatefulMacFactory>();
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(absl::StatusOr<std::unique_ptr<StatefulMac>>(
          std::move(stateful_mac)))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateComputation(), IsOk());
}

TEST(ChunkedMacImplTest, CreateComputationWithFactoryErrorFails) {
  auto factory = absl::make_unique<MockStatefulMacFactory>();
  absl::StatusOr<std::unique_ptr<StatefulMac>> error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(std::move(error_status))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateComputation().status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(ChunkedMacImplTest, CreateVerificationSucceeds) {
  auto factory = absl::make_unique<MockStatefulMacFactory>();
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(absl::StatusOr<std::unique_ptr<StatefulMac>>(
          std::move(stateful_mac)))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateVerification("tag"), IsOk());
}

TEST(ChunkedMacImplTest, CreateVerificationWithFactoryErrorFails) {
  auto factory = absl::make_unique<MockStatefulMacFactory>();
  absl::StatusOr<std::unique_ptr<StatefulMac>> error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(std::move(error_status))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateVerification("tag").status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(ChunkedMacComputationImplTest, UpdateSucceeds) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(absl::OkStatus()));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.Update("data"), IsOk());
}

TEST(ChunkedMacComputationImplTest, UpdateFails) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(error_status));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.Update("data"), StatusIs(error_status.code()));
}

TEST(ChunkedMacComputationImplTest, OperationsFailAfterComputeMac) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.ComputeMac(), IsOkAndHolds("tag"));

  EXPECT_THAT(mac_computation.Update("data"),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(mac_computation.ComputeMac().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(ChunkedMacComputationImplTest, ComputeMacSucceeds) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.ComputeMac(), IsOkAndHolds("tag"));
}

TEST(ChunkedMacComputationImplTest, ComputeMacFails) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData())
      .WillOnce(Return(error_status));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.ComputeMac().status(),
              StatusIs(error_status.code()));
}

TEST(ChunkedMacVerificationImplTest, UpdateSucceeds) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(absl::OkStatus()));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.Update("data"), IsOk());
}

TEST(ChunkedMacVerificationImplTest, UpdateFails) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(error_status));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.Update("data"), StatusIs(error_status.code()));
}

TEST(ChunkedMacVerificationImplTest, VerifyMacSucceeds) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.VerifyMac(), IsOk());
}

TEST(ChunkedMacVerificationImplTest, VerifyMacFailsWithInvalidSameLengthTag) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag123");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac),
                                              "tag456");

  EXPECT_THAT(mac_verification.VerifyMac(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChunkedMacVerificationImplTest, VerifyMacFailsWithDifferentLengthTag) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac),
                                              "tag456");

  EXPECT_THAT(mac_verification.VerifyMac(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChunkedMacVerificationImplTest, VerifyMacFailsWithFinalizeError) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData())
      .WillOnce(Return(error_status));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.VerifyMac(), StatusIs(error_status.code()));
}

TEST(ChunkedMacVerificationImplTest, OperationsFailAfterVerifyMac) {
  auto stateful_mac = absl::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.VerifyMac(), IsOk());

  EXPECT_THAT(mac_verification.Update("data"),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(mac_verification.VerifyMac(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
