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

#include <cstddef>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/chunked_mac.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/aes_cmac_test_vectors.h"
#include "tink/mac/internal/hmac_test_vectors.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "proto/aes_cmac.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::util::SecretDataFromStringView;
using AesCmacKeyProto = ::google::crypto::tink::AesCmacKey;
using ::google::crypto::tink::AesCmacParams;
using ::google::crypto::tink::HashType;
using HmacKeyProto = ::google::crypto::tink::HmacKey;
using ::google::crypto::tink::HmacParams;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Eq;
using ::testing::Not;
using ::testing::Return;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

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
  auto factory = std::make_unique<MockStatefulMacFactory>();
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(absl::StatusOr<std::unique_ptr<StatefulMac>>(
          std::move(stateful_mac)))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateComputation(), IsOk());
}

TEST(ChunkedMacImplTest, CreateComputationWithFactoryErrorFails) {
  auto factory = std::make_unique<MockStatefulMacFactory>();
  absl::StatusOr<std::unique_ptr<StatefulMac>> error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(std::move(error_status))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateComputation().status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(ChunkedMacImplTest, CreateVerificationSucceeds) {
  auto factory = std::make_unique<MockStatefulMacFactory>();
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(absl::StatusOr<std::unique_ptr<StatefulMac>>(
          std::move(stateful_mac)))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateVerification("tag"), IsOk());
}

TEST(ChunkedMacImplTest, CreateVerificationWithFactoryErrorFails) {
  auto factory = std::make_unique<MockStatefulMacFactory>();
  absl::StatusOr<std::unique_ptr<StatefulMac>> error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*factory, Create())
      .WillOnce(Return(ByMove(std::move(error_status))));
  ChunkedMacImpl chunked_mac(std::move(factory));

  EXPECT_THAT(chunked_mac.CreateVerification("tag").status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(ChunkedMacComputationImplTest, UpdateSucceeds) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(absl::OkStatus()));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.Update("data"), IsOk());
}

TEST(ChunkedMacComputationImplTest, UpdateFails) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(error_status));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.Update("data"), StatusIs(error_status.code()));
}

TEST(ChunkedMacComputationImplTest, OperationsFailAfterComputeMac) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
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
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.ComputeMac(), IsOkAndHolds("tag"));
}

TEST(ChunkedMacComputationImplTest, ComputeMacWithPrefixAndSuffixSucceeds) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, Update(absl::string_view("\0", 1)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac), "prefix_",
                                            absl::string_view("\0", 1));

  EXPECT_THAT(mac_computation.ComputeMac(), IsOkAndHolds("prefix_tag"));
}

TEST(ChunkedMacComputationImplTest, ComputeMacFails) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData())
      .WillOnce(Return(error_status));
  ChunkedMacComputationImpl mac_computation(std::move(stateful_mac));

  EXPECT_THAT(mac_computation.ComputeMac().status(),
              StatusIs(error_status.code()));
}

TEST(ChunkedMacVerificationImplTest, UpdateSucceeds) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(absl::OkStatus()));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.Update("data"), IsOk());
}

TEST(ChunkedMacVerificationImplTest, UpdateFails) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, Update(_)).WillOnce(Return(error_status));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.Update("data"), StatusIs(error_status.code()));
}

TEST(ChunkedMacVerificationImplTest, VerifyMacSucceeds) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.VerifyMac(), IsOk());
}

TEST(ChunkedMacVerificationImplTest, VerifyMacWithPrefixAndSuffixSucceeds) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, Update(absl::string_view("\0", 1)))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac),
                                              "prefix_tag", "prefix_",
                                              absl::string_view("\0", 1));

  EXPECT_THAT(mac_verification.VerifyMac(), IsOk());
}

TEST(ChunkedMacVerificationImplTest, VerifyMacFailsWithInvalidPrefix) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac),
                                              "wrong_tag", "prefix_");

  EXPECT_THAT(mac_verification.VerifyMac(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChunkedMacVerificationImplTest, VerifyMacFailsWithInvalidSameLengthTag) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag123");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac),
                                              "tag456");

  EXPECT_THAT(mac_verification.VerifyMac(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChunkedMacVerificationImplTest, VerifyMacFailsWithDifferentLengthTag) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac),
                                              "tag456");

  EXPECT_THAT(mac_verification.VerifyMac(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChunkedMacVerificationImplTest, VerifyMacFailsWithFinalizeError) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::Status error_status =
      absl::Status(absl::StatusCode::kInternal, "Internal error.");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData())
      .WillOnce(Return(error_status));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.VerifyMac(), StatusIs(error_status.code()));
}

TEST(ChunkedMacVerificationImplTest, OperationsFailAfterVerifyMac) {
  auto stateful_mac = std::make_unique<MockStatefulMac>();
  absl::StatusOr<SecretData> tag = SecretDataFromStringView("tag");
  EXPECT_CALL(*stateful_mac, FinalizeAsSecretData()).WillOnce(Return(tag));
  ChunkedMacVerificationImpl mac_verification(std::move(stateful_mac), "tag");

  EXPECT_THAT(mac_verification.VerifyMac(), IsOk());

  EXPECT_THAT(mac_verification.Update("data"),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(mac_verification.VerifyMac(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

using NewChunkedCmacTestVectorsTest = TestWithParam<TinkAesCmacTestVector>;

TEST_P(NewChunkedCmacTestVectorsTest, ComputeAndVerifyMac) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const TinkAesCmacTestVector& param = GetParam();

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      NewChunkedCmac(param.key);
  ASSERT_THAT(chunked_mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update(param.message), IsOk());
  EXPECT_THAT((*computation)->ComputeMac(), IsOkAndHolds(Eq(param.tag)));

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(param.tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(param.message), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());

  // Modify a byte in the tag (covers prefix and raw tag bytes).
  for (size_t i = 0; i < param.tag.size(); ++i) {
    std::string modified_tag = param.tag;
    modified_tag[i] ^= 1;
    absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
        (*chunked_mac)->CreateVerification(modified_tag);
    ASSERT_THAT(bad_verification, IsOk());
    ASSERT_THAT((*bad_verification)->Update(param.message), IsOk());
    EXPECT_THAT((*bad_verification)->VerifyMac(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  // Truncate or extend the tag.
  for (size_t i = 0; i < param.tag.size(); ++i) {
    absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
        (*chunked_mac)
            ->CreateVerification(absl::string_view(param.tag).substr(0, i));
    ASSERT_THAT(bad_verification, IsOk());
    ASSERT_THAT((*bad_verification)->Update(param.message), IsOk());
    EXPECT_THAT((*bad_verification)->VerifyMac(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    std::string extended_tag = param.tag + "x";
    absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
        (*chunked_mac)->CreateVerification(extended_tag);
    ASSERT_THAT(bad_verification, IsOk());
    ASSERT_THAT((*bad_verification)->Update(param.message), IsOk());
    EXPECT_THAT((*bad_verification)->VerifyMac(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    std::string modified_message = param.message + "x";
    absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
        (*chunked_mac)->CreateVerification(param.tag);
    ASSERT_THAT(bad_verification, IsOk());
    ASSERT_THAT((*bad_verification)->Update(modified_message), IsOk());
    EXPECT_THAT((*bad_verification)->VerifyMac(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

INSTANTIATE_TEST_SUITE_P(NewChunkedCmacTestVectorsTest,
                         NewChunkedCmacTestVectorsTest,
                         ValuesIn(AesCmacTestVectors()),
                         [](const TestParamInfo<TinkAesCmacTestVector>& info) {
                           return info.param.test_name;
                         });

TEST(NewChunkedCmacTest, FailInFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only test in FIPS-only mode";
  }
  const TinkAesCmacTestVector& param = AesCmacTestVectors()[0];
  EXPECT_THAT(NewChunkedCmac(param.key), Not(IsOk()));
}

using NewChunkedHmacTestVectorsTest = TestWithParam<HmacTestVector>;

TEST_P(NewChunkedHmacTestVectorsTest, ComputeMac) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& param = GetParam();

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      NewChunkedHmac(param.key);
  ASSERT_THAT(chunked_mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update(param.message), IsOk());
  EXPECT_THAT((*computation)->ComputeMac(), IsOkAndHolds(Eq(param.tag)));
}

TEST_P(NewChunkedHmacTestVectorsTest, VerifyMac) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& param = GetParam();

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      NewChunkedHmac(param.key);
  ASSERT_THAT(chunked_mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(param.tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(param.message), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST_P(NewChunkedHmacTestVectorsTest, VerifyMacFailsWithModifiedTagByte) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& param = GetParam();

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      NewChunkedHmac(param.key);
  ASSERT_THAT(chunked_mac, IsOk());

  // Modify a byte in the tag (covers prefix and raw tag bytes).
  for (size_t i = 0; i < param.tag.size(); ++i) {
    std::string modified_tag = param.tag;
    modified_tag[i] ^= 1;
    absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
        (*chunked_mac)->CreateVerification(modified_tag);
    ASSERT_THAT(bad_verification, IsOk());
    ASSERT_THAT((*bad_verification)->Update(param.message), IsOk());
    EXPECT_THAT((*bad_verification)->VerifyMac(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(NewChunkedHmacTestVectorsTest,
       VerifyMacFailsWithTruncatedOrExtendedTag) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& param = GetParam();

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      NewChunkedHmac(param.key);
  ASSERT_THAT(chunked_mac, IsOk());

  // Truncate or extend the tag.
  for (size_t i = 0; i < param.tag.size(); ++i) {
    absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
        (*chunked_mac)
            ->CreateVerification(absl::string_view(param.tag).substr(0, i));
    ASSERT_THAT(bad_verification, IsOk());
    ASSERT_THAT((*bad_verification)->Update(param.message), IsOk());
    EXPECT_THAT((*bad_verification)->VerifyMac(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  std::string extended_tag = param.tag + "x";
  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
      (*chunked_mac)->CreateVerification(extended_tag);
  ASSERT_THAT(bad_verification, IsOk());
  ASSERT_THAT((*bad_verification)->Update(param.message), IsOk());
  EXPECT_THAT((*bad_verification)->VerifyMac(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(NewChunkedHmacTestVectorsTest, VerifyMacFailsWithModifiedMessage) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& param = GetParam();

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      NewChunkedHmac(param.key);
  ASSERT_THAT(chunked_mac, IsOk());

  std::string modified_message = param.message + "x";
  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> bad_verification =
      (*chunked_mac)->CreateVerification(param.tag);
  ASSERT_THAT(bad_verification, IsOk());
  ASSERT_THAT((*bad_verification)->Update(modified_message), IsOk());
  EXPECT_THAT((*bad_verification)->VerifyMac(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

INSTANTIATE_TEST_SUITE_P(NewChunkedHmacTestVectorsTest,
                         NewChunkedHmacTestVectorsTest,
                         ValuesIn(CreateHmacTestVectors()));

TEST(NewChunkedHmacTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test only run in FIPS-only mode";
  }
  const HmacTestVector& test_vector = GetHmacTestVector(
      /*key_size_in_bytes=*/16, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kTink);
  if (IsFipsEnabledInSsl()) {
    EXPECT_THAT(NewChunkedHmac(test_vector.key), IsOk());
  } else {
    EXPECT_THAT(NewChunkedHmac(test_vector.key), Not(IsOk()));
  }
}
}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
