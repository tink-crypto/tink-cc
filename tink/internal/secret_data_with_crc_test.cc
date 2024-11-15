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

#include "tink/internal/secret_data_with_crc.h"

#include <cstdint>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::crypto::tink::util::SecretValue;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::SizeIs;

TEST(SecretDataWitCrcTest, DefaultConstructor) {
  SecretDataWithCrc secret_data_with_crc;
  EXPECT_THAT(secret_data_with_crc.data(), IsOkAndHolds(IsEmpty()));
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), absl::crc32c_t{0});
}

TEST(SecretDataWitCrcTest, CreateWithComputedCrcEmpty) {
  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc("");
  EXPECT_THAT(secret_data_with_crc.data(), IsOkAndHolds(IsEmpty()));
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), absl::crc32c_t{0});
}

TEST(SecretDataWitCrcTest, CreateWithComputedCrcNonEmpty) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc(data);
  EXPECT_THAT(secret_data_with_crc.data(), IsOkAndHolds(data));
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), crc);
}

TEST(SecretDataWitCrcTest, CreateWithComputedCrcSecretDataEmpty) {
  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc(SecretData());
  EXPECT_THAT(secret_data_with_crc.data(), IsOkAndHolds(IsEmpty()));
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), absl::crc32c_t{0});
}

TEST(SecretDataWitCrcTest, CreateWithComputedCrcSecretDataNonEmpty) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);
  SecretData secret_data = SecretDataFromStringView(data);
  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc(secret_data);
  EXPECT_THAT(secret_data_with_crc.data(), IsOkAndHolds(data));
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), crc);
}

TEST(SecretDataWitCrcTest, CreateWithCrc) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_1.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_1.SecretCrc().value(), crc);
  EXPECT_THAT(data_1, SizeIs(data.size()));

  SecretData secret_data_2 = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data_2, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_2.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));

  SecretData secret_data_3 = SecretDataFromStringView(data);
  SecretDataWithCrc data_3(std::move(secret_data_3),
                           SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_3.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_3.SecretCrc().value(), crc);
  EXPECT_THAT(data_3, SizeIs(data.size()));
}

TEST(SecretDataWitCrcTest, CreateWithoutCrc) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data);
  EXPECT_THAT(data_1.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_1.SecretCrc().value(), crc);
  EXPECT_THAT(data_1, SizeIs(data.size()));

  SecretData secret_data_2 = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data_2);
  EXPECT_THAT(data_2.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));

  SecretData secret_data_3 = SecretDataFromStringView(data);
  SecretDataWithCrc data_3(std::move(secret_data_3));
  EXPECT_THAT(data_3.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_3.SecretCrc().value(), crc);
  EXPECT_THAT(data_3, SizeIs(data.size()));
}

TEST(SecretDataWitCrcTest, DataWithInvalidCrcFails) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc =
      absl::crc32c_t{static_cast<uint32_t>(absl::ComputeCrc32c(data)) + 1};

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_1.data(), StatusIs(absl::StatusCode::kDataLoss));

  SecretData secret_data = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_2.data(), StatusIs(absl::StatusCode::kDataLoss));

  SecretDataWithCrc data_3(std::move(secret_data),
                           SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_3.data(), StatusIs(absl::StatusCode::kDataLoss));
}

TEST(SecretDataWitCrcTest, UncheckedDataWithInvalidCrcSucceeds) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc =
      absl::crc32c_t{static_cast<uint32_t>(absl::ComputeCrc32c(data)) + 1};

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_EQ(data_1.UncheckedData(), data);

  SecretData secret_data = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_EQ(data_2.UncheckedData(), data);

  SecretDataWithCrc data_3(std::move(secret_data),
                           SecretValue<absl::crc32c_t>(crc));
  EXPECT_EQ(data_3.UncheckedData(), data);
}

TEST(SecretDataWitCrcTest, CopyConstructor) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2(data_1);
  EXPECT_THAT(data_2.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWitCrcTest, CopyAssignment) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2;
  data_2 = data_1;
  EXPECT_THAT(data_2.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWitCrcTest, MoveConstructor) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2(std::move(data_1));
  EXPECT_THAT(data_2.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWitCrcTest, MoveAssignment) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2;
  data_2 = data_1;
  EXPECT_THAT(data_2.data(), IsOkAndHolds(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWitCrcTest, UncheckedAsSecretDataRvalueOverload) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc secret_data_with_crc(data,
                                         SecretValue<absl::crc32c_t>(crc));
  SecretData secret_data =
      std::move(secret_data_with_crc).UncheckedAsSecretData();
  EXPECT_THAT(SecretDataAsStringView(secret_data), Eq(data));
}

TEST(SecretDataWitCrcTest, UncheckedAsSecretDataConstRefOverload) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc secret_data_with_crc(data,
                                         SecretValue<absl::crc32c_t>(crc));
  SecretData secret_data = secret_data_with_crc.UncheckedAsSecretData();
  EXPECT_THAT(SecretDataAsStringView(secret_data), Eq(data));
  EXPECT_THAT(secret_data_with_crc.data(), IsOkAndHolds(data));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
