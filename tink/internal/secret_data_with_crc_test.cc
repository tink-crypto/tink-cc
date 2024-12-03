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
#include "absl/strings/str_cat.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::crypto::tink::util::SecretValue;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::SizeIs;

TEST(SecretDataWithCrcTest, DefaultConstructor) {
  SecretDataWithCrc secret_data_with_crc;
  EXPECT_THAT(secret_data_with_crc.AsStringView(), IsEmpty());
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), absl::crc32c_t{0});
  EXPECT_EQ(secret_data_with_crc.GetCrc32c(), absl::crc32c_t{0});
}

TEST(SecretDataWithCrcTest, CreateWithComputedCrcEmpty) {
  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc("");
  EXPECT_THAT(secret_data_with_crc.AsStringView(), IsEmpty());
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), absl::crc32c_t{0});
  EXPECT_EQ(secret_data_with_crc.GetCrc32c(), absl::crc32c_t{0});
  }

TEST(SecretDataWithCrcTest, CreateWithComputedCrcNonEmpty) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc(data);
  EXPECT_THAT(secret_data_with_crc.AsStringView(), Eq(data));
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), crc);
  EXPECT_EQ(secret_data_with_crc.GetCrc32c(), crc);
}

TEST(SecretDataWithCrcTest, CreateWithComputedCrcSecretDataEmpty) {
  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc(SecretData());
  EXPECT_THAT(secret_data_with_crc.AsStringView(), IsEmpty());
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), absl::crc32c_t{0});
  EXPECT_EQ(secret_data_with_crc.GetCrc32c(), absl::crc32c_t{0});
}

TEST(SecretDataWithCrcTest, CreateWithComputedCrcSecretDataNonEmpty) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);
  SecretData secret_data = SecretDataFromStringView(data);
  SecretDataWithCrc secret_data_with_crc =
      SecretDataWithCrc::WithComputedCrc(secret_data);
  EXPECT_THAT(secret_data_with_crc.AsStringView(), Eq(data));
  EXPECT_EQ(secret_data_with_crc.SecretCrc().value(), crc);
  EXPECT_EQ(secret_data_with_crc.GetCrc32c(), crc);
}

TEST(SecretDataWithCrcTest, CreateWithCrc) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_1.AsStringView(), Eq(data));
  EXPECT_EQ(data_1.SecretCrc().value(), crc);
  EXPECT_EQ(data_1.GetCrc32c(), crc);
  EXPECT_THAT(data_1, SizeIs(data.size()));

  SecretData secret_data_2 = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data_2, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_2.AsStringView(), Eq(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_EQ(data_2.GetCrc32c(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));

  SecretData secret_data_3 = SecretDataFromStringView(data);
  SecretDataWithCrc data_3(std::move(secret_data_3),
                           SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_3.AsStringView(), Eq(data));
  EXPECT_EQ(data_3.SecretCrc().value(), crc);
  EXPECT_EQ(data_3.GetCrc32c(), crc);
  EXPECT_THAT(data_3, SizeIs(data.size()));
}

TEST(SecretDataWithCrcTest, ValidateCrcSucceeds) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_1.AsStringView(), Eq(data));
  EXPECT_THAT(data_1.ValidateCrc(), IsOk());

  SecretData secret_data = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_2.AsStringView(), Eq(data));
  EXPECT_THAT(data_2.ValidateCrc(), IsOk());

  SecretDataWithCrc data_3(std::move(secret_data),
                           SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_3.AsStringView(), Eq(data));
  EXPECT_THAT(data_3.ValidateCrc(), IsOk());
}

TEST(SecretDataWithCrcTest, ValidateCrcFailsIfWrong) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc =
      absl::crc32c_t{static_cast<uint32_t>(absl::ComputeCrc32c(data)) + 1};

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_1.ValidateCrc(), StatusIs(absl::StatusCode::kDataLoss));

  SecretData secret_data = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_2.ValidateCrc(), StatusIs(absl::StatusCode::kDataLoss));

  SecretDataWithCrc data_3(std::move(secret_data),
                           SecretValue<absl::crc32c_t>(crc));
  EXPECT_THAT(data_3.ValidateCrc(), StatusIs(absl::StatusCode::kDataLoss));
}

TEST(SecretDataWithCrcTest, AsStringViewWithInvalidCrcSucceeds) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc =
      absl::crc32c_t{static_cast<uint32_t>(absl::ComputeCrc32c(data)) + 1};

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_EQ(data_1.AsStringView(), data);

  SecretData secret_data = SecretDataFromStringView(data);
  SecretDataWithCrc data_2(secret_data, SecretValue<absl::crc32c_t>(crc));
  EXPECT_EQ(data_2.AsStringView(), data);

  SecretDataWithCrc data_3(std::move(secret_data),
                           SecretValue<absl::crc32c_t>(crc));
  EXPECT_EQ(data_3.AsStringView(), data);
}

TEST(SecretDataWithCrcTest, CopyConstructor) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2(data_1);
  EXPECT_THAT(data_2.AsStringView(), Eq(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_EQ(data_2.GetCrc32c(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWithCrcTest, CopyAssignment) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2;
  data_2 = data_1;
  EXPECT_THAT(data_2.AsStringView(), Eq(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_EQ(data_2.GetCrc32c(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWithCrcTest, MoveConstructor) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2(std::move(data_1));
  EXPECT_THAT(data_2.AsStringView(), Eq(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_EQ(data_2.GetCrc32c(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWithCrcTest, MoveAssignment) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc data_1(data, SecretValue<absl::crc32c_t>(crc));
  SecretDataWithCrc data_2;
  data_2 = data_1;
  EXPECT_THAT(data_2.AsStringView(), Eq(data));
  EXPECT_EQ(data_2.SecretCrc().value(), crc);
  EXPECT_EQ(data_2.GetCrc32c(), crc);
  EXPECT_THAT(data_2, SizeIs(data.size()));
}

TEST(SecretDataWithCrcTest, UncheckedAsSecretDataRvalueOverload) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc secret_data_with_crc(data,
                                         SecretValue<absl::crc32c_t>(crc));
  SecretData secret_data =
      std::move(secret_data_with_crc).UncheckedAsSecretData();
  EXPECT_THAT(SecretDataAsStringView(secret_data), Eq(data));
}

TEST(SecretDataWithCrcTest, UncheckedAsSecretDataConstRefOverload) {
  std::string data = Random::GetRandomBytes(256);
  absl::crc32c_t crc = absl::ComputeCrc32c(data);

  SecretDataWithCrc secret_data_with_crc(data,
                                         SecretValue<absl::crc32c_t>(crc));
  SecretData secret_data = secret_data_with_crc.UncheckedAsSecretData();
  EXPECT_THAT(SecretDataAsStringView(secret_data), Eq(data));
  EXPECT_THAT(secret_data_with_crc.AsStringView(), Eq(data));
}

TEST(SecretDataWithCrcTest, EqualityEqual) {
  SecretDataWithCrc secret_data_with_crc_1 =
      SecretDataWithCrc::WithComputedCrc("Some data");
  SecretDataWithCrc secret_data_with_crc_1_copy =
      SecretDataWithCrc::WithComputedCrc("Some data");
  EXPECT_THAT(secret_data_with_crc_1 == secret_data_with_crc_1_copy, IsTrue());
  EXPECT_THAT(secret_data_with_crc_1 != secret_data_with_crc_1_copy, IsFalse());
}

TEST(SecretDataWithCrcTest, EqualitySameSizeDifferentData) {
  SecretDataWithCrc secret_data_with_crc_1 =
      SecretDataWithCrc::WithComputedCrc("Some data");
  SecretDataWithCrc secret_data_with_crc_2 =
      SecretDataWithCrc::WithComputedCrc("SOME DATA");
  EXPECT_THAT(secret_data_with_crc_1 == secret_data_with_crc_2, IsFalse());
  EXPECT_THAT(secret_data_with_crc_1 != secret_data_with_crc_2, IsTrue());
}

TEST(SecretDataWithCrcTest, EqualityDifferentSize) {
  SecretDataWithCrc secret_data_with_crc_1 =
      SecretDataWithCrc::WithComputedCrc("Some data");
  SecretDataWithCrc secret_data_with_crc_2 =
      SecretDataWithCrc::WithComputedCrc("Some data 2");
  EXPECT_THAT(secret_data_with_crc_1 == secret_data_with_crc_2, IsFalse());
  EXPECT_THAT(secret_data_with_crc_1 != secret_data_with_crc_2, IsTrue());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
