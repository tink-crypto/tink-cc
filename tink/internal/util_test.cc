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
///////////////////////////////////////////////////////////////////////////////
#include "tink/internal/util.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::EqualsSecretData;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::Not;

constexpr absl::string_view kLongString =
    "a long buffer with \n several \n newlines";

class Base {
 public:
  virtual ~Base() = default;
};

class Derived : public Base {};

class OtherDerived : public Base {};

TEST(DynamicCastOrError, Works) {
  std::unique_ptr<Base> base = std::make_unique<Derived>();
  absl::StatusOr<std::unique_ptr<Derived>> derived =
      DynamicCast<Derived>(std::move(base));
  EXPECT_THAT(derived, IsOkAndHolds(Not(IsNull())));
}

TEST(DynamicCastOrError, NullptrMakesError) {
  std::unique_ptr<Base> base = nullptr;
  absl::StatusOr<std::unique_ptr<Derived>> derived =
      DynamicCast<Derived>(std::move(base));
  EXPECT_THAT(derived, Not(IsOk()));
}

TEST(DynamicCastOrError, OtherDerivedMakesError) {
  std::unique_ptr<Base> base = std::make_unique<OtherDerived>();
  absl::StatusOr<std::unique_ptr<Derived>> derived =
      DynamicCast<Derived>(std::move(base));
  EXPECT_THAT(derived.status(), Not(IsOk()));
}

class TestParameters : public Parameters {
 public:
  TestParameters(const TestParameters& other) = default;
  bool HasIdRequirement() const override { return false; }
  bool operator==(const Parameters& other) const override {
    const TestParameters* other_test_parameters =
        dynamic_cast<const TestParameters*>(&other);
    if (other_test_parameters == nullptr) return false;
    return has_id_requirement_ == other_test_parameters->has_id_requirement_;
  }
  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<TestParameters>(*this);
  }
  static TestParameters Create(bool has_id_requirement) {
    return TestParameters(has_id_requirement);
  }

 private:
  explicit TestParameters(bool has_id_requirement)
      : has_id_requirement_(has_id_requirement) {}

  bool has_id_requirement_;
};

class TestKey : public Key {
 public:
  explicit TestKey(const TestParameters& parameters)
      : parameters_(parameters) {}
  const Parameters& GetParameters() const override { return parameters_; }
  absl::optional<int32_t> GetIdRequirement() const override {
    return absl::nullopt;
  }
  bool operator==(const Key& other) const override {
    const TestKey* other_test_key = dynamic_cast<const TestKey*>(&other);
    if (other_test_key == nullptr) return false;
    return parameters_ == other_test_key->parameters_;
  }
  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<TestKey>(parameters_);
  }

 private:
  TestParameters parameters_;
};

TEST(CloneKeyOrDie, WorksAndClones) {
  TestKey key(TestParameters::Create(/*has_id_requirement=*/false));
  std::unique_ptr<TestKey> cloned_key = CloneKeyOrDie(key);
  EXPECT_THAT(cloned_key, Not(IsNull()));
  EXPECT_THAT(*cloned_key, Eq(key));
  TestKey key2(TestParameters::Create(/*has_id_requirement=*/true));
  EXPECT_THAT(*cloned_key, Not(Eq(key2)));
}

TEST(UtilTest, EnsureStringNonNull) {
  // Purposely create a string_view from nullptr.
  auto null_str = absl::string_view(nullptr, 0);
  EXPECT_EQ(EnsureStringNonNull(null_str), absl::string_view(""));
  auto uninit_str = absl::string_view();
  EXPECT_EQ(EnsureStringNonNull(uninit_str), absl::string_view(""));
  auto regular_str = absl::string_view("This is a non-empty non-null str");
  EXPECT_EQ(EnsureStringNonNull(regular_str), regular_str);
}

TEST(BuffersOverlapTest, BufferOverlapEmpty) {
  absl::string_view empty = "";
  EXPECT_FALSE(BuffersOverlap(empty, empty));
  EXPECT_FALSE(BuffersOverlap(empty, ""));
}

TEST(BuffersOverlapTest, BufferOverlapSeparate) {
  absl::string_view first = "first";
  absl::string_view second = "second";
  EXPECT_FALSE(BuffersOverlap(first, second));
  EXPECT_TRUE(BuffersOverlap(first, first));
}

TEST(BuffersOverlapTest, BufferOverlap) {
  absl::string_view long_buffer = kLongString;

  EXPECT_TRUE(BuffersOverlap(long_buffer, long_buffer));

  EXPECT_TRUE(
      BuffersOverlap(long_buffer.substr(0, 10), long_buffer.substr(9, 5)));
  EXPECT_FALSE(
      BuffersOverlap(long_buffer.substr(0, 10), long_buffer.substr(10, 5)));

  EXPECT_TRUE(
      BuffersOverlap(long_buffer.substr(9, 5), long_buffer.substr(0, 10)));
  EXPECT_FALSE(
      BuffersOverlap(long_buffer.substr(10, 5), long_buffer.substr(0, 10)));
}

TEST(BuffersAreIdenticalTest, EmptyString) {
  std::string empty_str = "";
  absl::string_view empty = "";
  EXPECT_FALSE(BuffersAreIdentical(empty, empty));
  EXPECT_FALSE(BuffersAreIdentical(absl::string_view(empty_str),
                                   absl::string_view(empty_str)));
  EXPECT_FALSE(BuffersAreIdentical(empty, ""));
  EXPECT_FALSE(BuffersAreIdentical(empty, absl::string_view(empty_str)));
}

TEST(BuffersAreIdenticalTest, BuffersAreIdentical) {
  auto some_string = std::string(kLongString);
  auto buffer = absl::string_view(some_string);
  EXPECT_TRUE(BuffersAreIdentical(buffer, buffer));
  // Make sure BuffersAreIdentical is not checking for string equality.
  std::string identical_string = some_string;
  EXPECT_FALSE(
      BuffersAreIdentical(buffer, absl::string_view(identical_string)));
}

TEST(BuffersAreIdenticalTest, PartialOverlapFails) {
  auto some_string = std::string(kLongString);
  auto buffer = absl::string_view(some_string);
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(0, 10), buffer.substr(9, 5)));
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(0, 10), buffer.substr(10, 5)));
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(9, 5), buffer.substr(0, 10)));
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(10, 5), buffer.substr(0, 10)));
}

TEST(UtilTest, IsPrintableAscii) {
  const std::string input =
      "!\"#$%&'()*+,-./"
      "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
      "abcdefghijklmnopqrstuvwxyz{|}~";
  EXPECT_THAT(IsPrintableAscii(input), IsTrue());
}

TEST(UtilTest, IsNotPrintableAscii) {
  EXPECT_THAT(IsPrintableAscii("\n"), IsFalse());
  EXPECT_THAT(IsPrintableAscii("\t"), IsFalse());
  EXPECT_THAT(IsPrintableAscii(" "), IsFalse());
  EXPECT_THAT(IsPrintableAscii("\x7f"), IsFalse());
  EXPECT_THAT(IsPrintableAscii("ö"), IsFalse());
}

TEST(UtilTest, ParseBigIntToFixedLengthSuccessesWithZeros) {
  EXPECT_THAT(ParseBigIntToFixedLength("", 0),
              IsOkAndHolds(EqualsSecretData(SecretData())));

  EXPECT_THAT(ParseBigIntToFixedLength("", 1),
              IsOkAndHolds(EqualsSecretData(SecretData(1, 0))));

  EXPECT_THAT(ParseBigIntToFixedLength("", 10),
              IsOkAndHolds(EqualsSecretData(SecretData(10, 0))));

  EXPECT_THAT(ParseBigIntToFixedLength(HexDecodeOrDie("0000"), 0),
              IsOkAndHolds(EqualsSecretData(SecretData())));

  EXPECT_THAT(ParseBigIntToFixedLength(HexDecodeOrDie("0000"), 2),
              IsOkAndHolds(EqualsSecretData(SecretData(2, 0))));

  EXPECT_THAT(ParseBigIntToFixedLength(HexDecodeOrDie("0000"), 10),
              IsOkAndHolds(EqualsSecretData(SecretData(10, 0))));
}

TEST(UtilTest, ParseBigIntToFixedLengthSuccesses) {
  SecretData padded_data =
      SecretDataFromStringView(HexDecodeOrDie("000011223344"));
  absl::string_view padded_data_view =
      util::SecretDataAsStringView(padded_data);
  SecretData non_padded_data =
      SecretDataFromStringView(HexDecodeOrDie("11223344"));
  absl::string_view non_padded_data_view =
      util::SecretDataAsStringView(non_padded_data);

  EXPECT_THAT(ParseBigIntToFixedLength(non_padded_data_view, 4),
              IsOkAndHolds(EqualsSecretData(non_padded_data)));
  EXPECT_THAT(ParseBigIntToFixedLength(padded_data_view, 4),
              IsOkAndHolds(EqualsSecretData(non_padded_data)));

  EXPECT_THAT(ParseBigIntToFixedLength(non_padded_data_view, 6),
              IsOkAndHolds(EqualsSecretData(padded_data)));
  EXPECT_THAT(ParseBigIntToFixedLength(padded_data_view, 6),
              IsOkAndHolds(EqualsSecretData(padded_data)));
}

TEST(UtilTest, ParseBigIntToFixedLengthFailures) {
  std::string padded_data = HexDecodeOrDie("000011223344");
  std::string non_padded_data = HexDecodeOrDie("11223344");

  EXPECT_THAT(ParseBigIntToFixedLength(padded_data, 0), Not(IsOk()));
  EXPECT_THAT(ParseBigIntToFixedLength(padded_data, 3), Not(IsOk()));
  EXPECT_THAT(ParseBigIntToFixedLength(non_padded_data, 0), Not(IsOk()));
  EXPECT_THAT(ParseBigIntToFixedLength(non_padded_data, 3), Not(IsOk()));
}

TEST(UtilTest, StripZeros) {
  EXPECT_EQ(
      WithoutLeadingZeros(absl::string_view(HexDecodeOrDie("000011223344"))),
      HexDecodeOrDie("11223344"));
  EXPECT_EQ(WithoutLeadingZeros(HexDecodeOrDie("11223344")),
            HexDecodeOrDie("11223344"));
  EXPECT_EQ(WithoutLeadingZeros(HexDecodeOrDie("0000")), "");
  EXPECT_EQ(WithoutLeadingZeros(""), "");
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
