// Copyright 2024 Google LLC
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

#include "tink/internal/proto_parser_fields.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

constexpr int32_t kUint32Field1Number = 1;
constexpr int32_t kUint32Field2Number = 2;

struct ParsedStruct {
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
  uint64_t uint64_member_1;
  uint64_t uint64_member_2;
  std::string string_member_1;
  std::string string_member_2;
  SecretData secret_data_member_1;
  SecretData secret_data_member_2;
};

// String helpers ===========================================================

TEST(ClearStringLikeValue, String) {
  std::string s = "hi";
  ClearStringLikeValue(s);
  EXPECT_THAT(s, IsEmpty());
}

TEST(ClearStringLikeValue, SecretData) {
  SecretData s = SecretDataFromStringView("hi");
  ClearStringLikeValue(s);
  EXPECT_THAT(s, IsEmpty());
}

TEST(ClearStringLikeValue, StringView) {
  absl::string_view b = absl::string_view("hi");
  ClearStringLikeValue(b);
  EXPECT_THAT(b, Eq(""));
}

TEST(CopyIntoStringLikeValue, String) {
  std::string s = "hi";
  std::string t;
  CopyIntoStringLikeValue(s, t);
  EXPECT_THAT(t, Eq(s));
}

TEST(CopyIntoStringLikeValue, SecretData) {
  std::string s = "hi";
  SecretData t;
  CopyIntoStringLikeValue(s, t);
  EXPECT_THAT(SecretDataAsStringView(t), Eq(s));
}

TEST(CopyIntoStringLikeValue, BigInteger) {
  std::string s = "hi";
  absl::string_view dest;
  CopyIntoStringLikeValue(s, dest);
  EXPECT_THAT(dest, Eq(s));
}

TEST(SizeOfStringLikeValue, String) {
  std::string s = "1234567";
  EXPECT_THAT(SizeOfStringLikeValue(s), Eq(7));
}

TEST(SizeOfStringLikeValue, SecretData) {
  SecretData s = SecretDataFromStringView("1234567");
  EXPECT_THAT(SizeOfStringLikeValue(s), Eq(7));
}

TEST(SizeOfStringLikeValue, BigInteger) {
  absl::string_view b = absl::string_view("1234567");
  EXPECT_THAT(SizeOfStringLikeValue(b), Eq(7));
}

TEST(SerializeStringLikeValue, String) {
  std::string s = "1234567";
  std::string t;
  t.resize(100);
  SerializeStringLikeValue(s, absl::MakeSpan(t));
  EXPECT_THAT(t.substr(0, 7), Eq("1234567"));
}

TEST(SerializeStringLikeValue, SecretData) {
  std::string s = "1234567";
  SecretBuffer t;
  t.resize(100);
  SerializeStringLikeValue(
      s, absl::MakeSpan(reinterpret_cast<char*>(t.data()), t.size()));
  EXPECT_THAT(t.AsStringView().substr(0, 7), Eq("1234567"));
}

TEST(SerializeStringLikeValue, BigInteger) {
  absl::string_view s = "1234567";
  std::string t;
  t.resize(100);
  SerializeStringLikeValue(s, absl::MakeSpan(t));
  EXPECT_THAT(t.substr(0, 7), Eq("1234567"));
}


// Uint64Field ==============================================================

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
