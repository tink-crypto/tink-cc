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

#include "tink/internal/proto_parser_string_like_helpers.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {
namespace {

using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Test;

TEST(StringLikeHelpersTest, ClearStringLikeValue_String) {
  std::string s = "hi";
  ClearStringLikeValue(s);
  EXPECT_THAT(s, IsEmpty());
}

TEST(StringLikeHelpersTest, ClearStringLikeValue_StringView) {
  absl::string_view b = absl::string_view("hi");
  ClearStringLikeValue(b);
  EXPECT_THAT(b, Eq(""));
}

TEST(StringLikeHelpersTest, CopyIntoStringLikeValue_String) {
  std::string s = "hi";
  std::string t;
  CopyIntoStringLikeValue(s, t);
  EXPECT_THAT(t, Eq(s));
}

TEST(StringLikeHelpersTest, CopyIntoStringLikeValue_StringView) {
  std::string s = "hi";
  absl::string_view dest;
  CopyIntoStringLikeValue(s, dest);
  EXPECT_THAT(dest, Eq(s));
}

TEST(StringLikeHelpersTest, SizeOfStringLikeValue_String) {
  std::string s = "1234567";
  EXPECT_THAT(SizeOfStringLikeValue(s), Eq(7));
}

TEST(StringLikeHelpersTest, SizeOfStringLikeValue_StringView) {
  auto b = absl::string_view("1234567");
  EXPECT_THAT(SizeOfStringLikeValue(b), Eq(7));
}

TEST(StringLikeHelpersTest, SerializeStringLikeValue_String) {
  std::string s = "1234567";
  std::string t;
  t.resize(100);
  SerializeStringLikeValue(s, absl::MakeSpan(t));
  EXPECT_THAT(t.substr(0, 7), Eq("1234567"));
}

TEST(StringLikeHelpersTest, SerializeStringLikeValue_StringView) {
  auto b = absl::string_view("1234567");
  std::string t;
  t.resize(100);
  SerializeStringLikeValue(b, absl::MakeSpan(t));
  EXPECT_THAT(t.substr(0, b.size()), Eq("1234567"));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
