// Copyright 2025 Google LLC
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

#include "tink/daead/internal/aes_siv_proto_format.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/internal/testing/field_with_number.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

std::string GetSerializedProtoAesSivKeyFormat() {
  return absl::StrCat(proto_testing::FieldWithNumber(1).IsVarint(64),
                      proto_testing::FieldWithNumber(2).IsVarint(1));
}

TEST(AesSivProtoStructsTest, ParseProtoAesSivKeyFormat) {
  ProtoAesSivKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(GetSerializedProtoAesSivKeyFormat()),
              IsTrue());
  EXPECT_THAT(key_format.key_size(), Eq(64));
  EXPECT_THAT(key_format.version(), Eq(1));
}

TEST(AesSivProtoStructsTest, ParseProtoAesSivKeyFormatInvalid) {
  ProtoAesSivKeyFormat key_format;
  EXPECT_THAT(key_format.ParseFromString("invalid"), IsFalse());
}

TEST(AesSivProtoStructsTest, SerializeProtoAesSivKeyFormat) {
  ProtoAesSivKeyFormat key_format;
  key_format.set_key_size(64);
  key_format.set_version(1);

  EXPECT_THAT(key_format.SerializeAsString(),
              Eq(GetSerializedProtoAesSivKeyFormat()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
