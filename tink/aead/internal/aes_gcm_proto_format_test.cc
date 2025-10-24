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

#include "tink/aead/internal/aes_gcm_proto_format.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(ProtoAesGcmKeyFormatTest, Parse) {
  const std::string serialized_format =
      absl::StrCat(proto_testing::FieldWithNumber(2).IsVarint(32),
                   proto_testing::FieldWithNumber(3).IsVarint(1234));
  ProtoAesGcmKeyFormat format;
  ASSERT_THAT(format.ParseFromString(serialized_format), IsTrue());
  EXPECT_THAT(format.key_size(), Eq(32));
  EXPECT_THAT(format.version(), Eq(1234));
}

TEST(ProtoAesGcmKeyFormatTest, ParseInvalid) {
  ProtoAesGcmKeyFormat format;
  EXPECT_THAT(format.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoAesGcmKeyFormatTest, Serialize) {
  ProtoAesGcmKeyFormat format;
  format.set_version(1234);
  format.set_key_size(32);

  auto serialized_format = format.SerializeAsSecretData();
  const std::string expected_serialized_format =
      absl::StrCat(proto_testing::FieldWithNumber(2).IsVarint(32),
                   proto_testing::FieldWithNumber(3).IsVarint(1234));
  EXPECT_THAT(util::SecretDataAsStringView(serialized_format),
              Eq(expected_serialized_format));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
