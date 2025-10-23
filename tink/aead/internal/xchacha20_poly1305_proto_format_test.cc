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
#include "tink/aead/internal/xchacha20_poly1305_proto_format.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(ProtoXChaCha20Poly1305KeyFormatTest, Parse) {
  const std::string serialized_hmac_format =
      proto_testing::FieldWithNumber(1).IsVarint(1234);
  ProtoXChaCha20Poly1305KeyFormat format;
  ASSERT_THAT(format.ParseFromString(serialized_hmac_format), IsTrue());
  EXPECT_THAT(format.version(), Eq(1234));
}

TEST(ProtoXChaCha20Poly1305KeyFormatTest, ParseInvalid) {
  ProtoXChaCha20Poly1305KeyFormat format;
  EXPECT_THAT(format.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoXChaCha20Poly1305KeyFormatTest, Serialize) {
  ProtoXChaCha20Poly1305KeyFormat format;
  format.set_version(1234);

  auto serialized_hmac_format = format.SerializeAsSecretData();
  const std::string expected_serialized_hmac_format =
      proto_testing::FieldWithNumber(1).IsVarint(1234);
  EXPECT_THAT(util::SecretDataAsStringView(serialized_hmac_format),
              Eq(expected_serialized_hmac_format));
}
}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
