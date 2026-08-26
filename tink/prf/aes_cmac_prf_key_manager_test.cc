// Copyright 2020 Google LLC
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
#include "tink/prf/aes_cmac_prf_key_manager.h"

#include <memory>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/input_stream.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/prf/config_2026.h"
#include "tink/prf/internal/aes_cmac_prf_test_vectors.h"
#include "tink/prf/prf_config.h"
#include "tink/prf/prf_set.h"
#include "tink/subtle/aes_cmac_boringssl.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::absl_testing::IsOk;
using AesCmacPrfKeyProto = ::google::crypto::tink::AesCmacPrfKey;
using ::google::crypto::tink::AesCmacPrfKeyFormat;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StrEq;

std::unique_ptr<InputStream> GetInputStreamForString(const std::string& input) {
  return std::make_unique<util::IstreamInputStream>(
      std::make_unique<std::stringstream>(input));
}

AesCmacPrfKeyFormat ValidKeyFormat() {
  AesCmacPrfKeyFormat format;
  format.set_key_size(32);
  return format;
}

TEST(AesCmacPrfKeyManagerTest, Basics) {
  EXPECT_THAT(AesCmacPrfKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesCmacPrfKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacPrfKey"));
  EXPECT_THAT(AesCmacPrfKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesCmacPrfKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(AesCmacPrfKeyProto()),
              Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(AesCmacPrfKeyFormat()),
              Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateSimpleKeyFormat) {
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(ValidKeyFormat()),
              IsOk());
}

TEST(AesCmacPrfKeyManagerTest, ValidateKeyFormatKeySizes) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();

  format.set_key_size(0);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(1);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(15);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(16);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(17);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(31);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(32);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), IsOk());

  format.set_key_size(33);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, CreateKey) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  ASSERT_THAT(AesCmacPrfKeyManager().CreateKey(format), IsOk());
  AesCmacPrfKeyProto key = AesCmacPrfKeyManager().CreateKey(format).value();
  EXPECT_THAT(key.version(), Eq(0));
  EXPECT_THAT(key.key_value(), SizeIs(format.key_size()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateKey) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKeyProto key = AesCmacPrfKeyManager().CreateKey(format).value();
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(key), IsOk());
}

TEST(AesCmacPrfKeyManagerTest, ValidateKeyInvalidVersion) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKeyProto key = AesCmacPrfKeyManager().CreateKey(format).value();
  key.set_version(1);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateKeyShortKey) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKeyProto key = AesCmacPrfKeyManager().CreateKey(format).value();
  key.set_key_value("0123456789abcdef");
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, GetPrimitive) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKeyProto key = AesCmacPrfKeyManager().CreateKey(format).value();
  auto manager_prf_or = AesCmacPrfKeyManager().GetPrimitive<Prf>(key);
  ASSERT_THAT(manager_prf_or, IsOk());
  auto prf_value_or = manager_prf_or.value()->Compute("some plaintext", 16);
  ASSERT_THAT(prf_value_or, IsOk());

  auto direct_prf_or = subtle::AesCmacBoringSsl::New(
      util::SecretDataFromStringView(key.key_value()), 16);
  ASSERT_THAT(direct_prf_or, IsOk());
  auto direct_prf_value_or =
      direct_prf_or.value()->ComputeMac("some plaintext");
  ASSERT_THAT(direct_prf_value_or, IsOk());
  EXPECT_THAT(direct_prf_value_or.value(), StrEq(prf_value_or.value()));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyValid) {
  std::string bytes = "0123456789abcdef0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto key_or =
      AesCmacPrfKeyManager().DeriveKey(ValidKeyFormat(), inputstream.get());
  ASSERT_THAT(key_or, IsOk());
  AesCmacPrfKeyProto key = key_or.value();
  EXPECT_THAT(key.version(), Eq(AesCmacPrfKeyManager().get_version()));
  EXPECT_THAT(key.key_value(), Eq(bytes));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  std::string bytes = "0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto key_or =
      AesCmacPrfKeyManager().DeriveKey(ValidKeyFormat(), inputstream.get());
  EXPECT_THAT(key_or, Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyInvalidFormat) {
  std::string bytes = "0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto format = ValidKeyFormat();
  format.set_key_size(12);
  auto key_or = AesCmacPrfKeyManager().DeriveKey(format, inputstream.get());
  EXPECT_THAT(key_or, Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyInvalidVersion) {
  auto format = ValidKeyFormat();
  format.set_version(1);
  std::string bytes = "0123456789abcdef0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto key_or =
      AesCmacPrfKeyManager().DeriveKey(format, inputstream.get());
  EXPECT_THAT(key_or, Not(IsOk()));
}

using AesCmacPrfKeyManagerTestVectorTest =
    testing::TestWithParam<internal::AesCmacPrfTestVector>;

TEST_P(AesCmacPrfKeyManagerTestVectorTest, ComputePrfSet) {
  const internal::AesCmacPrfTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 32) {
    GTEST_SKIP() << "KeyManager only supports 32-byte keys";
  }
  ASSERT_THAT(PrfConfig::Register(), IsOk());
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              test_vector.key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<PrfSet>> prf_set =
      handle->GetPrimitive<PrfSet>(ConfigPrf2026());
  ASSERT_THAT(prf_set, IsOk());

  absl::StatusOr<std::string> output = (*prf_set)->ComputePrimary(
      test_vector.message, test_vector.output.size());
  ASSERT_THAT(output, IsOk());
  EXPECT_THAT(*output, Eq(test_vector.output));
}

INSTANTIATE_TEST_SUITE_P(
    AesCmacPrfKeyManagerTestVectorTestSuite, AesCmacPrfKeyManagerTestVectorTest,
    testing::ValuesIn(internal::CreateAesCmacPrfTestVectors()));

}  // namespace
}  // namespace tink
}  // namespace crypto
