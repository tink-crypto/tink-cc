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

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/crypto_format.h"
#include "tink/experimental/pqcrypto/signature/signature_config.h"
#include "tink/internal/fips_utils.h"
#include "tink/primitive_set.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;
using ::crypto::tink::test::IsOk;

class PcqSignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(PcqSignatureConfigTest, CheckStatus) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used";
  }

  EXPECT_THAT(PqSignatureConfigRegister(), IsOk());
}

// Tests that the PublicKeySignWrapper has been properly registered and we
// can wrap primitives.
TEST_F(PcqSignatureConfigTest, PublicKeySignWrapperRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used";
  }

  ASSERT_THAT(PqSignatureConfigRegister(), IsOk());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);

  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeySign>>();
  auto add_primitive = primitive_set->AddPrimitive(
      absl::make_unique<DummyPublicKeySign>("dummy"), key_info);
  ASSERT_THAT(add_primitive, IsOk());
  ASSERT_THAT(primitive_set->set_primary(*add_primitive), IsOk());

  absl::StatusOr<std::unique_ptr<crypto::tink::PublicKeySign>> wrapped =
      Registry::Wrap(std::move(primitive_set));
  ASSERT_THAT(wrapped, IsOk());

  absl::StatusOr<std::string> signature_result = (*wrapped)->Sign("message");
  ASSERT_THAT(signature_result, IsOk());

  absl::StatusOr<std::string> prefix = CryptoFormat::GetOutputPrefix(key_info);
  ASSERT_THAT(prefix, IsOk());
  absl::StatusOr<std::string> signature =
      DummyPublicKeySign("dummy").Sign("message");
  ASSERT_THAT(signature, IsOk());

  EXPECT_EQ(*signature_result, absl::StrCat(*prefix, *signature));
}

// Tests that the PublicKeyVerifyWrapper has been properly registered and we
// can wrap primitives.
TEST_F(PcqSignatureConfigTest, PublicKeyVerifyWrapperRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used";
  }

  ASSERT_THAT(PqSignatureConfigRegister(), IsOk());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);

  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeyVerify>>();
  auto add_primitive = primitive_set->AddPrimitive(
      absl::make_unique<DummyPublicKeyVerify>("dummy"), key_info);
  ASSERT_THAT(add_primitive, IsOk());
  ASSERT_THAT(primitive_set->set_primary(*add_primitive), IsOk());

  absl::StatusOr<std::unique_ptr<crypto::tink::PublicKeyVerify>> wrapped =
      Registry::Wrap(std::move(primitive_set));
  ASSERT_THAT(wrapped, IsOk());

  absl::StatusOr<std::string> prefix = CryptoFormat::GetOutputPrefix(key_info);
  ASSERT_THAT(prefix, IsOk());
  absl::StatusOr<std::string> signature =
      DummyPublicKeySign("dummy").Sign("message");
  ASSERT_THAT(signature, IsOk());

  ASSERT_THAT((*wrapped)->Verify(absl::StrCat(*prefix, *signature), "message"),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
