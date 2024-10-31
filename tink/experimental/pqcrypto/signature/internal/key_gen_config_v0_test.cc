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
////////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/internal/key_gen_config_v0.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;

TEST(PqcSignatureKeyGenConfigV0Test, PqcSignaturesCreateKeysetHandlesWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());

  util::StatusOr<SlhDsaParameters> slhdsa_parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(slhdsa_parameters, IsOk());

  util::StatusOr<MlDsaParameters> mldsa_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(mldsa_parameters, IsOk());

  KeysetHandleBuilder builder;
  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(*slhdsa_parameters,
                                                           KeyStatus::kEnabled,
                                                           /*is_primary=*/true);
  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *mldsa_parameters, KeyStatus::kEnabled,
          /*is_primary=*/false);

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
