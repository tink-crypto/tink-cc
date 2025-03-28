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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_VERIFY_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_VERIFY_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class FalconVerify : public PublicKeyVerify {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      const FalconPublicKeyPqclean& public_key);

  // Verifies that 'signature' is a digital signature for 'data'.
  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

 private:
  explicit FalconVerify(const FalconPublicKeyPqclean& public_key)
      : public_key_(public_key) {}

  const FalconPublicKeyPqclean public_key_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_FALCON_VERIFY_H_
