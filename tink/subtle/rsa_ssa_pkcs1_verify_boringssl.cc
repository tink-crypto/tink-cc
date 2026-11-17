// Copyright 2018 Google LLC
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

#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/rsa_util.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

class RsaSsaPkcs1VerifyBoringSslImpl final : public RsaSsaPkcs1VerifyBoringSsl {
 public:
  explicit RsaSsaPkcs1VerifyBoringSslImpl(
      std::unique_ptr<PublicKeyVerify> verify)
      : verify_(std::move(verify)) {}

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override {
    return verify_->Verify(signature, data);
  }

 private:
  std::unique_ptr<PublicKeyVerify> verify_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPkcs1VerifyBoringSsl::New(const RsaSsaPkcs1PublicKey& key) {
  return internal::NewRsaSsaPkcs1VerifyBoringSsl(key);
}

absl::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>>
RsaSsaPkcs1VerifyBoringSsl::New(const internal::RsaPublicKey& pub_key,
                                const internal::RsaSsaPkcs1Params& params) {
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<PublicKeyVerify> verify,
      internal::NewRsaSsaPkcs1VerifyBoringSsl(pub_key, params));
  return std::make_unique<RsaSsaPkcs1VerifyBoringSslImpl>(std::move(verify));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
