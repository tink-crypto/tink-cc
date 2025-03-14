// Copyright 2018 Google Inc.
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

#include "tink/signature/sig_util.h"

#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

absl::Status SignAndVerify(const PublicKeySign* signer,
                           const PublicKeyVerify* verifier) {
  static constexpr char kTestMessage[] = "Wycheproof and Tink.";
  auto sign_result = signer->Sign(kTestMessage);
  if (!sign_result.ok()) return sign_result.status();
  return verifier->Verify(sign_result.value(), kTestMessage);
}

}  // namespace tink
}  // namespace crypto
