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

#ifndef TINK_SIGNATURE_INTERNAL_SLH_DSA_SIGN_BORINGSSL_H_
#define TINK_SIGNATURE_INTERNAL_SLH_DSA_SIGN_BORINGSSL_H_

#include <memory>

#include "tink/public_key_sign.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new PublicKeySign primitive using the SLH-DSA implementation from
// BoringSSL. Only SLH-DSA-SHA2-128s is currently supported.
crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>>
NewSlhDsaSignBoringSsl(const SlhDsaPrivateKey& private_key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_SLH_DSA_SIGN_BORINGSSL_H_