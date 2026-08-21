// Copyright 2017 Google Inc.
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

#ifndef TINK_SUBTLE_AES_SIV_BORINGSSL_H_
#define TINK_SUBTLE_AES_SIV_BORINGSSL_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "tink/deterministic_aead.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

// AesSivBoringSsl is an implemenatation of AES-SIV-CMAC as defined in
// https://tools.ietf.org/html/rfc5297 .
// AesSivBoringSsl implements a deterministic encryption with associated
// data (i.e. the DeterministicAead interface). Hence the implementation
// below is restricted to one AD component.
//
// Thread safety: This class is thread safe and thus can be used
// concurrently.
//
// Security:
// =========
// Chatterjee, Menezes and Sarkar analyze AES-SIV in Section 5.1 of
// https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf
// Their analysis shows that AES-SIV is susceptible to an attack in
// a multi-user setting. Concretely, if an attacker knows the encryption
// of a message m encrypted and authenticated with k different keys,
// then it is possible  to find one of the MAC keys in time 2^b / k
// where b is the size of the MAC key. A consequence of this attack
// is that 128-bit MAC keys give unsufficient security.
// Since 192-bit AES keys are not supported by tink for voodoo reasons
// and RFC 5297 only supports same size encryption and MAC keys this
// implies that keys must be 64 bytes (2*256 bits) long.
class AesSivBoringSsl {
 public:
  static absl::StatusOr<std::unique_ptr<DeterministicAead>> New(
      const SecretData& key);

  static bool IsValidKeySizeInBytes(size_t size) { return size == 64; }

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  AesSivBoringSsl() = delete;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_SIV_BORINGSSL_H_
