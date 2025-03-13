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

#ifndef TINK_JWT_INTERNAL_JWT_PUBLIC_KEY_VERIFY_IMPL_H_
#define TINK_JWT_INTERNAL_JWT_PUBLIC_KEY_VERIFY_IMPL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/internal/jwt_public_key_verify_internal.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/public_key_verify.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class JwtPublicKeyVerifyImpl : public JwtPublicKeyVerifyInternal {
 public:
  // Creates a JwtPublicKeyVerifyImpl with a fixed Kid.
  // This means that SignAndEncodeWithKid needs to be called with the
  // given kid; otherwise it will fail. This is useful because in the
  // migration to full primitives we have a phase where the kid will
  // be passed in at two places (here and in SignAndEncodeWithKid).
  static std::unique_ptr<JwtPublicKeyVerifyImpl> WithKid(
      std::unique_ptr<crypto::tink::PublicKeyVerify> verify,
      absl::string_view algorithm, absl::string_view kid);

  // Creates a JwtPublicKeyVerifyImpl for a RAW key with a custom kid.
  // If this is used, SignAndEncodeWithKid must have an absent kid.
  static std::unique_ptr<JwtPublicKeyVerifyImpl> RawWithCustomKid(
      std::unique_ptr<crypto::tink::PublicKeyVerify> verify,
      absl::string_view algorithm, absl::string_view custom_kid);

  // Creates a JwtPublicKeyVerifyImpl for a RAW key without custom kid.
  // If this is used, SignAndEncodeWithKid may be called with an absent
  // or a present kid. This is because for non-full primitives, we
  // always use a RAW output prefix and hence we cannot distinguish between
  // Tink style kids and absent kids.
  static std::unique_ptr<JwtPublicKeyVerifyImpl> Raw(
      std::unique_ptr<crypto::tink::PublicKeyVerify> verify,
      absl::string_view algorithm);

  absl::StatusOr<VerifiedJwt> VerifyAndDecodeWithKid(
      absl::string_view compact, const JwtValidator& validator,
      absl::optional<absl::string_view> kid) const override;

 private:
  explicit JwtPublicKeyVerifyImpl(
      std::unique_ptr<crypto::tink::PublicKeyVerify> verify,
      absl::string_view algorithm, absl::optional<std::string> custom_kid,
      absl::optional<std::string> kid)
      : verify_(std::move(verify)),
        algorithm_(algorithm),
        custom_kid_(custom_kid),
        kid_(kid) {}

  std::unique_ptr<crypto::tink::PublicKeyVerify> verify_;
  std::string algorithm_;
  // custom_kid may be set when a key is converted from another format, for
  // example JWK. It does not have any relation to the key id. It can only be
  // set for keys with output prefix RAW.
  absl::optional<std::string> custom_kid_;
  // kid is for TINK keys. It is the key id. If this is set, custom_kid_ is
  // not set.
  absl::optional<std::string> kid_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_PUBLIC_KEY_VERIFY_IMPL_H_
