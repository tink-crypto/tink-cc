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

#ifndef TINK_JWT_JWT_MAC_H_
#define TINK_JWT_JWT_MAC_H_

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Interface for authenticating and verifying JWT with JWS MAC.
//
// Sees RFC 7519 and RFC 7515. Security guarantees: similar to MAC.
class JwtMac {
 public:
  // Computes a MAC and encodes the raw JWT token and the MAC in the JWS compact
  // serialization format.
  virtual absl::StatusOr<std::string> ComputeMacAndEncode(
      const RawJwt& token) const = 0;

  // Verifies and decodes a JWT token in the JWS compact serialization format.
  //
  // The JWT is validated against the rules in validator. That is, every claim
  // in validator must also be present in the JWT. For example, if validator
  // contains an issuer (iss) claim, the JWT must contain an identical claim.
  // The JWT can contain claims that are NOT in the validator. However, if the
  // JWT contains a list of audiences, the validator must also contain an
  // audience in the list.
  //
  // If the JWT contains timestamp claims such as expiration (exp), issued_at
  // (iat) or not_before (nbf), they will also be validated. validator allows to
  // set a clock skew, to deal with small clock differences among different
  // machines.
  virtual absl::StatusOr<VerifiedJwt> VerifyMacAndDecode(
      absl::string_view compact, const JwtValidator& validator) const = 0;

  virtual ~JwtMac() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_MAC_H_
