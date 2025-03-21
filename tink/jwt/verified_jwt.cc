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

#include "tink/jwt/verified_jwt.h"

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "tink/jwt/raw_jwt.h"

namespace crypto {
namespace tink {

VerifiedJwt::VerifiedJwt() = default;

VerifiedJwt::VerifiedJwt(const RawJwt& raw_jwt) {
  raw_jwt_ = raw_jwt;
}

bool VerifiedJwt::HasTypeHeader() const { return raw_jwt_.HasTypeHeader(); }

absl::StatusOr<std::string> VerifiedJwt::GetTypeHeader() const {
  return raw_jwt_.GetTypeHeader();
}

bool VerifiedJwt::HasIssuer() const {
  return raw_jwt_.HasIssuer();
}

absl::StatusOr<std::string> VerifiedJwt::GetIssuer() const {
  return raw_jwt_.GetIssuer();
}

bool VerifiedJwt::HasSubject() const {
  return raw_jwt_.HasSubject();
}

absl::StatusOr<std::string> VerifiedJwt::GetSubject() const {
  return raw_jwt_.GetSubject();
}

bool VerifiedJwt::HasAudiences() const {
  return raw_jwt_.HasAudiences();
}

absl::StatusOr<std::vector<std::string>> VerifiedJwt::GetAudiences() const {
  return raw_jwt_.GetAudiences();
}

bool VerifiedJwt::HasJwtId() const {
  return raw_jwt_.HasJwtId();
}

absl::StatusOr<std::string> VerifiedJwt::GetJwtId() const {
  return raw_jwt_.GetJwtId();
}

bool VerifiedJwt::HasExpiration() const {
  return raw_jwt_.HasExpiration();
}

absl::StatusOr<absl::Time> VerifiedJwt::GetExpiration() const {
  return raw_jwt_.GetExpiration();
}

bool VerifiedJwt::HasNotBefore() const {
  return raw_jwt_.HasNotBefore();
}

absl::StatusOr<absl::Time> VerifiedJwt::GetNotBefore() const {
  return raw_jwt_.GetNotBefore();
}

bool VerifiedJwt::HasIssuedAt() const {
  return raw_jwt_.HasIssuedAt();
}

absl::StatusOr<absl::Time> VerifiedJwt::GetIssuedAt() const {
  return raw_jwt_.GetIssuedAt();
}

bool VerifiedJwt::IsNullClaim(absl::string_view name) const {
  return raw_jwt_.IsNullClaim(name);
}

bool VerifiedJwt::HasBooleanClaim(absl::string_view name) const {
  return raw_jwt_.HasBooleanClaim(name);
}

absl::StatusOr<bool> VerifiedJwt::GetBooleanClaim(
    absl::string_view name) const {
  return raw_jwt_.GetBooleanClaim(name);
}

bool VerifiedJwt::HasStringClaim(absl::string_view name) const {
  return raw_jwt_.HasStringClaim(name);
}

absl::StatusOr<std::string> VerifiedJwt::GetStringClaim(
    absl::string_view name) const {
  return raw_jwt_.GetStringClaim(name);
}

bool VerifiedJwt::HasNumberClaim(absl::string_view name) const {
  return raw_jwt_.HasNumberClaim(name);
}

absl::StatusOr<double> VerifiedJwt::GetNumberClaim(
    absl::string_view name) const {
  return raw_jwt_.GetNumberClaim(name);
}

bool VerifiedJwt::HasJsonObjectClaim(absl::string_view name) const {
  return raw_jwt_.HasJsonObjectClaim(name);
}

absl::StatusOr<std::string> VerifiedJwt::GetJsonObjectClaim(
    absl::string_view name) const {
  return raw_jwt_.GetJsonObjectClaim(name);
}

bool VerifiedJwt::HasJsonArrayClaim(absl::string_view name) const {
  return raw_jwt_.HasJsonArrayClaim(name);
}

absl::StatusOr<std::string> VerifiedJwt::GetJsonArrayClaim(
    absl::string_view name) const {
  return raw_jwt_.GetJsonArrayClaim(name);
}

std::vector<std::string> VerifiedJwt::CustomClaimNames() const {
  return raw_jwt_.CustomClaimNames();
}

absl::StatusOr<std::string> VerifiedJwt::GetJsonPayload() {
  return raw_jwt_.GetJsonPayload();
}

}  // namespace tink
}  // namespace crypto
