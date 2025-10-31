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

#include "tink/jwt/jwt_validator.h"

#include <string>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/jwt/raw_jwt.h"

namespace crypto {
namespace tink {

namespace {

static constexpr absl::Duration kJwtMaxClockSkew = absl::Minutes(10);

}

JwtValidator::JwtValidator(const JwtValidatorBuilder& builder) {
  expected_type_header_ = builder.expected_type_header_;
  expected_issuer_ = builder.expected_issuer_;
  expected_audience_ = builder.expected_audience_;
  ignore_type_header_ = builder.ignore_type_header_;
  ignore_issuer_ = builder.ignore_issuer_;
  ignore_audiences_ = builder.ignore_audiences_;
  allow_missing_expiration_ = builder.allow_missing_expiration_;
  expect_issued_in_the_past_ = builder.expect_issued_in_the_past_;
  clock_skew_ = builder.clock_skew_;
  fixed_now_ = builder.fixed_now_;
}

absl::Status JwtValidator::ValidateTimestamps(RawJwt const& raw_jwt) const {
  absl::Time now;
  if (fixed_now_.has_value()) {
    now = fixed_now_.value();
  } else {
    now = absl::Now();
  }
  if (!raw_jwt.HasExpiration() && !allow_missing_expiration_) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "token does not have an expiration set");
  }
  if (raw_jwt.HasExpiration()) {
    absl::StatusOr<absl::Time> expiration = raw_jwt.GetExpiration();
    if (!expiration.ok()) {
      return expiration.status();
    }
    if (*expiration <= now - clock_skew_) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "token has expired");
    }
  }
  if (raw_jwt.HasNotBefore()) {
    absl::StatusOr<absl::Time> not_before = raw_jwt.GetNotBefore();
    if (!not_before.ok()) {
      return not_before.status();
    }
    if (*not_before > now + clock_skew_) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "token cannot yet be used");
    }
  }
  if (expect_issued_in_the_past_) {
    absl::StatusOr<absl::Time> issued_at = raw_jwt.GetIssuedAt();
    if (!issued_at.ok()) {
      return issued_at.status();
    }
    if (*issued_at > now + clock_skew_) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "token has an invalid iat claim in the future");
    }
  }
  return absl::OkStatus();
}

absl::Status JwtValidator::ValidateTypeHeader(RawJwt const& raw_jwt) const {
  if (expected_type_header_.has_value()) {
    if (!raw_jwt.HasTypeHeader()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "missing expected type header");
    }
    absl::StatusOr<std::string> type_header = raw_jwt.GetTypeHeader();
    if (!type_header.ok()) {
      return type_header.status();
    }
    if (expected_type_header_.value() != *type_header) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "wrong type header");
    }
  } else {
    if (raw_jwt.HasTypeHeader() && !ignore_type_header_) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "invalid JWT; token has type header set, but validator not");
    }
  }
  return absl::OkStatus();
}

absl::Status JwtValidator::ValidateIssuer(RawJwt const& raw_jwt) const {
  if (expected_issuer_.has_value()){
    if (!raw_jwt.HasIssuer()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "missing expected issuer");
    }
    absl::StatusOr<std::string> issuer = raw_jwt.GetIssuer();
    if (!issuer.ok()) {
      return issuer.status();
    }
    if (expected_issuer_.value() != *issuer) {
      return absl::Status(absl::StatusCode::kInvalidArgument, "wrong issuer");
    }
  } else {
    if (raw_jwt.HasIssuer() && !ignore_issuer_) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "invalid JWT; token has issuer set, but validator not");
    }
  }
  return absl::OkStatus();
}

absl::Status JwtValidator::ValidateAudiences(RawJwt const& raw_jwt) const {
  if (expected_audience_.has_value()) {
    if (!raw_jwt.HasAudiences()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "missing expected audiences");
    }
    absl::StatusOr<std::vector<std::string>> audiences = raw_jwt.GetAudiences();
    if (!audiences.ok()) {
      return audiences.status();
    }
    auto it = absl::c_find(*audiences, expected_audience_);
    if (it == audiences->end()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "audience not found");
    }
  } else {
    if (raw_jwt.HasAudiences() && !ignore_audiences_) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "invalid JWT; token has audience set, but validator not");
    }
  }
  return absl::OkStatus();
}

absl::Status JwtValidator::Validate(RawJwt const& raw_jwt) const {
  absl::Status status;
  status = ValidateTimestamps(raw_jwt);
  if (!status.ok()) {
    return status;
  }
  status = ValidateTypeHeader(raw_jwt);
  if (!status.ok()) {
    return status;
  }
  status = ValidateIssuer(raw_jwt);
  if (!status.ok()) {
    return status;
  }
  status = ValidateAudiences(raw_jwt);
  if (!status.ok()) {
    return status;
  }
  return absl::OkStatus();
}

JwtValidatorBuilder::JwtValidatorBuilder() {
  ignore_type_header_ = false;
  ignore_issuer_ = false;
  ignore_audiences_ = false;
  allow_missing_expiration_ = false;
  expect_issued_in_the_past_ = false;
  clock_skew_ = absl::ZeroDuration();
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectTypeHeader(
    absl::string_view type_header) {
  expected_type_header_ = std::string(type_header);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectIssuer(
    absl::string_view issuer) {
  expected_issuer_ = std::string(issuer);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectAudience(
    absl::string_view audience) {
  expected_audience_ = std::string(audience);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::IgnoreTypeHeader() {
  ignore_type_header_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::IgnoreIssuer() {
  ignore_issuer_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::IgnoreAudiences() {
  ignore_audiences_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::AllowMissingExpiration() {
  allow_missing_expiration_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectIssuedInThePast() {
  expect_issued_in_the_past_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::SetClockSkew(
    absl::Duration clock_skew) {
  clock_skew_ = clock_skew;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::SetFixedNow(absl::Time fixed_now) {
  fixed_now_ = fixed_now;
  return *this;
}

absl::StatusOr<JwtValidator> JwtValidatorBuilder::Build() {
  if (expected_type_header_.has_value() && ignore_type_header_) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "IgnoreTypeHeader() and ExpectTypeHeader() cannot be used together");
  }
  if (expected_issuer_.has_value() && ignore_issuer_) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "IgnoreIssuer() and ExpectedIssuer() cannot be used together");
  }
  if (expected_audience_.has_value() && ignore_audiences_) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "IgnoreAudiences() and ExpectAudience() cannot be used together");
  }
  if (clock_skew_ > kJwtMaxClockSkew) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "clock skew too large, max is 10 minutes");
  }
  JwtValidator validator(*this);
  return validator;
}

}  // namespace tink
}  // namespace crypto

