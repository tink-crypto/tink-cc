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

#include "tink/jwt/internal/jwt_public_key_sign_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/public_key_sign.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

absl::StatusOr<std::string> JwtPublicKeySignImpl::SignAndEncodeWithKid(
    const RawJwt& token, absl::optional<absl::string_view> kid) const {
  absl::optional<std::string> type_header;
  if (token.HasTypeHeader()) {
    absl::StatusOr<std::string> type = token.GetTypeHeader();
    if (!type.ok()) {
      return type.status();
    }
    type_header = *type;
  }

  if (kid_.has_value() && kid != kid_) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("invalid kid provided; expected: %s, got: %s", *kid_,
                        kid.value_or("nullopt")));
  }

  if (custom_kid_.has_value()) {
    if (kid.has_value()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "TINK keys are not allowed to have a custom kid value");
    }
    kid = *custom_kid_;
  }
  absl::StatusOr<std::string> encoded_header =
      CreateHeader(algorithm_, type_header, kid);
  if (!encoded_header.ok()) {
    return encoded_header.status();
  }
  absl::StatusOr<std::string> payload = token.GetJsonPayload();
  if (!payload.ok()) {
    return payload.status();
  }
  std::string encoded_payload = EncodePayload(*payload);
  std::string unsigned_token =
      absl::StrCat(*encoded_header, ".", encoded_payload);
  absl::StatusOr<std::string> tag = sign_->Sign(unsigned_token);
  if (!tag.ok()) {
    return tag.status();
  }
  std::string encoded_tag = EncodeSignature(*tag);
  return absl::StrCat(unsigned_token, ".", encoded_tag);
}

std::unique_ptr<JwtPublicKeySignImpl> JwtPublicKeySignImpl::WithKid(
    std::unique_ptr<crypto::tink::PublicKeySign> sign,
    absl::string_view algorithm, absl::string_view kid) {
  return absl::WrapUnique(new JwtPublicKeySignImpl(
      std::move(sign), algorithm, absl::nullopt, std::string(kid)));
}

std::unique_ptr<JwtPublicKeySignImpl> JwtPublicKeySignImpl::RawWithCustomKid(
    std::unique_ptr<crypto::tink::PublicKeySign> sign,
    absl::string_view algorithm, absl::string_view custom_kid) {
  return absl::WrapUnique(new JwtPublicKeySignImpl(std::move(sign), algorithm,
                                                   std::string(custom_kid),
                                                   /*kid=*/absl::nullopt));
}

std::unique_ptr<JwtPublicKeySignImpl> JwtPublicKeySignImpl::Raw(
    std::unique_ptr<crypto::tink::PublicKeySign> sign,
    absl::string_view algorithm) {
  return absl::WrapUnique(new JwtPublicKeySignImpl(std::move(sign), algorithm,
                                                   /*custom_kid=*/absl::nullopt,
                                                   /*kid=*/absl::nullopt));
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
