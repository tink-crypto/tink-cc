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

#include "tink/jwt/internal/jwt_mac_impl.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/mac.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

absl::StatusOr<std::string> JwtMacImpl::ComputeMacAndEncodeWithKid(
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
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "TINK keys are not allowed to have a kid value set.");
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
  absl::StatusOr<std::string> tag = mac_->ComputeMac(unsigned_token);
  if (!tag.ok()) {
    return tag.status();
  }
  std::string encoded_tag = EncodeSignature(*tag);
  return absl::StrCat(unsigned_token, ".", encoded_tag);
}

absl::StatusOr<VerifiedJwt> JwtMacImpl::VerifyMacAndDecodeWithKid(
    absl::string_view compact, const JwtValidator& validator,
    absl::optional<absl::string_view> kid) const {
  if (kid_.has_value() && kid != kid_) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("invalid kid provided; expected: %s, got: %s", *kid_,
                        kid.value_or("nullopt")));
  }
  std::size_t mac_pos = compact.find_last_of('.');
  if (mac_pos == absl::string_view::npos) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid token");
  }
  absl::string_view unsigned_token = compact.substr(0, mac_pos);
  std::string mac_value;
  if (!DecodeSignature(compact.substr(mac_pos + 1), &mac_value)) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid JWT MAC");
  }
  absl::Status verify_result = mac_->VerifyMac(mac_value, unsigned_token);
  if (!verify_result.ok()) {
    // Use a different error code so that we can distinguish it.
    return absl::Status(absl::StatusCode::kUnauthenticated,
                        verify_result.message());
  }
  std::vector<absl::string_view> parts = absl::StrSplit(unsigned_token, '.');
  if (parts.size() != 2) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "only tokens in JWS compact serialization format are supported");
  }
  std::string json_header;
  if (!DecodeHeader(parts[0], &json_header)) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid header");
  }
  absl::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  if (!header.ok()) {
    return header.status();
  }
  absl::Status validate_header_result =
      ValidateHeader(*header, algorithm_, kid, custom_kid_);
  if (!validate_header_result.ok()) {
    return validate_header_result;
  }
  std::string json_payload;
  if (!DecodePayload(parts[1], &json_payload)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "invalid JWT payload");
  }
  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtParser::FromJson(GetTypeHeader(*header), json_payload);
  if (!raw_jwt.ok()) {
    return raw_jwt.status();
  }
  absl::Status validate_result = validator.Validate(*raw_jwt);
  if (!validate_result.ok()) {
    return validate_result;
  }
  return VerifiedJwt(*std::move(raw_jwt));
}

std::unique_ptr<JwtMacImpl> JwtMacImpl::WithKid(std::unique_ptr<Mac> mac,
                                                absl::string_view algorithm,
                                                absl::string_view kid) {
  return absl::WrapUnique(new JwtMacImpl(std::move(mac), algorithm,
                                         /*custom_kid=*/absl::nullopt,
                                         std::string(kid)));
}

std::unique_ptr<JwtMacImpl> JwtMacImpl::RawWithCustomKid(
    std::unique_ptr<Mac> mac, absl::string_view algorithm,
    absl::string_view custom_kid) {
  return absl::WrapUnique(new JwtMacImpl(std::move(mac), algorithm,
                                         std::string(custom_kid),
                                         /*kid=*/absl::nullopt));
}

std::unique_ptr<JwtMacImpl> JwtMacImpl::Raw(std::unique_ptr<Mac> mac,
                                            absl::string_view algorithm) {
  return absl::WrapUnique(new JwtMacImpl(std::move(mac), algorithm,
                                         /*custom_kid=*/absl::nullopt,
                                         /*kid=*/absl::nullopt));
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
