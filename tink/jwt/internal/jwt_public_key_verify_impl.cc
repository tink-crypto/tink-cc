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

#include "tink/jwt/internal/jwt_public_key_verify_impl.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/public_key_verify.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

absl::StatusOr<VerifiedJwt> JwtPublicKeyVerifyImpl::VerifyAndDecodeWithKid(
    absl::string_view compact, const JwtValidator& validator,
    absl::optional<absl::string_view> kid) const {
  if (kid_.has_value() && kid != kid_) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("invalid kid provided; expected: %s, got: %s", *kid_,
                        kid.value_or("nullopt")));
  }

  // TODO(juerg): Refactor this code into a util function.
  std::size_t signature_pos = compact.find_last_of('.');
  if (signature_pos == absl::string_view::npos) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid token");
  }
  absl::string_view unsigned_token = compact.substr(0, signature_pos);
  std::string signature;
  if (!DecodeSignature(compact.substr(signature_pos + 1), &signature)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "invalid JWT signature");
  }
  absl::Status verify_result = verify_->Verify(signature, unsigned_token);
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

std::unique_ptr<JwtPublicKeyVerifyImpl> JwtPublicKeyVerifyImpl::WithKid(
    std::unique_ptr<crypto::tink::PublicKeyVerify> verify,
    absl::string_view algorithm, absl::string_view kid) {
  return absl::WrapUnique(new JwtPublicKeyVerifyImpl(
      std::move(verify), algorithm, /*custom_kid=*/absl::nullopt,
      std::string(kid)));
}

std::unique_ptr<JwtPublicKeyVerifyImpl>
JwtPublicKeyVerifyImpl::RawWithCustomKid(
    std::unique_ptr<crypto::tink::PublicKeyVerify> verify,
    absl::string_view algorithm, absl::string_view custom_kid) {
  return absl::WrapUnique(new JwtPublicKeyVerifyImpl(
      std::move(verify), algorithm, std::string(custom_kid),
      /*kid=*/absl::nullopt));
}

std::unique_ptr<JwtPublicKeyVerifyImpl> JwtPublicKeyVerifyImpl::Raw(
    std::unique_ptr<crypto::tink::PublicKeyVerify> verify,
    absl::string_view algorithm) {
  return absl::WrapUnique(
      new JwtPublicKeyVerifyImpl(std::move(verify), algorithm,
                                 /*custom_kid=*/absl::nullopt,
                                 /*kid=*/absl::nullopt));
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
