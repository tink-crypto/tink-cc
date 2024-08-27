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

#include "tink/experimental/pqcrypto/signature/internal/ml_dsa_verify_boringssl.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/mldsa.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_public_key.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

class MlDsaVerifyBoringSsl : public PublicKeyVerify {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static util::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      MlDsaPublicKey public_key);

  util::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

  explicit MlDsaVerifyBoringSsl(
      MlDsaPublicKey public_key,
      std::unique_ptr<MLDSA65_public_key> boringssl_public_key)
      : public_key_(std::move(public_key)),
        boringssl_public_key_(std::move(boringssl_public_key)) {}

  MlDsaPublicKey public_key_;
  std::unique_ptr<MLDSA65_public_key> boringssl_public_key_;
};

util::StatusOr<std::unique_ptr<PublicKeyVerify>> MlDsaVerifyBoringSsl::New(
    MlDsaPublicKey public_key) {
  auto status = CheckFipsCompatibility<MlDsaVerifyBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (public_key.GetParameters().GetInstance() !=
      MlDsaParameters::Instance::kMlDsa65) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-DSA-65 is supported");
  }

  absl::string_view public_key_bytes =
      public_key.GetPublicKeyBytes(GetPartialKeyAccess());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t *>(public_key_bytes.data()),
           public_key_bytes.size());
  auto boringssl_public_key = std::make_unique<MLDSA65_public_key>();
  if (!MLDSA65_parse_public_key(boringssl_public_key.get(), &cbs)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Invalid ML-DSA public key");
  }

  return absl::make_unique<MlDsaVerifyBoringSsl>(
      std::move(public_key), std::move(boringssl_public_key));
}

util::Status MlDsaVerifyBoringSsl::Verify(absl::string_view signature,
                                          absl::string_view data) const {
  size_t output_prefix_size = public_key_.GetOutputPrefix().size();

  if (signature.size() != MLDSA65_SIGNATURE_BYTES + output_prefix_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Verification failed: incorrect signature length for ML-DSA");
  }

  if (!absl::StartsWith(signature, public_key_.GetOutputPrefix())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Verification failed: invalid output prefix");
  }

  if (1 != MLDSA65_verify(boringssl_public_key_.get(),
                          reinterpret_cast<const uint8_t *>(signature.data() +
                                                            output_prefix_size),
                          MLDSA65_SIGNATURE_BYTES,
                          reinterpret_cast<const uint8_t *>(data.data()),
                          data.size(), /* context = */ nullptr,
                          /* context_len = */ 0)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Signature is not valid");
  }

  return util::OkStatus();
}

}  // namespace

util::StatusOr<std::unique_ptr<PublicKeyVerify>> NewMlDsaVerifyBoringSsl(
    MlDsaPublicKey public_key) {
  return MlDsaVerifyBoringSsl::New(std::move(public_key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
