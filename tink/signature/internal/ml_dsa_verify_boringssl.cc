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

#include "tink/signature/internal/ml_dsa_verify_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/mldsa.h"
#endif
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

#ifdef OPENSSL_IS_BORINGSSL
class MlDsa65VerifyBoringSsl : public PublicKeyVerify {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      MlDsaPublicKey public_key, absl::string_view context);

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

  explicit MlDsa65VerifyBoringSsl(
      MlDsaPublicKey public_key,
      std::unique_ptr<MLDSA65_public_key> boringssl_public_key,
      absl::string_view context)
      : public_key_(std::move(public_key)),
        boringssl_public_key_(std::move(boringssl_public_key)),
        context_(context) {}

  MlDsaPublicKey public_key_;
  std::unique_ptr<MLDSA65_public_key> boringssl_public_key_;
  std::string context_;
};

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> MlDsa65VerifyBoringSsl::New(
    MlDsaPublicKey public_key, absl::string_view context) {
  auto status = CheckFipsCompatibility<MlDsa65VerifyBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (public_key.GetParameters().GetInstance() !=
      MlDsaParameters::Instance::kMlDsa65) {
    return absl::InternalError("Expected ML-DSA-65");
  }

  if (context.size() > 255) {
    return absl::InternalError("Context is too long");
  }

  absl::string_view public_key_bytes =
      public_key.GetPublicKeyBytes(GetPartialKeyAccess());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key_bytes.data()),
           public_key_bytes.size());
  auto boringssl_public_key = std::make_unique<MLDSA65_public_key>();
  if (!MLDSA65_parse_public_key(boringssl_public_key.get(), &cbs)) {
    return absl::InternalError("Invalid ML-DSA public key");
  }

  return absl::make_unique<MlDsa65VerifyBoringSsl>(
      std::move(public_key), std::move(boringssl_public_key), context);
}

absl::Status MlDsa65VerifyBoringSsl::Verify(absl::string_view signature,
                                            absl::string_view data) const {
  size_t output_prefix_size = public_key_.GetOutputPrefix().size();

  if (signature.size() != MLDSA65_SIGNATURE_BYTES + output_prefix_size) {
    return absl::InvalidArgumentError(
        "Verification failed: incorrect signature length for ML-DSA");
  }

  if (!absl::StartsWith(signature, public_key_.GetOutputPrefix())) {
    return absl::InvalidArgumentError(
        "Verification failed: invalid output prefix");
  }

  if (1 != MLDSA65_verify(boringssl_public_key_.get(),
                          reinterpret_cast<const uint8_t*>(signature.data() +
                                                           output_prefix_size),
                          MLDSA65_SIGNATURE_BYTES,
                          reinterpret_cast<const uint8_t*>(data.data()),
                          data.size(),
                          reinterpret_cast<const uint8_t*>(context_.data()),
                          context_.size())) {
    return absl::InvalidArgumentError("Signature is not valid");
  }

  return absl::OkStatus();
}

class MlDsa87VerifyBoringSsl : public PublicKeyVerify {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      MlDsaPublicKey public_key, absl::string_view context);

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

  explicit MlDsa87VerifyBoringSsl(
      MlDsaPublicKey public_key,
      std::unique_ptr<MLDSA87_public_key> boringssl_public_key,
      absl::string_view context)
      : public_key_(std::move(public_key)),
        boringssl_public_key_(std::move(boringssl_public_key)),
        context_(context) {}

  MlDsaPublicKey public_key_;
  std::unique_ptr<MLDSA87_public_key> boringssl_public_key_;
  std::string context_;
};

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> MlDsa87VerifyBoringSsl::New(
    MlDsaPublicKey public_key, absl::string_view context) {
  auto status = CheckFipsCompatibility<MlDsa87VerifyBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (public_key.GetParameters().GetInstance() !=
      MlDsaParameters::Instance::kMlDsa87) {
    return absl::InternalError("Expected ML-DSA-87");
  }

  if (context.size() > 255) {
    return absl::InternalError("Context is too long");
  }

  absl::string_view public_key_bytes =
      public_key.GetPublicKeyBytes(GetPartialKeyAccess());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key_bytes.data()),
           public_key_bytes.size());
  auto boringssl_public_key = std::make_unique<MLDSA87_public_key>();
  if (!MLDSA87_parse_public_key(boringssl_public_key.get(), &cbs)) {
    return absl::InternalError("Invalid ML-DSA public key");
  }

  return absl::make_unique<MlDsa87VerifyBoringSsl>(
      std::move(public_key), std::move(boringssl_public_key), context);
}

absl::Status MlDsa87VerifyBoringSsl::Verify(absl::string_view signature,
                                            absl::string_view data) const {
  size_t output_prefix_size = public_key_.GetOutputPrefix().size();

  if (signature.size() != MLDSA87_SIGNATURE_BYTES + output_prefix_size) {
    return absl::InvalidArgumentError(
        "Verification failed: incorrect signature length for ML-DSA");
  }

  if (!absl::StartsWith(signature, public_key_.GetOutputPrefix())) {
    return absl::InvalidArgumentError(
        "Verification failed: invalid output prefix");
  }

  if (1 != MLDSA87_verify(boringssl_public_key_.get(),
                          reinterpret_cast<const uint8_t*>(signature.data() +
                                                           output_prefix_size),
                          MLDSA87_SIGNATURE_BYTES,
                          reinterpret_cast<const uint8_t*>(data.data()),
                          data.size(),
                          reinterpret_cast<const uint8_t*>(context_.data()),
                          context_.size())) {
    return absl::InvalidArgumentError("Signature is not valid");
  }

  return absl::OkStatus();
}
#endif  // OPENSSL_IS_BORINGSSL

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
NewMlDsaVerifyWithContextBoringSsl(MlDsaPublicKey public_key,
                                   absl::string_view context) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  switch (public_key.GetParameters().GetInstance()) {
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsa65VerifyBoringSsl::New(std::move(public_key), context);
    case MlDsaParameters::Instance::kMlDsa87:
      return MlDsa87VerifyBoringSsl::New(std::move(public_key), context);
    default:
      return absl::InvalidArgumentError(
          "Only ML-DSA-65 and ML-DSA-87 are supported");
  }
#endif  // OPENSSL_IS_BORINGSSL
}

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewMlDsaVerifyBoringSsl(
    MlDsaPublicKey public_key) {
  return NewMlDsaVerifyWithContextBoringSsl(std::move(public_key),
                                            /* context = */ "");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
