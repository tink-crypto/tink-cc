// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/subtle/composite_ml_dsa_verify_boringssl.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/mldsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/low_level_crypto_access_token.h"
#include "tink/public_key_verify.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_public_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/internal/composite_ml_dsa_util_boringssl.h"
#include "tink/signature/internal/ml_dsa_verify_boringssl.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> GetClassicalPublicKeyVerify(
    const CompositeMlDsaPublicKey& public_key) {
  switch (public_key.GetParameters().GetClassicalAlgorithm()) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519: {
      const Ed25519PublicKey* classical_public_key =
          dynamic_cast<const Ed25519PublicKey*>(
              &public_key.GetClassicalPublicKey());
      if (classical_public_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical public key is not an Ed25519 public key.");
      }
      return subtle::Ed25519VerifyBoringSsl::New(*classical_public_key);
    }
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521: {
      const EcdsaPublicKey* classical_public_key =
          dynamic_cast<const EcdsaPublicKey*>(
              &public_key.GetClassicalPublicKey());
      if (classical_public_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical public key is not an ECDSA public key.");
      }
      return subtle::EcdsaVerifyBoringSsl::New(*classical_public_key);
    }
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss: {
      const RsaSsaPssPublicKey* classical_public_key =
          dynamic_cast<const RsaSsaPssPublicKey*>(
              &public_key.GetClassicalPublicKey());
      if (classical_public_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical public key is not an RSA-SSA-PSS public key.");
      }
      return subtle::RsaSsaPssVerifyBoringSsl::New(*classical_public_key);
    }
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1: {
      const RsaSsaPkcs1PublicKey* classical_public_key =
          dynamic_cast<const RsaSsaPkcs1PublicKey*>(
              &public_key.GetClassicalPublicKey());
      if (classical_public_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical public key is not an RSA-SSA-PKCS1 public key.");
      }
      return subtle::RsaSsaPkcs1VerifyBoringSsl::New(*classical_public_key);
    }
    default:
      return absl::UnimplementedError(
          "Not implemented for this classical algorithm.");
  }
}

class CompositeMlDsaVerify : public PublicKeyVerify {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      const CompositeMlDsaPublicKey& public_key);

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

  explicit CompositeMlDsaVerify(
      CompositeMlDsaPublicKey public_key,
      std::unique_ptr<PublicKeyVerify> ml_dsa_verify,
      std::unique_ptr<PublicKeyVerify> classical_verify,
      absl::string_view label)
      : public_key_(std::move(public_key)),
        ml_dsa_verify_(std::move(ml_dsa_verify)),
        classical_verify_(std::move(classical_verify)),
        label_(label) {}

  CompositeMlDsaPublicKey public_key_;
  std::unique_ptr<PublicKeyVerify> ml_dsa_verify_;
  std::unique_ptr<PublicKeyVerify> classical_verify_;
  std::string label_;
};

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> CompositeMlDsaVerify::New(
    const CompositeMlDsaPublicKey& public_key) {
  auto status = internal::CheckFipsCompatibility<CompositeMlDsaVerify>();
  if (!status.ok()) {
    return status;
  }

  // The composite signature label is used as the ML-DSA context.
  absl::StatusOr<std::string> label =
      internal::GetCompositeMlDsaLabel(public_key.GetParameters());
  if (!label.ok()) {
    return label.status();
  }

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> ml_dsa_verify =
      internal::NewMlDsaVerifyWithContextBoringSsl(
          public_key.GetMlDsaPublicKey(), *label);
  if (!ml_dsa_verify.ok()) {
    return ml_dsa_verify.status();
  }

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> classical_verify =
      GetClassicalPublicKeyVerify(public_key);
  if (!classical_verify.ok()) {
    return classical_verify.status();
  }

  return std::make_unique<CompositeMlDsaVerify>(
      public_key, std::move(*ml_dsa_verify), std::move(*classical_verify),
      *label);
}

absl::Status CompositeMlDsaVerify::Verify(absl::string_view signature,
                                          absl::string_view data) const {
  size_t ml_dsa_signature_size = 0;
  switch (public_key_.GetParameters().GetMlDsaInstance()) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65:
      ml_dsa_signature_size = MLDSA65_SIGNATURE_BYTES;
      break;
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87:
      ml_dsa_signature_size = MLDSA87_SIGNATURE_BYTES;
      break;
    default:
      return absl::InvalidArgumentError("MLDSA instance is not supported.");
  }

  size_t output_prefix_size = public_key_.GetOutputPrefix().size();

  if (signature.size() < ml_dsa_signature_size + output_prefix_size) {
    return absl::InvalidArgumentError("Signature is too short.");
  }

  if (!absl::StartsWith(signature, public_key_.GetOutputPrefix())) {
    return absl::InvalidArgumentError(
        "Verification failed: invalid output prefix");
  }

  std::string message_prime =
      internal::ComputeCompositeMlDsaMessagePrime(label_, data);

  absl::string_view ml_dsa_signature =
      signature.substr(output_prefix_size, ml_dsa_signature_size);
  absl::Status ml_dsa_verify_status =
      ml_dsa_verify_->Verify(ml_dsa_signature, message_prime);
  if (!ml_dsa_verify_status.ok()) {
    return ml_dsa_verify_status;
  }

  absl::string_view classical_signature =
      signature.substr(output_prefix_size + ml_dsa_signature_size);
  return classical_verify_->Verify(classical_signature, message_prime);
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewCompositeMlDsaVerify(
    const CompositeMlDsaPublicKey& public_key,
    LowLevelCryptoAccessToken token) {
  return CompositeMlDsaVerify::New(public_key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
