// Copyright 2026 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/subtle/composite_ml_dsa_sign_boringssl.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/low_level_crypto_access_token.h"
#include "tink/public_key_sign.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/composite_ml_dsa_util_boringssl.h"
#include "tink/signature/internal/ml_dsa_sign_boringssl.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/ed25519_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

absl::StatusOr<std::unique_ptr<PublicKeySign>> GetClassicalPublicKeySign(
    const CompositeMlDsaPrivateKey& private_key) {
  switch (private_key.GetPublicKey().GetParameters().GetClassicalAlgorithm()) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519: {
      const Ed25519PrivateKey* classical_private_key =
          dynamic_cast<const Ed25519PrivateKey*>(
              &private_key.GetClassicalPrivateKey());
      if (classical_private_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical private key is not an Ed25519 private key.");
      }
      return subtle::Ed25519SignBoringSsl::New(*classical_private_key);
    }
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521: {
      const EcdsaPrivateKey* classical_private_key =
          dynamic_cast<const EcdsaPrivateKey*>(
              &private_key.GetClassicalPrivateKey());
      if (classical_private_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical private key is not an ECDSA private key.");
      }
      return subtle::EcdsaSignBoringSsl::New(*classical_private_key);
    }
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss: {
      const RsaSsaPssPrivateKey* classical_private_key =
          dynamic_cast<const RsaSsaPssPrivateKey*>(
              &private_key.GetClassicalPrivateKey());
      if (classical_private_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical private key is not an RSA-PSS private key.");
      }
      return subtle::RsaSsaPssSignBoringSsl::New(*classical_private_key);
    }
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1: {
      const RsaSsaPkcs1PrivateKey* classical_private_key =
          dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
              &private_key.GetClassicalPrivateKey());
      if (classical_private_key == nullptr) {
        return absl::InvalidArgumentError(
            "Classical private key is not an RSA-PKCS1 private key.");
      }
      return subtle::RsaSsaPkcs1SignBoringSsl::New(*classical_private_key);
    }
    default:
      return absl::UnimplementedError(
          "Not implemented for this classical algorithm.");
  }
}

class CompositeMlDsaSign : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const CompositeMlDsaPrivateKey& private_key);

  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

  explicit CompositeMlDsaSign(CompositeMlDsaPrivateKey private_key,
                              std::unique_ptr<PublicKeySign> ml_dsa_sign,
                              std::unique_ptr<PublicKeySign> classical_sign,
                              absl::string_view label)
      : private_key_(std::move(private_key)),
        ml_dsa_sign_(std::move(ml_dsa_sign)),
        classical_sign_(std::move(classical_sign)),
        label_(label) {}

  CompositeMlDsaPrivateKey private_key_;
  std::unique_ptr<PublicKeySign> ml_dsa_sign_;
  std::unique_ptr<PublicKeySign> classical_sign_;
  std::string label_;
};

absl::StatusOr<std::unique_ptr<PublicKeySign>> CompositeMlDsaSign::New(
    const CompositeMlDsaPrivateKey& private_key) {
  absl::Status status = internal::CheckFipsCompatibility<CompositeMlDsaSign>();
  if (!status.ok()) {
    return status;
  }

  // The composite signature label is used as the ML-DSA context.
  absl::StatusOr<std::string> label = internal::GetCompositeMlDsaLabel(
      private_key.GetPublicKey().GetParameters());
  if (!label.ok()) {
    return label.status();
  }

  absl::StatusOr<std::unique_ptr<PublicKeySign>> ml_dsa_sign =
      internal::NewMlDsaSignWithContextBoringSsl(
          private_key.GetMlDsaPrivateKey(), *label);
  if (!ml_dsa_sign.ok()) {
    return ml_dsa_sign.status();
  }

  absl::StatusOr<std::unique_ptr<PublicKeySign>> classical_sign =
      GetClassicalPublicKeySign(private_key);
  if (!classical_sign.ok()) {
    return classical_sign.status();
  }

  return std::make_unique<CompositeMlDsaSign>(
      private_key, std::move(*ml_dsa_sign), std::move(*classical_sign), *label);
}

absl::StatusOr<std::string> CompositeMlDsaSign::Sign(
    absl::string_view data) const {
  std::string message_prime =
      internal::ComputeCompositeMlDsaMessagePrime(label_, data);

  absl::StatusOr<std::string> ml_dsa_signature =
      ml_dsa_sign_->Sign(message_prime);
  if (!ml_dsa_signature.ok()) {
    return ml_dsa_signature.status();
  }

  absl::StatusOr<std::string> classical_signature =
      classical_sign_->Sign(message_prime);
  if (!classical_signature.ok()) {
    return classical_signature.status();
  }

  return absl::StrCat(private_key_.GetOutputPrefix(), *ml_dsa_signature,
                      *classical_signature);
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewCompositeMlDsaSign(
    const CompositeMlDsaPrivateKey& private_key,
    LowLevelCryptoAccessToken token) {
  return CompositeMlDsaSign::New(private_key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
