// Copyright 2025 Google LLC
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

#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/hrss.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<std::string> ComputeOutputPrefix(
    const Cecpq2Parameters& parameters, absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case Cecpq2Parameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case Cecpq2Parameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return absl::InvalidArgumentError(
            "ID requirement must have value with kTink");
      }
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Invalid variant: ", parameters.GetVariant()));
  }
}

}  // namespace

Cecpq2PublicKey::Builder& Cecpq2PublicKey::Builder::SetParameters(
    const Cecpq2Parameters& parameters) {
  parameters_ = parameters;
  return *this;
}

Cecpq2PublicKey::Builder& Cecpq2PublicKey::Builder::SetX25519PublicKeyBytes(
    absl::string_view x25519_public_key_bytes) {
  x25519_public_key_bytes_ = x25519_public_key_bytes;
  return *this;
}

Cecpq2PublicKey::Builder& Cecpq2PublicKey::Builder::SetHrssPublicKeyBytes(
    absl::string_view hrss_public_key_bytes) {
  hrss_public_key_bytes_ = hrss_public_key_bytes;
  return *this;
}

Cecpq2PublicKey::Builder& Cecpq2PublicKey::Builder::SetIdRequirement(
    int32_t id) {
  id_requirement_ = id;
  return *this;
}

absl::StatusOr<Cecpq2PublicKey> Cecpq2PublicKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return absl::InvalidArgumentError("CECPQ2 parameters must be set.");
  }
  if (!x25519_public_key_bytes_.has_value()) {
    return absl::InvalidArgumentError("X25519 public key must be set.");
  }
  if (!hrss_public_key_bytes_.has_value()) {
    return absl::InvalidArgumentError("HRSS public key must be set.");
  }

  if (parameters_->HasIdRequirement() && !id_requirement_.has_value()) {
    return absl::InvalidArgumentError(
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters_->HasIdRequirement() && id_requirement_.has_value()) {
    return absl::InvalidArgumentError(
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }

  // Validate X25519 public key length.
  if (x25519_public_key_bytes_->length() != internal::X25519KeyPubKeySize()) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid X25519 public key length (expected %d, got %d)",
        internal::X25519KeyPubKeySize(), x25519_public_key_bytes_->length()));
  }

  // Validate HRSS public key length.
  if (hrss_public_key_bytes_->length() != HRSS_PUBLIC_KEY_BYTES) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid HRSS public key length (expected %d, got %d)",
        HRSS_PUBLIC_KEY_BYTES, hrss_public_key_bytes_->length()));
  }

  absl::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(*parameters_, id_requirement_);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }

  return Cecpq2PublicKey(*parameters_, *x25519_public_key_bytes_,
                         *hrss_public_key_bytes_, id_requirement_,
                         *output_prefix);
}

bool Cecpq2PublicKey::operator==(const Key& other) const {
  const Cecpq2PublicKey* that = dynamic_cast<const Cecpq2PublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  if (x25519_public_key_bytes_ != that->x25519_public_key_bytes_) {
    return false;
  }
  return hrss_public_key_bytes_ == that->hrss_public_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
