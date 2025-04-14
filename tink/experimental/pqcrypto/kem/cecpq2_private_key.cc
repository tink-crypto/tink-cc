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

#include "tink/experimental/pqcrypto/kem/cecpq2_private_key.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"
#include "tink/experimental/pqcrypto/kem/subtle/cecpq2_subtle_boringssl_util.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace {

absl::Status ValidateX25519KeyPair(absl::string_view public_key_bytes,
                                   const RestrictedData& private_key_bytes) {
  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::X25519KeyFromPrivateKey(private_key_bytes.Get(
          internal::GetInsecureSecretKeyAccessInternal()));
  if (!x25519_key.ok()) {
    return x25519_key.status();
  }

  absl::string_view public_key_bytes_from_private = absl::string_view(
      reinterpret_cast<const char*>((*x25519_key)->public_value),
      internal::X25519KeyPubKeySize());
  if (public_key_bytes != public_key_bytes_from_private) {
    return absl::InvalidArgumentError(
        "X25519 private key does not match the specified X25519 public key.");
  }

  return absl::OkStatus();
}

absl::Status ValidateHrssKeyPair(absl::string_view public_key_bytes,
                                 const RestrictedData& private_key_seed) {
  absl::StatusOr<pqc::HrssKeyPair> hrss_key = pqc::GenerateHrssKeyPair(
      private_key_seed.Get(internal::GetInsecureSecretKeyAccessInternal()));
  if (!hrss_key.ok()) {
    return hrss_key.status();
  }
  if (public_key_bytes != hrss_key->hrss_public_key_marshaled) {
    return absl::InvalidArgumentError(
        "HRSS private seed does not match the specified HRSS public key.");
  }

  return absl::OkStatus();
}

}  // namespace

Cecpq2PrivateKey::Builder& Cecpq2PrivateKey::Builder::SetPublicKey(
    const Cecpq2PublicKey& public_key) {
  public_key_ = public_key;
  return *this;
}

Cecpq2PrivateKey::Builder& Cecpq2PrivateKey::Builder::SetX25519PrivateKeyBytes(
    const RestrictedData& x25519_private_key_bytes) {
  x25519_private_key_bytes_ = x25519_private_key_bytes;
  return *this;
}

Cecpq2PrivateKey::Builder& Cecpq2PrivateKey::Builder::SetHrssPrivateKeySeed(
    const RestrictedData& hrss_private_key_seed) {
  hrss_private_key_seed_ = hrss_private_key_seed;
  return *this;
}

absl::StatusOr<Cecpq2PrivateKey> Cecpq2PrivateKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return absl::InvalidArgumentError("CECPQ2 public key must be set.");
  }
  if (!x25519_private_key_bytes_.has_value()) {
    return absl::InvalidArgumentError("X25519 private key must be set.");
  }
  if (!hrss_private_key_seed_.has_value()) {
    return absl::InvalidArgumentError("HRSS private key seed must be set.");
  }

  absl::Status x25519_key_validation = ValidateX25519KeyPair(
      public_key_->GetX25519PublicKeyBytes(token), *x25519_private_key_bytes_);
  if (!x25519_key_validation.ok()) {
    return x25519_key_validation;
  }

  absl::Status hrss_key_validation = ValidateHrssKeyPair(
      public_key_->GetHrssPublicKeyBytes(token), *hrss_private_key_seed_);
  if (!hrss_key_validation.ok()) {
    return hrss_key_validation;
  }

  return Cecpq2PrivateKey(*public_key_, *x25519_private_key_bytes_,
                          *hrss_private_key_seed_);
}

bool Cecpq2PrivateKey::operator==(const Key& other) const {
  const Cecpq2PrivateKey* that = dynamic_cast<const Cecpq2PrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (x25519_private_key_bytes_ != that->x25519_private_key_bytes_) {
    return false;
  }
  if (hrss_private_key_seed_ != that->hrss_private_key_seed_) {
    return false;
  }
  return GetPublicKey() == that->GetPublicKey();
}

}  // namespace tink
}  // namespace crypto
