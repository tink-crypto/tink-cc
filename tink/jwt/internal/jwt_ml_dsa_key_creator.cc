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

#include "tink/jwt/internal/jwt_ml_dsa_key_creator.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/mldsa.h"
#endif
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/secret_buffer.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<std::unique_ptr<JwtMlDsaPrivateKey>> BuildJwtMlDsaKey(
    const JwtMlDsaParameters& parameters, absl::optional<int> id_requirement,
    absl::string_view public_key_bytes,
    const SecretData& private_key_seed_bytes) {
  JwtMlDsaPublicKey::Builder builder = JwtMlDsaPublicKey::Builder()
                                           .SetParameters(parameters)
                                           .SetPublicKeyBytes(public_key_bytes);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  absl::StatusOr<JwtMlDsaPrivateKey> key = JwtMlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_seed_bytes,
                     GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<JwtMlDsaPrivateKey>(*key);
}

#ifdef OPENSSL_IS_BORINGSSL
absl::StatusOr<std::unique_ptr<JwtMlDsaPrivateKey>> CreateJwtMlDsa44Key(
    const JwtMlDsaParameters& parameters, absl::optional<int> id_requirement) {
  if (parameters.GetAlgorithm() != JwtMlDsaParameters::Algorithm::kMlDsa44) {
    return absl::InternalError("Expected ML-DSA-44 instance");
  }

  std::string public_key_bytes(MLDSA44_PUBLIC_KEY_BYTES, '\0');
  internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
  auto private_key = util::MakeSecretUniquePtr<MLDSA44_private_key>();

  if (!MLDSA44_generate_key(reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                            private_seed_bytes.data(), private_key.get())) {
    return absl::InternalError("Failed to generate ML-DSA-44 key");
  }

  SecretData secret_data =
      util::internal::AsSecretData(std::move(private_seed_bytes));

  return BuildJwtMlDsaKey(parameters, id_requirement, public_key_bytes,
                          secret_data);
}

absl::StatusOr<std::unique_ptr<JwtMlDsaPrivateKey>> CreateJwtMlDsa65Key(
    const JwtMlDsaParameters& parameters, absl::optional<int> id_requirement) {
  if (parameters.GetAlgorithm() != JwtMlDsaParameters::Algorithm::kMlDsa65) {
    return absl::InternalError("Expected ML-DSA-65 instance");
  }

  std::string public_key_bytes(MLDSA65_PUBLIC_KEY_BYTES, '\0');
  internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
  auto private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();

  if (!MLDSA65_generate_key(reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                            private_seed_bytes.data(), private_key.get())) {
    return absl::InternalError("Failed to generate ML-DSA-65 key");
  }

  SecretData secret_data =
      util::internal::AsSecretData(std::move(private_seed_bytes));

  return BuildJwtMlDsaKey(parameters, id_requirement, public_key_bytes,
                          secret_data);
}

absl::StatusOr<std::unique_ptr<JwtMlDsaPrivateKey>> CreateJwtMlDsa87Key(
    const JwtMlDsaParameters& parameters, absl::optional<int> id_requirement) {
  if (parameters.GetAlgorithm() != JwtMlDsaParameters::Algorithm::kMlDsa87) {
    return absl::InternalError("Expected ML-DSA-87 instance");
  }

  std::string public_key_bytes(MLDSA87_PUBLIC_KEY_BYTES, '\0');
  internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
  auto private_key = util::MakeSecretUniquePtr<MLDSA87_private_key>();
  if (!MLDSA87_generate_key(reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                            private_seed_bytes.data(), private_key.get())) {
    return absl::InternalError("Failed to generate ML-DSA-87 key");
  }

  SecretData secret_data =
      util::internal::AsSecretData(std::move(private_seed_bytes));

  return BuildJwtMlDsaKey(parameters, id_requirement, public_key_bytes,
                          secret_data);
}
#endif  // OPENSSL_IS_BORINGSSL

}  // namespace

absl::StatusOr<std::unique_ptr<JwtMlDsaPrivateKey>> CreateJwtMlDsaKey(
    const JwtMlDsaParameters& parameters, absl::optional<int> id_requirement) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  switch (parameters.GetAlgorithm()) {
    case JwtMlDsaParameters::Algorithm::kMlDsa44:
      return CreateJwtMlDsa44Key(parameters, id_requirement);
    case JwtMlDsaParameters::Algorithm::kMlDsa65:
      return CreateJwtMlDsa65Key(parameters, id_requirement);
    case JwtMlDsaParameters::Algorithm::kMlDsa87:
      return CreateJwtMlDsa87Key(parameters, id_requirement);
    default:
      return absl::InvalidArgumentError(
          "Only ML-DSA-44, ML-DSA-65, and ML-DSA-87 are supported");
  }
#endif  // OPENSSL_IS_BORINGSSL
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
