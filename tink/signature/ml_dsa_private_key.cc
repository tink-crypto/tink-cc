// Copyright 2024 Google LLC
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

#include "tink/signature/ml_dsa_private_key.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/mem.h"
#include "openssl/mldsa.h"
#endif
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {

absl::StatusOr<MlDsaPrivateKey> MlDsaPrivateKey::Create(
    const MlDsaPublicKey& public_key, const RestrictedData& private_seed_bytes,
    PartialKeyAccessToken token) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  if (private_seed_bytes.size() != MLDSA_SEED_BYTES) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid ML-DSA private seed size. The seed must be ",
                     MLDSA_SEED_BYTES, " bytes."));
  }

  switch (public_key.GetParameters().GetInstance()) {
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsaPrivateKey::Create65(public_key, private_seed_bytes, token);
    case MlDsaParameters::Instance::kMlDsa87:
      return MlDsaPrivateKey::Create87(public_key, private_seed_bytes, token);
    default:
      return absl::InvalidArgumentError(
          "Invalid ML-DSA instance. Only ML-DSA-65 and "
          "ML-DSA-87 are currently supported.");
  }
#endif
}

absl::StatusOr<MlDsaPrivateKey> MlDsaPrivateKey::Create65(
    const MlDsaPublicKey& public_key, const RestrictedData& private_seed_bytes,
    PartialKeyAccessToken token) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  util::SecretUniquePtr<MLDSA65_private_key> boringssl_private_key =
      util::MakeSecretUniquePtr<MLDSA65_private_key>();
  absl::Status status = internal::CallWithCoreDumpProtection([&]() {
    if (!MLDSA65_private_key_from_seed(
            boringssl_private_key.get(),
            reinterpret_cast<const uint8_t*>(
                private_seed_bytes.GetSecret(InsecureSecretKeyAccess::Get())
                    .data()),
            private_seed_bytes.size())) {
      return absl::InternalError(
          "Failed to create ML-DSA private key from seed.");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  auto boringssl_public_key = std::make_unique<MLDSA65_public_key>();
  status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(boringssl_public_key.get(),
                                                   sizeof(MLDSA65_public_key));
    if (!MLDSA65_public_from_private(boringssl_public_key.get(),
                                     boringssl_private_key.get())) {
      return absl::InternalError(
          "Failed to get ML-DSA public key from private key.");
    }
    internal::DfsanClearLabel(boringssl_public_key.get(),
                              sizeof(MLDSA65_public_key));
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  CBB cbb;
  size_t size;
  std::string public_key_bytes_regen;
  public_key_bytes_regen.resize(MLDSA65_PUBLIC_KEY_BYTES);

  status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&public_key_bytes_regen[0],
                                                   MLDSA65_PUBLIC_KEY_BYTES);
    if (!CBB_init_fixed(&cbb,
                        reinterpret_cast<uint8_t*>(&public_key_bytes_regen[0]),
                        MLDSA65_PUBLIC_KEY_BYTES) ||
        !MLDSA65_marshal_public_key(&cbb, boringssl_public_key.get()) ||
        !CBB_finish(&cbb, nullptr, &size) || size != MLDSA65_PUBLIC_KEY_BYTES) {
      return absl::InternalError("Failed to serialize ML-DSA public key.");
    }
    internal::DfsanClearLabel(&public_key_bytes_regen[0],
                              MLDSA65_PUBLIC_KEY_BYTES);
    return absl::OkStatus();
  });

  absl::string_view expected_public_key_bytes =
      public_key.GetPublicKeyBytes(token);

  if (CRYPTO_memcmp(expected_public_key_bytes.data(),
                    public_key_bytes_regen.data(),
                    MLDSA65_PUBLIC_KEY_BYTES) != 0) {
    return absl::InvalidArgumentError(
        "ML-DSA public key doesn't match the private key.");
  }

  return MlDsaPrivateKey(public_key, private_seed_bytes);
#endif
}

absl::StatusOr<MlDsaPrivateKey> MlDsaPrivateKey::Create87(
    const MlDsaPublicKey& public_key, const RestrictedData& private_seed_bytes,
    PartialKeyAccessToken token) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  util::SecretUniquePtr<MLDSA87_private_key> boringssl_private_key =
      util::MakeSecretUniquePtr<MLDSA87_private_key>();
  absl::Status status = internal::CallWithCoreDumpProtection([&]() {
    if (!MLDSA87_private_key_from_seed(
            boringssl_private_key.get(),
            reinterpret_cast<const uint8_t*>(
                private_seed_bytes.GetSecret(InsecureSecretKeyAccess::Get())
                    .data()),
            private_seed_bytes.size())) {
      return absl::InternalError(
          "Failed to create ML-DSA private key from seed.");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  auto boringssl_public_key = std::make_unique<MLDSA87_public_key>();
  status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(boringssl_public_key.get(),
                                                   sizeof(MLDSA87_public_key));
    if (!MLDSA87_public_from_private(boringssl_public_key.get(),
                                     boringssl_private_key.get())) {
      return absl::InternalError(
          "Failed to get ML-DSA public key from private key.");
    }
    internal::DfsanClearLabel(boringssl_public_key.get(),
                              sizeof(MLDSA87_public_key));
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  CBB cbb;
  size_t size;
  std::string public_key_bytes_regen;
  public_key_bytes_regen.resize(MLDSA87_PUBLIC_KEY_BYTES);

  status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&public_key_bytes_regen[0],
                                                   MLDSA87_PUBLIC_KEY_BYTES);
    if (!CBB_init_fixed(&cbb,
                        reinterpret_cast<uint8_t*>(&public_key_bytes_regen[0]),
                        MLDSA87_PUBLIC_KEY_BYTES) ||
        !MLDSA87_marshal_public_key(&cbb, boringssl_public_key.get()) ||
        !CBB_finish(&cbb, nullptr, &size) || size != MLDSA87_PUBLIC_KEY_BYTES) {
      return absl::InternalError("Failed to serialize ML-DSA public key.");
    }
    internal::DfsanClearLabel(&public_key_bytes_regen[0],
                              MLDSA87_PUBLIC_KEY_BYTES);
    return absl::OkStatus();
  });

  absl::string_view expected_public_key_bytes =
      public_key.GetPublicKeyBytes(token);

  if (CRYPTO_memcmp(expected_public_key_bytes.data(),
                    public_key_bytes_regen.data(),
                    MLDSA87_PUBLIC_KEY_BYTES) != 0) {
    return absl::InvalidArgumentError(
        "ML-DSA public key doesn't match the private key.");
  }

  return MlDsaPrivateKey(public_key, private_seed_bytes);
#endif
}

bool MlDsaPrivateKey::operator==(const Key& other) const {
  const MlDsaPrivateKey* that = dynamic_cast<const MlDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         private_seed_bytes_ == that->private_seed_bytes_;
}

}  // namespace tink
}  // namespace crypto
