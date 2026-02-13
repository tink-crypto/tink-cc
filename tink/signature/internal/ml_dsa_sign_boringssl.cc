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

#include "tink/signature/internal/ml_dsa_sign_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/mldsa.h"
#endif
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

#ifdef OPENSSL_IS_BORINGSSL
class MlDsa65SignBoringSsl : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const MlDsaPrivateKey& private_key, absl::string_view context);

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

  explicit MlDsa65SignBoringSsl(
      MlDsaPrivateKey private_key,
      util::SecretUniquePtr<MLDSA65_private_key> boringssl_private_key,
      absl::string_view context)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)),
        context_(context) {}

  MlDsaPrivateKey private_key_;
  util::SecretUniquePtr<MLDSA65_private_key> boringssl_private_key_;
  std::string context_;
};

absl::StatusOr<std::unique_ptr<PublicKeySign>> MlDsa65SignBoringSsl::New(
    const MlDsaPrivateKey& private_key, absl::string_view context) {
  absl::Status status =
      internal::CheckFipsCompatibility<MlDsa65SignBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (private_key.GetPublicKey().GetParameters().GetInstance() !=
      MlDsaParameters::Instance::kMlDsa65) {
    return absl::InternalError("Expected ML-DSA-65");
  }

  if (context.size() > 255) {
    return absl::InternalError("Context length is too long.");
  }

  auto boringssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();
  status = internal::CallWithCoreDumpProtection([&]() {
    absl::string_view private_seed_bytes =
        private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
            .GetSecret(InsecureSecretKeyAccess::Get());
    if (!MLDSA65_private_key_from_seed(
            boringssl_private_key.get(),
            reinterpret_cast<const uint8_t*>(private_seed_bytes.data()),
            private_seed_bytes.size())) {
      return absl::InternalError(
          "Failed to expand ML-DSA private key from seed.");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  return absl::make_unique<MlDsa65SignBoringSsl>(
      std::move(private_key), std::move(boringssl_private_key), context);
}

absl::StatusOr<std::string> MlDsa65SignBoringSsl::Sign(
    absl::string_view data) const {
  std::string signature(private_key_.GetOutputPrefix());
  size_t signature_buffer_size =
      MLDSA65_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size();
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  absl::Status status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    if (!MLDSA65_sign(
            reinterpret_cast<uint8_t*>(&signature[0] +
                                       private_key_.GetOutputPrefix().size()),
            boringssl_private_key_.get(),
            reinterpret_cast<const uint8_t*>(data.data()), data.size(),
            reinterpret_cast<const uint8_t*>(context_.data()),
            context_.size())) {
      return absl::InternalError("Failed to generate ML-DSA signature.");
    }
    internal::DfsanClearLabel(&signature[0], signature_buffer_size);
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  return signature;
}

class MlDsa87SignBoringSsl : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const MlDsaPrivateKey& private_key, absl::string_view context);

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

  explicit MlDsa87SignBoringSsl(
      MlDsaPrivateKey private_key,
      util::SecretUniquePtr<MLDSA87_private_key> boringssl_private_key,
      absl::string_view context)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)),
        context_(context) {}

  MlDsaPrivateKey private_key_;
  util::SecretUniquePtr<MLDSA87_private_key> boringssl_private_key_;
  std::string context_;
};

absl::StatusOr<std::unique_ptr<PublicKeySign>> MlDsa87SignBoringSsl::New(
    const MlDsaPrivateKey& private_key, absl::string_view context) {
  absl::Status status =
      internal::CheckFipsCompatibility<MlDsa87SignBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (private_key.GetPublicKey().GetParameters().GetInstance() !=
      MlDsaParameters::Instance::kMlDsa87) {
    return absl::InternalError("Expected ML-DSA-87");
  }

  if (context.size() > 255) {
    return absl::InternalError("Context length is too long.");
  }

  auto boringssl_private_key = util::MakeSecretUniquePtr<MLDSA87_private_key>();
  status = internal::CallWithCoreDumpProtection([&]() {
    absl::string_view private_seed_bytes =
        private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
            .GetSecret(InsecureSecretKeyAccess::Get());
    if (!MLDSA87_private_key_from_seed(
            boringssl_private_key.get(),
            reinterpret_cast<const uint8_t*>(private_seed_bytes.data()),
            private_seed_bytes.size())) {
      return absl::InternalError(
          "Failed to expand ML-DSA private key from seed.");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  return absl::make_unique<MlDsa87SignBoringSsl>(
      std::move(private_key), std::move(boringssl_private_key), context);
}

absl::StatusOr<std::string> MlDsa87SignBoringSsl::Sign(
    absl::string_view data) const {
  std::string signature(private_key_.GetOutputPrefix());
  size_t signature_buffer_size =
      MLDSA87_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size();
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  absl::Status status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    if (!MLDSA87_sign(
            reinterpret_cast<uint8_t*>(&signature[0] +
                                       private_key_.GetOutputPrefix().size()),
            boringssl_private_key_.get(),
            reinterpret_cast<const uint8_t*>(data.data()), data.size(),
            reinterpret_cast<const uint8_t*>(context_.data()),
            context_.size())) {
      return absl::InternalError("Failed to generate ML-DSA signature.");
    }
    internal::DfsanClearLabel(&signature[0], signature_buffer_size);
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  return signature;
}
#endif  // OPENSSL_IS_BORINGSSL

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewMlDsaSignWithContextBoringSsl(
    MlDsaPrivateKey private_key, absl::string_view context) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  switch (private_key.GetPublicKey().GetParameters().GetInstance()) {
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsa65SignBoringSsl::New(std::move(private_key), context);
    case MlDsaParameters::Instance::kMlDsa87:
      return MlDsa87SignBoringSsl::New(std::move(private_key), context);
    default:
      return absl::InvalidArgumentError(
          "Only ML-DSA-65 and ML-DSA-87 are supported");
  }
#endif  // OPENSSL_IS_BORINGSSL
}

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewMlDsaSignBoringSsl(
    MlDsaPrivateKey private_key) {
  return NewMlDsaSignWithContextBoringSsl(std::move(private_key),
                                          /* context = */ "");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
