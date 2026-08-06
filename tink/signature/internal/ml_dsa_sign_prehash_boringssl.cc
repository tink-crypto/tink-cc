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
///////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/ml_dsa_sign_prehash_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "openssl/opensslv.h"  // To get OPENSSL_IS_BORINGSSL if needed
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/mldsa.h"
#endif
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/signature/internal/prehash_format.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/sign_prehash.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

#ifdef OPENSSL_IS_BORINGSSL

class MlDsa44SignPrehashBoringSsl : public SignPrehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<SignPrehash>> New(
      const MlDsaPrivateKey& private_key);

  absl::StatusOr<std::string> Sign(absl::string_view prehash) const override;

  explicit MlDsa44SignPrehashBoringSsl(
      MlDsaPrivateKey private_key,
      util::SecretUniquePtr<MLDSA44_private_key> boringssl_private_key)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)),
        prehash_prefix_(
            GetPrehashPrefix(*private_key_.GetPublicKey().GetIdRequirement())) {
  }

 private:
  MlDsaPrivateKey private_key_;
  util::SecretUniquePtr<MLDSA44_private_key> boringssl_private_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<SignPrehash>> MlDsa44SignPrehashBoringSsl::New(
    const MlDsaPrivateKey& private_key) {
  absl::Status status =
      internal::CheckFipsCompatibility<MlDsa44SignPrehashBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (private_key.GetPublicKey().GetParameters().GetVariant() !=
      MlDsaParameters::Variant::kNoPrefixWithPrehashId) {
    return absl::InvalidArgumentError(
        "ML-DSA SignPrehash requires Variant::kNoPrefixWithPrehashId");
  }

  auto boringssl_private_key = util::MakeSecretUniquePtr<MLDSA44_private_key>();
  status = internal::CallWithCoreDumpProtection([&]() {
    absl::string_view private_seed_bytes =
        private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
            .GetSecret(InsecureSecretKeyAccess::Get());
    if (!MLDSA44_private_key_from_seed(
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

  return std::make_unique<MlDsa44SignPrehashBoringSsl>(
      std::move(private_key), std::move(boringssl_private_key));
}

absl::StatusOr<std::string> MlDsa44SignPrehashBoringSsl::Sign(
    absl::string_view prehash) const {
  if (prehash.size() != prehash_prefix_.size() + MLDSA_MU_BYTES) {
    return absl::InvalidArgumentError(
        "SignPrehash failed: incorrect prehash length");
  }
  if (!absl::StartsWith(prehash, prehash_prefix_)) {
    return absl::InvalidArgumentError(
        "SignPrehash failed: invalid prehash prefix");
  }

  absl::string_view mu = prehash.substr(prehash_prefix_.size(), MLDSA_MU_BYTES);

  std::string signature(private_key_.GetOutputPrefix());
  size_t signature_buffer_size =
      MLDSA44_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size();
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  absl::Status status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    if (!MLDSA44_sign_message_representative(
            reinterpret_cast<uint8_t*>(&signature[0] +
                                       private_key_.GetOutputPrefix().size()),
            boringssl_private_key_.get(),
            reinterpret_cast<const uint8_t*>(mu.data()))) {
      return absl::InternalError(
          "Failed to generate ML-DSA signature from message representative.");
    }
    internal::DfsanClearLabel(&signature[0], signature_buffer_size);
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  return signature;
}

class MlDsa65SignPrehashBoringSsl : public SignPrehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<SignPrehash>> New(
      const MlDsaPrivateKey& private_key);

  absl::StatusOr<std::string> Sign(absl::string_view prehash) const override;

  explicit MlDsa65SignPrehashBoringSsl(
      MlDsaPrivateKey private_key,
      util::SecretUniquePtr<MLDSA65_private_key> boringssl_private_key)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)),
        prehash_prefix_(
            GetPrehashPrefix(*private_key_.GetPublicKey().GetIdRequirement())) {
  }

 private:
  MlDsaPrivateKey private_key_;
  util::SecretUniquePtr<MLDSA65_private_key> boringssl_private_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<SignPrehash>> MlDsa65SignPrehashBoringSsl::New(
    const MlDsaPrivateKey& private_key) {
  absl::Status status =
      internal::CheckFipsCompatibility<MlDsa65SignPrehashBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (private_key.GetPublicKey().GetParameters().GetVariant() !=
      MlDsaParameters::Variant::kNoPrefixWithPrehashId) {
    return absl::InvalidArgumentError(
        "ML-DSA SignPrehash requires Variant::kNoPrefixWithPrehashId");
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

  return std::make_unique<MlDsa65SignPrehashBoringSsl>(
      std::move(private_key), std::move(boringssl_private_key));
}

absl::StatusOr<std::string> MlDsa65SignPrehashBoringSsl::Sign(
    absl::string_view prehash) const {
  if (prehash.size() != prehash_prefix_.size() + MLDSA_MU_BYTES) {
    return absl::InvalidArgumentError(
        "SignPrehash failed: incorrect prehash length");
  }
  if (!absl::StartsWith(prehash, prehash_prefix_)) {
    return absl::InvalidArgumentError(
        "SignPrehash failed: invalid prehash prefix");
  }

  absl::string_view mu = prehash.substr(prehash_prefix_.size(), MLDSA_MU_BYTES);

  std::string signature(private_key_.GetOutputPrefix());
  size_t signature_buffer_size =
      MLDSA65_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size();
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  absl::Status status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    if (!MLDSA65_sign_message_representative(
            reinterpret_cast<uint8_t*>(&signature[0] +
                                       private_key_.GetOutputPrefix().size()),
            boringssl_private_key_.get(),
            reinterpret_cast<const uint8_t*>(mu.data()))) {
      return absl::InternalError(
          "Failed to generate ML-DSA signature from message representative.");
    }
    internal::DfsanClearLabel(&signature[0], signature_buffer_size);
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }

  return signature;
}

class MlDsa87SignPrehashBoringSsl : public SignPrehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<SignPrehash>> New(
      const MlDsaPrivateKey& private_key);

  absl::StatusOr<std::string> Sign(absl::string_view prehash) const override;

  explicit MlDsa87SignPrehashBoringSsl(
      MlDsaPrivateKey private_key,
      util::SecretUniquePtr<MLDSA87_private_key> boringssl_private_key)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)),
        prehash_prefix_(
            GetPrehashPrefix(*private_key_.GetPublicKey().GetIdRequirement())) {
  }

 private:
  MlDsaPrivateKey private_key_;
  util::SecretUniquePtr<MLDSA87_private_key> boringssl_private_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<SignPrehash>> MlDsa87SignPrehashBoringSsl::New(
    const MlDsaPrivateKey& private_key) {
  absl::Status status =
      internal::CheckFipsCompatibility<MlDsa87SignPrehashBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (private_key.GetPublicKey().GetParameters().GetVariant() !=
      MlDsaParameters::Variant::kNoPrefixWithPrehashId) {
    return absl::InvalidArgumentError(
        "ML-DSA SignPrehash requires Variant::kNoPrefixWithPrehashId");
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

  return std::make_unique<MlDsa87SignPrehashBoringSsl>(
      std::move(private_key), std::move(boringssl_private_key));
}

absl::StatusOr<std::string> MlDsa87SignPrehashBoringSsl::Sign(
    absl::string_view prehash) const {
  if (prehash.size() != prehash_prefix_.size() + MLDSA_MU_BYTES) {
    return absl::InvalidArgumentError(
        "SignPrehash failed: incorrect prehash length");
  }
  if (!absl::StartsWith(prehash, prehash_prefix_)) {
    return absl::InvalidArgumentError(
        "SignPrehash failed: invalid prehash prefix");
  }

  absl::string_view mu = prehash.substr(prehash_prefix_.size(), MLDSA_MU_BYTES);

  std::string signature(private_key_.GetOutputPrefix());
  size_t signature_buffer_size =
      MLDSA87_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size();
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  absl::Status status = internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    if (!MLDSA87_sign_message_representative(
            reinterpret_cast<uint8_t*>(&signature[0] +
                                       private_key_.GetOutputPrefix().size()),
            boringssl_private_key_.get(),
            reinterpret_cast<const uint8_t*>(mu.data()))) {
      return absl::InternalError(
          "Failed to generate ML-DSA signature from message representative.");
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

absl::StatusOr<std::unique_ptr<SignPrehash>> NewMlDsaSignPrehashBoringSsl(
    MlDsaPrivateKey private_key) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  switch (private_key.GetPublicKey().GetParameters().GetInstance()) {
    case MlDsaParameters::Instance::kMlDsa44:
      return MlDsa44SignPrehashBoringSsl::New(std::move(private_key));
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsa65SignPrehashBoringSsl::New(std::move(private_key));
    case MlDsaParameters::Instance::kMlDsa87:
      return MlDsa87SignPrehashBoringSsl::New(std::move(private_key));
    default:
      return absl::InvalidArgumentError(
          "Only ML-DSA-44, ML-DSA-65 and ML-DSA-87 are supported");
  }
#endif  // OPENSSL_IS_BORINGSSL
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
