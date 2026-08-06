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

#include "tink/signature/internal/ml_dsa_prehash_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "openssl/opensslv.h"  // To get OPENSSL_IS_BORINGSSL if needed
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/bytestring.h"
#include "openssl/mldsa.h"
#endif
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/signature/internal/prehash_format.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

#ifdef OPENSSL_IS_BORINGSSL

class MlDsa44PrehashBoringSsl : public Prehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<Prehash>> New(
      MlDsaPublicKey public_key);

  absl::StatusOr<std::string> Compute(absl::string_view data) const override;

  explicit MlDsa44PrehashBoringSsl(
      MlDsaPublicKey public_key,
      std::unique_ptr<MLDSA44_public_key> boringssl_public_key)
      : public_key_(std::move(public_key)),
        boringssl_public_key_(std::move(boringssl_public_key)),
        prehash_prefix_(GetPrehashPrefix(*public_key_.GetIdRequirement())) {}

 private:
  MlDsaPublicKey public_key_;
  std::unique_ptr<MLDSA44_public_key> boringssl_public_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<Prehash>> MlDsa44PrehashBoringSsl::New(
    MlDsaPublicKey public_key) {
  auto status = CheckFipsCompatibility<MlDsa44PrehashBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (public_key.GetParameters().GetVariant() !=
      MlDsaParameters::Variant::kNoPrefixWithPrehashId) {
    return absl::InvalidArgumentError(
        "ML-DSA Prehash requires Variant::kNoPrefixWithPrehashId");
  }

  absl::string_view public_key_bytes =
      public_key.GetPublicKeyBytes(GetPartialKeyAccess());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key_bytes.data()),
           public_key_bytes.size());
  auto boringssl_public_key = std::make_unique<MLDSA44_public_key>();
  if (!MLDSA44_parse_public_key(boringssl_public_key.get(), &cbs)) {
    return absl::InvalidArgumentError("Invalid ML-DSA public key");
  }

  return std::make_unique<MlDsa44PrehashBoringSsl>(
      std::move(public_key), std::move(boringssl_public_key));
}

absl::StatusOr<std::string> MlDsa44PrehashBoringSsl::Compute(
    absl::string_view data) const {
  struct MLDSA44_prehash prehash_state;
  if (!MLDSA44_prehash_init(&prehash_state, boringssl_public_key_.get(),
                            /*context=*/nullptr, /*context_len=*/0)) {
    return absl::InternalError("MLDSA44_prehash_init failed.");
  }
  MLDSA44_prehash_update(&prehash_state,
                         reinterpret_cast<const uint8_t*>(data.data()),
                         data.size());
  std::string result = prehash_prefix_;
  size_t prefix_len = result.size();
  result.resize(prefix_len + MLDSA_MU_BYTES);
  MLDSA44_prehash_finalize(reinterpret_cast<uint8_t*>(&result[prefix_len]),
                           &prehash_state);
  return result;
}

class MlDsa65PrehashBoringSsl : public Prehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<Prehash>> New(
      MlDsaPublicKey public_key);

  absl::StatusOr<std::string> Compute(absl::string_view data) const override;

  explicit MlDsa65PrehashBoringSsl(
      MlDsaPublicKey public_key,
      std::unique_ptr<MLDSA65_public_key> boringssl_public_key)
      : public_key_(std::move(public_key)),
        boringssl_public_key_(std::move(boringssl_public_key)),
        prehash_prefix_(GetPrehashPrefix(*public_key_.GetIdRequirement())) {}

 private:
  MlDsaPublicKey public_key_;
  std::unique_ptr<MLDSA65_public_key> boringssl_public_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<Prehash>> MlDsa65PrehashBoringSsl::New(
    MlDsaPublicKey public_key) {
  auto status = CheckFipsCompatibility<MlDsa65PrehashBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (public_key.GetParameters().GetVariant() !=
      MlDsaParameters::Variant::kNoPrefixWithPrehashId) {
    return absl::InvalidArgumentError(
        "ML-DSA Prehash requires Variant::kNoPrefixWithPrehashId");
  }

  absl::string_view public_key_bytes =
      public_key.GetPublicKeyBytes(GetPartialKeyAccess());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key_bytes.data()),
           public_key_bytes.size());
  auto boringssl_public_key = std::make_unique<MLDSA65_public_key>();
  if (!MLDSA65_parse_public_key(boringssl_public_key.get(), &cbs)) {
    return absl::InvalidArgumentError("Invalid ML-DSA public key");
  }

  return std::make_unique<MlDsa65PrehashBoringSsl>(
      std::move(public_key), std::move(boringssl_public_key));
}

absl::StatusOr<std::string> MlDsa65PrehashBoringSsl::Compute(
    absl::string_view data) const {
  struct MLDSA65_prehash prehash_state;
  if (!MLDSA65_prehash_init(&prehash_state, boringssl_public_key_.get(),
                            /*context=*/nullptr, /*context_len=*/0)) {
    return absl::InternalError("MLDSA65_prehash_init failed.");
  }
  MLDSA65_prehash_update(&prehash_state,
                         reinterpret_cast<const uint8_t*>(data.data()),
                         data.size());
  std::string result = prehash_prefix_;
  size_t prefix_len = result.size();
  result.resize(prefix_len + MLDSA_MU_BYTES);
  MLDSA65_prehash_finalize(reinterpret_cast<uint8_t*>(&result[prefix_len]),
                           &prehash_state);
  return result;
}

class MlDsa87PrehashBoringSsl : public Prehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<Prehash>> New(
      MlDsaPublicKey public_key);

  absl::StatusOr<std::string> Compute(absl::string_view data) const override;

  explicit MlDsa87PrehashBoringSsl(
      MlDsaPublicKey public_key,
      std::unique_ptr<MLDSA87_public_key> boringssl_public_key)
      : public_key_(std::move(public_key)),
        boringssl_public_key_(std::move(boringssl_public_key)),
        prehash_prefix_(GetPrehashPrefix(*public_key_.GetIdRequirement())) {}

 private:
  MlDsaPublicKey public_key_;
  std::unique_ptr<MLDSA87_public_key> boringssl_public_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<Prehash>> MlDsa87PrehashBoringSsl::New(
    MlDsaPublicKey public_key) {
  auto status = CheckFipsCompatibility<MlDsa87PrehashBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (public_key.GetParameters().GetVariant() !=
      MlDsaParameters::Variant::kNoPrefixWithPrehashId) {
    return absl::InvalidArgumentError(
        "ML-DSA Prehash requires Variant::kNoPrefixWithPrehashId");
  }

  absl::string_view public_key_bytes =
      public_key.GetPublicKeyBytes(GetPartialKeyAccess());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key_bytes.data()),
           public_key_bytes.size());
  auto boringssl_public_key = std::make_unique<MLDSA87_public_key>();
  if (!MLDSA87_parse_public_key(boringssl_public_key.get(), &cbs)) {
    return absl::InvalidArgumentError("Invalid ML-DSA public key");
  }

  return std::make_unique<MlDsa87PrehashBoringSsl>(
      std::move(public_key), std::move(boringssl_public_key));
}

absl::StatusOr<std::string> MlDsa87PrehashBoringSsl::Compute(
    absl::string_view data) const {
  struct MLDSA87_prehash prehash_state;
  if (!MLDSA87_prehash_init(&prehash_state, boringssl_public_key_.get(),
                            /*context=*/nullptr, /*context_len=*/0)) {
    return absl::InternalError("MLDSA87_prehash_init failed.");
  }
  MLDSA87_prehash_update(&prehash_state,
                         reinterpret_cast<const uint8_t*>(data.data()),
                         data.size());
  std::string result = prehash_prefix_;
  size_t prefix_len = result.size();
  result.resize(prefix_len + MLDSA_MU_BYTES);
  MLDSA87_prehash_finalize(reinterpret_cast<uint8_t*>(&result[prefix_len]),
                           &prehash_state);
  return result;
}

#endif  // OPENSSL_IS_BORINGSSL

}  // namespace

absl::StatusOr<std::unique_ptr<Prehash>> NewMlDsaPrehashBoringSsl(
    MlDsaPublicKey public_key) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  switch (public_key.GetParameters().GetInstance()) {
    case MlDsaParameters::Instance::kMlDsa44:
      return MlDsa44PrehashBoringSsl::New(std::move(public_key));
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsa65PrehashBoringSsl::New(std::move(public_key));
    case MlDsaParameters::Instance::kMlDsa87:
      return MlDsa87PrehashBoringSsl::New(std::move(public_key));
    default:
      return absl::InvalidArgumentError(
          "Only ML-DSA-44, ML-DSA-65 and ML-DSA-87 are supported");
  }
#endif  // OPENSSL_IS_BORINGSSL
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
