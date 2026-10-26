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

#include "tink/signature/internal/ml_dsa_chunked_prehash_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/bytestring.h"
#include "openssl/crypto.h"
#include "openssl/mldsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/signature/chunked_prehash.h"
#include "tink/signature/internal/prehash_format.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

// BoringSSL aborts if a prehash state is updated after it has been finalized,
// so computations must not be used after `GetPrehash()` has been called.
constexpr absl::string_view kAlreadyFinalizedError =
    "Chunked prehash already finalized.";

class MlDsa44ChunkedPrehashComputationBoringSsl
    : public ChunkedPrehashComputation {
 public:
  static absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> New(
      const MLDSA44_public_key& boringssl_public_key,
      absl::string_view prehash_prefix);

  absl::Status Update(absl::string_view data) override;

  absl::StatusOr<std::string> GetPrehash() override;

 private:
  explicit MlDsa44ChunkedPrehashComputationBoringSsl(
      absl::string_view prehash_prefix)
      : prehash_prefix_(prehash_prefix) {}

  MLDSA44_prehash prehash_state_;
  std::string prehash_prefix_;
  bool finalized_ = false;
};

absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
MlDsa44ChunkedPrehashComputationBoringSsl::New(
    const MLDSA44_public_key& boringssl_public_key,
    absl::string_view prehash_prefix) {
  std::unique_ptr<MlDsa44ChunkedPrehashComputationBoringSsl> computation =
      absl::WrapUnique(
          new MlDsa44ChunkedPrehashComputationBoringSsl(prehash_prefix));
  if (!MLDSA44_prehash_init(&computation->prehash_state_, &boringssl_public_key,
                            /*context=*/nullptr, /*context_len=*/0)) {
    return absl::InternalError("MLDSA44_prehash_init failed.");
  }
  return computation;
}

absl::Status MlDsa44ChunkedPrehashComputationBoringSsl::Update(
    absl::string_view data) {
  if (finalized_) {
    return absl::FailedPreconditionError(kAlreadyFinalizedError);
  }
  MLDSA44_prehash_update(&prehash_state_,
                         reinterpret_cast<const uint8_t*>(data.data()),
                         data.size());
  return absl::OkStatus();
}

absl::StatusOr<std::string>
MlDsa44ChunkedPrehashComputationBoringSsl::GetPrehash() {
  if (finalized_) {
    return absl::FailedPreconditionError(kAlreadyFinalizedError);
  }
  finalized_ = true;
  std::string result = prehash_prefix_;
  size_t prefix_len = result.size();
  result.resize(prefix_len + MLDSA_MU_BYTES);
  MLDSA44_prehash_finalize(reinterpret_cast<uint8_t*>(&result[prefix_len]),
                           &prehash_state_);
  return result;
}

class MlDsa44ChunkedPrehashBoringSsl : public ChunkedPrehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus
      [[maybe_unused]] =
          crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  static absl::StatusOr<std::unique_ptr<ChunkedPrehash>> New(
      const MlDsaPublicKey& public_key);

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> CreateComputation()
      const override;

 private:
  MlDsa44ChunkedPrehashBoringSsl(
      std::unique_ptr<MLDSA44_public_key> boringssl_public_key,
      std::string prehash_prefix)
      : boringssl_public_key_(std::move(boringssl_public_key)),
        prehash_prefix_(std::move(prehash_prefix)) {}

  std::unique_ptr<MLDSA44_public_key> boringssl_public_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<ChunkedPrehash>>
MlDsa44ChunkedPrehashBoringSsl::New(const MlDsaPublicKey& public_key) {
  absl::Status status =
      CheckFipsCompatibility<MlDsa44ChunkedPrehashBoringSsl>();
  if (!status.ok()) {
    return status;
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

  return absl::WrapUnique(new MlDsa44ChunkedPrehashBoringSsl(
      std::move(boringssl_public_key),
      GetPrehashPrefix(public_key.GetIdRequirement())));
}

absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
MlDsa44ChunkedPrehashBoringSsl::CreateComputation() const {
  return MlDsa44ChunkedPrehashComputationBoringSsl::New(*boringssl_public_key_,
                                                        prehash_prefix_);
}

class MlDsa65ChunkedPrehashComputationBoringSsl
    : public ChunkedPrehashComputation {
 public:
  static absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> New(
      const MLDSA65_public_key& boringssl_public_key,
      absl::string_view prehash_prefix);

  absl::Status Update(absl::string_view data) override;

  absl::StatusOr<std::string> GetPrehash() override;

 private:
  explicit MlDsa65ChunkedPrehashComputationBoringSsl(
      absl::string_view prehash_prefix)
      : prehash_prefix_(prehash_prefix) {}

  MLDSA65_prehash prehash_state_;
  std::string prehash_prefix_;
  bool finalized_ = false;
};

absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
MlDsa65ChunkedPrehashComputationBoringSsl::New(
    const MLDSA65_public_key& boringssl_public_key,
    absl::string_view prehash_prefix) {
  std::unique_ptr<MlDsa65ChunkedPrehashComputationBoringSsl> computation =
      absl::WrapUnique(
          new MlDsa65ChunkedPrehashComputationBoringSsl(prehash_prefix));
  if (!MLDSA65_prehash_init(&computation->prehash_state_, &boringssl_public_key,
                            /*context=*/nullptr, /*context_len=*/0)) {
    return absl::InternalError("MLDSA65_prehash_init failed.");
  }
  return computation;
}

absl::Status MlDsa65ChunkedPrehashComputationBoringSsl::Update(
    absl::string_view data) {
  if (finalized_) {
    return absl::FailedPreconditionError(kAlreadyFinalizedError);
  }
  MLDSA65_prehash_update(&prehash_state_,
                         reinterpret_cast<const uint8_t*>(data.data()),
                         data.size());
  return absl::OkStatus();
}

absl::StatusOr<std::string>
MlDsa65ChunkedPrehashComputationBoringSsl::GetPrehash() {
  if (finalized_) {
    return absl::FailedPreconditionError(kAlreadyFinalizedError);
  }
  finalized_ = true;
  std::string result = prehash_prefix_;
  size_t prefix_len = result.size();
  result.resize(prefix_len + MLDSA_MU_BYTES);
  MLDSA65_prehash_finalize(reinterpret_cast<uint8_t*>(&result[prefix_len]),
                           &prehash_state_);
  return result;
}

class MlDsa65ChunkedPrehashBoringSsl : public ChunkedPrehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus
      [[maybe_unused]] =
          crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  static absl::StatusOr<std::unique_ptr<ChunkedPrehash>> New(
      const MlDsaPublicKey& public_key);

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> CreateComputation()
      const override;

 private:
  MlDsa65ChunkedPrehashBoringSsl(
      std::unique_ptr<MLDSA65_public_key> boringssl_public_key,
      std::string prehash_prefix)
      : boringssl_public_key_(std::move(boringssl_public_key)),
        prehash_prefix_(std::move(prehash_prefix)) {}

  std::unique_ptr<MLDSA65_public_key> boringssl_public_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<ChunkedPrehash>>
MlDsa65ChunkedPrehashBoringSsl::New(const MlDsaPublicKey& public_key) {
  absl::Status status =
      CheckFipsCompatibility<MlDsa65ChunkedPrehashBoringSsl>();
  if (!status.ok()) {
    return status;
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

  return absl::WrapUnique(new MlDsa65ChunkedPrehashBoringSsl(
      std::move(boringssl_public_key),
      GetPrehashPrefix(public_key.GetIdRequirement())));
}

absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
MlDsa65ChunkedPrehashBoringSsl::CreateComputation() const {
  return MlDsa65ChunkedPrehashComputationBoringSsl::New(*boringssl_public_key_,
                                                        prehash_prefix_);
}

class MlDsa87ChunkedPrehashComputationBoringSsl
    : public ChunkedPrehashComputation {
 public:
  static absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> New(
      const MLDSA87_public_key& boringssl_public_key,
      absl::string_view prehash_prefix);

  absl::Status Update(absl::string_view data) override;

  absl::StatusOr<std::string> GetPrehash() override;

 private:
  explicit MlDsa87ChunkedPrehashComputationBoringSsl(
      absl::string_view prehash_prefix)
      : prehash_prefix_(prehash_prefix) {}

  MLDSA87_prehash prehash_state_;
  std::string prehash_prefix_;
  bool finalized_ = false;
};

absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
MlDsa87ChunkedPrehashComputationBoringSsl::New(
    const MLDSA87_public_key& boringssl_public_key,
    absl::string_view prehash_prefix) {
  std::unique_ptr<MlDsa87ChunkedPrehashComputationBoringSsl> computation =
      absl::WrapUnique(
          new MlDsa87ChunkedPrehashComputationBoringSsl(prehash_prefix));
  if (!MLDSA87_prehash_init(&computation->prehash_state_, &boringssl_public_key,
                            /*context=*/nullptr, /*context_len=*/0)) {
    return absl::InternalError("MLDSA87_prehash_init failed.");
  }
  return computation;
}

absl::Status MlDsa87ChunkedPrehashComputationBoringSsl::Update(
    absl::string_view data) {
  if (finalized_) {
    return absl::FailedPreconditionError(kAlreadyFinalizedError);
  }
  MLDSA87_prehash_update(&prehash_state_,
                         reinterpret_cast<const uint8_t*>(data.data()),
                         data.size());
  return absl::OkStatus();
}

absl::StatusOr<std::string>
MlDsa87ChunkedPrehashComputationBoringSsl::GetPrehash() {
  if (finalized_) {
    return absl::FailedPreconditionError(kAlreadyFinalizedError);
  }
  finalized_ = true;
  std::string result = prehash_prefix_;
  size_t prefix_len = result.size();
  result.resize(prefix_len + MLDSA_MU_BYTES);
  MLDSA87_prehash_finalize(reinterpret_cast<uint8_t*>(&result[prefix_len]),
                           &prehash_state_);
  return result;
}

class MlDsa87ChunkedPrehashBoringSsl : public ChunkedPrehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus
      [[maybe_unused]] =
          crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  static absl::StatusOr<std::unique_ptr<ChunkedPrehash>> New(
      const MlDsaPublicKey& public_key);

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> CreateComputation()
      const override;

 private:
  MlDsa87ChunkedPrehashBoringSsl(
      std::unique_ptr<MLDSA87_public_key> boringssl_public_key,
      std::string prehash_prefix)
      : boringssl_public_key_(std::move(boringssl_public_key)),
        prehash_prefix_(std::move(prehash_prefix)) {}

  std::unique_ptr<MLDSA87_public_key> boringssl_public_key_;
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<ChunkedPrehash>>
MlDsa87ChunkedPrehashBoringSsl::New(const MlDsaPublicKey& public_key) {
  absl::Status status =
      CheckFipsCompatibility<MlDsa87ChunkedPrehashBoringSsl>();
  if (!status.ok()) {
    return status;
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

  return absl::WrapUnique(new MlDsa87ChunkedPrehashBoringSsl(
      std::move(boringssl_public_key),
      GetPrehashPrefix(public_key.GetIdRequirement())));
}

absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
MlDsa87ChunkedPrehashBoringSsl::CreateComputation() const {
  return MlDsa87ChunkedPrehashComputationBoringSsl::New(*boringssl_public_key_,
                                                        prehash_prefix_);
}

}  // namespace

absl::StatusOr<std::unique_ptr<ChunkedPrehash>> NewMlDsaChunkedPrehashBoringSsl(
    const MlDsaPublicKey& public_key) {
  switch (public_key.GetParameters().GetInstance()) {
    case MlDsaParameters::Instance::kMlDsa44:
      return MlDsa44ChunkedPrehashBoringSsl::New(public_key);
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsa65ChunkedPrehashBoringSsl::New(public_key);
    case MlDsaParameters::Instance::kMlDsa87:
      return MlDsa87ChunkedPrehashBoringSsl::New(public_key);
    default:
      return absl::InvalidArgumentError(
          "Only ML-DSA-44, ML-DSA-65 and ML-DSA-87 are supported");
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
