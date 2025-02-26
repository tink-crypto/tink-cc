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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/mldsa.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

class MlDsaSignBoringSsl : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const MlDsaPrivateKey& private_key);

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

  explicit MlDsaSignBoringSsl(
      MlDsaPrivateKey private_key,
      util::SecretUniquePtr<MLDSA65_private_key> boringssl_private_key)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)) {}

  MlDsaPrivateKey private_key_;
  util::SecretUniquePtr<MLDSA65_private_key> boringssl_private_key_;
};

absl::StatusOr<std::unique_ptr<PublicKeySign>> MlDsaSignBoringSsl::New(
    const MlDsaPrivateKey& private_key) {
  auto status = internal::CheckFipsCompatibility<MlDsaSignBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (private_key.GetPublicKey().GetParameters().GetInstance() !=
      MlDsaParameters::Instance::kMlDsa65) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-DSA-65 is supported");
  }

  absl::string_view private_seed_bytes =
      private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());

  auto boringssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();
  if (!MLDSA65_private_key_from_seed(
          boringssl_private_key.get(),
          reinterpret_cast<const uint8_t*>(private_seed_bytes.data()),
          private_seed_bytes.size())) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to expand ML-DSA private key from seed.");
  }

  return absl::make_unique<MlDsaSignBoringSsl>(
      std::move(private_key), std::move(boringssl_private_key));
}

absl::StatusOr<std::string> MlDsaSignBoringSsl::Sign(
    absl::string_view data) const {
  std::string signature(private_key_.GetOutputPrefix());
  subtle::ResizeStringUninitialized(
      &signature,
      MLDSA65_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size());

  if (!MLDSA65_sign(
          reinterpret_cast<uint8_t*>(&signature[0] +
                                     private_key_.GetOutputPrefix().size()),
          boringssl_private_key_.get(),
          reinterpret_cast<const uint8_t*>(data.data()), data.size(),
          /* context = */ nullptr, /* context_len = */ 0)) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to generate ML-DSA signature.");
  }

  return signature;
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewMlDsaSignBoringSsl(
    MlDsaPrivateKey private_key) {
  return MlDsaSignBoringSsl::New(std::move(private_key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
