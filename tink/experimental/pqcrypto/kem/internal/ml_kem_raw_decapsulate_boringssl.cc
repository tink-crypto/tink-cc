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

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_raw_decapsulate_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/mlkem.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/kem/internal/raw_kem_decapsulate.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

class MlKemRawDecapsulateBoringSsl : public RawKemDecapsulate {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static util::StatusOr<std::unique_ptr<RawKemDecapsulate>> New(
      MlKemPrivateKey recipient_key);

  util::StatusOr<RestrictedData> Decapsulate(
      absl::string_view ciphertext) const override;

  explicit MlKemRawDecapsulateBoringSsl(
      MlKemPrivateKey private_key,
      util::SecretUniquePtr<MLKEM768_private_key> boringssl_private_key)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)) {}

  MlKemPrivateKey private_key_;
  util::SecretUniquePtr<MLKEM768_private_key> boringssl_private_key_;
};

util::StatusOr<std::unique_ptr<RawKemDecapsulate>>
MlKemRawDecapsulateBoringSsl::New(MlKemPrivateKey recipient_key) {
  util::Status status = CheckFipsCompatibility<MlKemRawDecapsulateBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (recipient_key.GetPublicKey().GetParameters().GetKeySize() != 768) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-KEM 768 is supported");
  }

  absl::string_view private_seed_bytes =
      recipient_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());

  auto boringssl_private_key =
      util::MakeSecretUniquePtr<MLKEM768_private_key>();
  if (!MLKEM768_private_key_from_seed(
          boringssl_private_key.get(),
          reinterpret_cast<const uint8_t*>(private_seed_bytes.data()),
          private_seed_bytes.size())) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to expand ML-KEM private key from seed.");
  }

  return absl::make_unique<MlKemRawDecapsulateBoringSsl>(
      std::move(recipient_key), std::move(boringssl_private_key));
}

util::StatusOr<RestrictedData> MlKemRawDecapsulateBoringSsl::Decapsulate(
    absl::string_view ciphertext) const {
  size_t output_prefix_size = private_key_.GetOutputPrefix().size();

  if (ciphertext.size() != MLKEM768_CIPHERTEXT_BYTES + output_prefix_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Decapsulation failed: incorrect ciphertext size for ML-KEM");
  }

  if (!absl::StartsWith(ciphertext, private_key_.GetOutputPrefix())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Decapsulation failed: invalid output prefix");
  }

  util::SecretData shared_secret(MLKEM_SHARED_SECRET_BYTES);
  MLKEM768_decap(
      shared_secret.data(),
      reinterpret_cast<const uint8_t*>(&ciphertext[output_prefix_size]),
      MLKEM768_CIPHERTEXT_BYTES, boringssl_private_key_.get());

  return RestrictedData(shared_secret, InsecureSecretKeyAccess::Get());
}

}  // namespace

util::StatusOr<std::unique_ptr<RawKemDecapsulate>>
NewMlKemRawDecapsulateBoringSsl(MlKemPrivateKey recipient_key) {
  return MlKemRawDecapsulateBoringSsl::New(std::move(recipient_key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
