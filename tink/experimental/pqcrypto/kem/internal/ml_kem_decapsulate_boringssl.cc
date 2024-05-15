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

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_decapsulate_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/experimental/kyber.h"
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

class MlKemDecapsulateBoringSsl : public RawKemDecapsulate {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static util::StatusOr<std::unique_ptr<RawKemDecapsulate>> New(
      MlKemPrivateKey recipient_key);

  util::StatusOr<RestrictedData> Decapsulate(
      absl::string_view ciphertext) const override;

  explicit MlKemDecapsulateBoringSsl(
      MlKemPrivateKey private_key,
      util::SecretUniquePtr<KYBER_private_key> boringssl_private_key)
      : private_key_(std::move(private_key)),
        boringssl_private_key_(std::move(boringssl_private_key)) {}

  MlKemPrivateKey private_key_;
  util::SecretUniquePtr<KYBER_private_key> boringssl_private_key_;
};

util::StatusOr<std::unique_ptr<RawKemDecapsulate>>
MlKemDecapsulateBoringSsl::New(MlKemPrivateKey recipient_key) {
  auto status = CheckFipsCompatibility<MlKemDecapsulateBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (recipient_key.GetPublicKey().GetParameters().GetKeySize() != 768) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-KEM 768 is supported");
  }

  absl::string_view private_key_bytes =
      recipient_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(private_key_bytes.data()),
           private_key_bytes.size());
  auto private_key = util::MakeSecretUniquePtr<KYBER_private_key>();
  if (!KYBER_parse_private_key(private_key.get(), &cbs)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Invalid ML-KEM private key.");
  }

  return absl::make_unique<MlKemDecapsulateBoringSsl>(std::move(recipient_key),
                                                      std::move(private_key));
}

util::StatusOr<RestrictedData> MlKemDecapsulateBoringSsl::Decapsulate(
    absl::string_view ciphertext) const {
  size_t output_prefix_size = private_key_.GetOutputPrefix().size();

  if (ciphertext.size() != KYBER_CIPHERTEXT_BYTES + output_prefix_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Decapsulation failed: incorrect ciphertext size for ML-KEM");
  }

  if (!absl::StartsWith(ciphertext, private_key_.GetOutputPrefix())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Decapsulation failed: invalid output prefix");
  }

  util::SecretData shared_secret(KYBER_SHARED_SECRET_BYTES);
  KYBER_decap(shared_secret.data(),
              reinterpret_cast<const uint8_t*>(&ciphertext[output_prefix_size]),
              boringssl_private_key_.get());

  return RestrictedData(shared_secret, InsecureSecretKeyAccess::Get());
}

}  // namespace

util::StatusOr<std::unique_ptr<RawKemDecapsulate>> NewMlKemDecapsulateBoringSsl(
    MlKemPrivateKey recipient_key) {
  return MlKemDecapsulateBoringSsl::New(std::move(recipient_key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
