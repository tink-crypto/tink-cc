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

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/experimental/kyber.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/kem/internal/raw_kem_encapsulate.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

class MlKemEncapsulateBoringSsl : public RawKemEncapsulate {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static util::StatusOr<std::unique_ptr<RawKemEncapsulate>> New(
      MlKemPublicKey recipient_key);

  util::StatusOr<RawKemEncapsulation> Encapsulate() const override;

  explicit MlKemEncapsulateBoringSsl(
      MlKemPublicKey public_key,
      std::unique_ptr<KYBER_public_key> boringssl_public_key)
      : public_key_(std::move(public_key)),
        boringssl_public_key_(std::move(boringssl_public_key)) {}

  MlKemPublicKey public_key_;
  std::unique_ptr<KYBER_public_key> boringssl_public_key_;
};

util::StatusOr<std::unique_ptr<RawKemEncapsulate>>
MlKemEncapsulateBoringSsl::New(MlKemPublicKey recipient_key) {
  auto status = CheckFipsCompatibility<MlKemEncapsulateBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  if (recipient_key.GetParameters().GetKeySize() != 768) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-KEM 768 is supported");
  }

  absl::string_view public_key_bytes =
      recipient_key.GetPublicKeyBytes(GetPartialKeyAccess());

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key_bytes.data()),
           public_key_bytes.size());
  auto public_key = std::make_unique<KYBER_public_key>();
  if (!KYBER_parse_public_key(public_key.get(), &cbs)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Invalid ML-KEM public key");
  }

  return absl::make_unique<MlKemEncapsulateBoringSsl>(std::move(recipient_key),
                                                      std::move(public_key));
}

util::StatusOr<RawKemEncapsulation> MlKemEncapsulateBoringSsl::Encapsulate()
    const {
  size_t output_prefix_size = public_key_.GetOutputPrefix().size();

  // The ciphertext will be prepended with the output prefix for TINK keys.
  std::string ciphertext(public_key_.GetOutputPrefix());
  subtle::ResizeStringUninitialized(
      &ciphertext, output_prefix_size + KYBER_CIPHERTEXT_BYTES);

  util::SecretData shared_secret(KYBER_SHARED_SECRET_BYTES);
  KYBER_encap(reinterpret_cast<uint8_t*>(&ciphertext[output_prefix_size]),
              shared_secret.data(), boringssl_public_key_.get());

  return RawKemEncapsulation{
      std::move(ciphertext),
      RestrictedData(shared_secret, InsecureSecretKeyAccess::Get()),
  };
}

}  // namespace

util::StatusOr<std::unique_ptr<RawKemEncapsulate>> NewMlKemEncapsulateBoringSsl(
    MlKemPublicKey recipient_key) {
  return MlKemEncapsulateBoringSsl::New(std::move(recipient_key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
