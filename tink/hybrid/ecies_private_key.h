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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_HYBRID_ECIES_PRIVATE_KEY_H_
#define TINK_HYBRID_ECIES_PRIVATE_KEY_H_

#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/hybrid/hybrid_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {

// Representation of the decryption function for an ECIES hybrid encryption
// primitive.
class EciesPrivateKey final : public HybridPrivateKey {
 public:
  // Copyable and movable.
  EciesPrivateKey(const EciesPrivateKey& other)
      : public_key_(other.public_key_),
        private_key_bytes_(other.private_key_bytes_) {
    absl::MutexLock lock(other.mutex_);

    private_key_value_big_integer_ = other.private_key_value_big_integer_;
  }

  EciesPrivateKey& operator=(const EciesPrivateKey& other) {
    if (this == &other) {
      return *this;
    }

    absl::optional<RestrictedBigInteger> tmp_private_key_value_big_integer;
    {
      absl::MutexLock lock(other.mutex_);
      tmp_private_key_value_big_integer = other.private_key_value_big_integer_;
    }

    public_key_ = other.public_key_;
    private_key_bytes_ = other.private_key_bytes_;
    absl::MutexLock lock(mutex_);
    private_key_value_big_integer_ = tmp_private_key_value_big_integer;

    return *this;
  }

  EciesPrivateKey(EciesPrivateKey&& other) = default;
  EciesPrivateKey& operator=(EciesPrivateKey&& other) = default;

  static absl::StatusOr<EciesPrivateKey> CreateForNistCurve(
      const EciesPublicKey& public_key,
      const RestrictedBigInteger& private_key_value,
      PartialKeyAccessToken token);

  // Creates a new EciesPrivateKey for a nist curve. Will return an error
  // if private_key_value is not of length
  // public_key.GetParameters().GetPrivateKeyLength()
  static absl::StatusOr<EciesPrivateKey> CreateForNistCurve(
      const EciesPublicKey& public_key, const RestrictedData& private_key_value,
      PartialKeyAccessToken token);

  // Pads private_key_value to GetPrivateKeyLength() if needed,
  // truncates leading zeros if needed.
  static absl::StatusOr<EciesPrivateKey> CreateForNistCurveAllowNonConstantTime(
      const EciesPublicKey& public_key, const RestrictedData& private_key_value,
      PartialKeyAccessToken token);

  static absl::StatusOr<EciesPrivateKey> CreateForCurveX25519(
      const EciesPublicKey& public_key, const RestrictedData& private_key_bytes,
      PartialKeyAccessToken token);

  absl::optional<RestrictedBigInteger> GetNistPrivateKeyValue(
      PartialKeyAccessToken token) const;

  absl::optional<RestrictedData> GetX25519PrivateKeyBytes(
      PartialKeyAccessToken token) const {
    switch (public_key_.GetParameters().GetCurveType()) {
      case EciesParameters::CurveType::kX25519:
        return private_key_bytes_;
      default:
        return absl::nullopt;
    }
  }

  // Returns the bytes of length GetParameters().GetPrivateKeyLength()
  // or null opt for X25519 keys.
  absl::optional<RestrictedData> GetNistPrivateKeyBytes(
      PartialKeyAccessToken token) const {
    switch (public_key_.GetParameters().GetCurveType()) {
      case EciesParameters::CurveType::kNistP256:
      case EciesParameters::CurveType::kNistP384:
      case EciesParameters::CurveType::kNistP521:
        return private_key_bytes_;
      default:
        return absl::nullopt;
    }
  }
  const EciesPublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<EciesPrivateKey>(*this);
  }

 private:
  // Creates a NIST curve-based ECIES private key.
  explicit EciesPrivateKey(const EciesPublicKey& public_key,
                           const RestrictedData& private_key_value)
      : public_key_(public_key), private_key_bytes_(private_key_value) {}

  EciesPublicKey public_key_;
  absl::optional<RestrictedData> private_key_bytes_;

  mutable absl::Mutex mutex_;
  mutable absl::optional<RestrictedBigInteger> private_key_value_big_integer_
      ABSL_GUARDED_BY(mutex_);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_PRIVATE_KEY_H_
