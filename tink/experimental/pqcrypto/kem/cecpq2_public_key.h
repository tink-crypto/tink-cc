// Copyright 2025 Google LLC
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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PUBLIC_KEY_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PUBLIC_KEY_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/hybrid/hybrid_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"

namespace crypto {
namespace tink {

// Representation of the encryption function of a CECPQ2 hybrid encryption
// primitive.
class Cecpq2PublicKey final : public HybridPublicKey {
 public:
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    Builder() = default;

    Builder& SetParameters(const Cecpq2Parameters& parameters);
    Builder& SetX25519PublicKeyBytes(absl::string_view x25519_public_key_bytes);
    Builder& SetHrssPublicKeyBytes(absl::string_view hrss_public_key_bytes);
    Builder& SetIdRequirement(int32_t id);

    absl::StatusOr<Cecpq2PublicKey> Build(PartialKeyAccessToken token);

   private:
    absl::optional<Cecpq2Parameters> parameters_ = absl::nullopt;
    absl::optional<std::string> x25519_public_key_bytes_ = absl::nullopt;
    absl::optional<std::string> hrss_public_key_bytes_ = absl::nullopt;
    absl::optional<int32_t> id_requirement_ = absl::nullopt;
  };

  // Copyable and movable.
  Cecpq2PublicKey(const Cecpq2PublicKey& other) = default;
  Cecpq2PublicKey& operator=(const Cecpq2PublicKey& other) = default;
  Cecpq2PublicKey(Cecpq2PublicKey&& other) = default;
  Cecpq2PublicKey& operator=(Cecpq2PublicKey&& other) = default;

  const Cecpq2Parameters& GetParameters() const override { return parameters_; }

  absl::string_view GetX25519PublicKeyBytes(PartialKeyAccessToken token) const {
    return x25519_public_key_bytes_;
  }

  absl::string_view GetHrssPublicKeyBytes(PartialKeyAccessToken token) const {
    return hrss_public_key_bytes_;
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  absl::string_view GetOutputPrefix() const override { return output_prefix_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<Cecpq2PublicKey>(*this);
  }

 private:
  explicit Cecpq2PublicKey(const Cecpq2Parameters& parameters,
                           absl::string_view x25519_public_key_bytes,
                           absl::string_view hrss_public_key_bytes,
                           absl::optional<int> id_requirement,
                           absl::string_view output_prefix)
      : parameters_(parameters),
        x25519_public_key_bytes_(x25519_public_key_bytes),
        hrss_public_key_bytes_(hrss_public_key_bytes),
        id_requirement_(id_requirement),
        output_prefix_(output_prefix) {}

  Cecpq2Parameters parameters_;
  std::string x25519_public_key_bytes_;
  std::string hrss_public_key_bytes_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PUBLIC_KEY_H_
