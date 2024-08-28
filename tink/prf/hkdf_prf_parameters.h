// Copyright 2024 Google LLC
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

#ifndef TINK_PRF_HKDF_PRF_PARAMETERS_H_
#define TINK_PRF_HKDF_PRF_PARAMETERS_H_

#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/parameters.h"
#include "tink/prf/prf_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `HkdfPrfKey`.
class HkdfPrfParameters : public PrfParameters {
 public:
  // Describes the hash algorithm used.
  enum class HashType : int {
    kSha1 = 1,
    kSha224 = 2,
    kSha256 = 3,
    kSha384 = 4,
    kSha512 = 5,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  HkdfPrfParameters(const HkdfPrfParameters& other) = default;
  HkdfPrfParameters& operator=(const HkdfPrfParameters& other) = default;
  HkdfPrfParameters(HkdfPrfParameters&& other) = default;
  HkdfPrfParameters& operator=(HkdfPrfParameters&& other) = default;

  // Creates an HKDF-PRF parameters object.
  //
  // Key size must be at least 16 bytes. As of RFC5869, the salt is optional;
  // if `salt` is `absl::nullopt` or an empty string, it will be set to a string
  // of HashLen zeros in the algorithm implementation.
  static util::StatusOr<HkdfPrfParameters> Create(
      int key_size_in_bytes, HashType hash_type,
      absl::optional<absl::string_view> salt);

  int KeySizeInBytes() const { return key_size_in_bytes_; }

  HashType GetHashType() const { return hash_type_; }

  absl::optional<absl::string_view> GetSalt() const { return salt_; }

  bool operator==(const Parameters& other) const override;

 private:
  explicit HkdfPrfParameters(int key_size_in_bytes, HashType hash_type,
                             absl::optional<absl::string_view> salt)
      : key_size_in_bytes_(key_size_in_bytes),
        hash_type_(hash_type),
        salt_(std::move(salt)) {
    // If salt is an empty string, default to absl::nullopt
    if (salt_.has_value() && salt_->empty()) {
      salt_ = absl::nullopt;
    }
  }

  int key_size_in_bytes_;
  HashType hash_type_;
  absl::optional<std::string> salt_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_HKDF_PRF_PARAMETERS_H_
