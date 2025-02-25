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

#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"

#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#else
#include "openssl/bn.h"
#endif
#include "tink/big_integer.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

constexpr int kF4 = 65537;

}  // namespace

JwtRsaSsaPssParameters::Builder&
JwtRsaSsaPssParameters::Builder::SetAlgorithm(Algorithm algorithm) {
  algorithm_ = algorithm;
  return *this;
}

JwtRsaSsaPssParameters::Builder&
JwtRsaSsaPssParameters::Builder::SetKidStrategy(KidStrategy kid_strategy) {
  kid_strategy_ = kid_strategy;
  return *this;
}

JwtRsaSsaPssParameters::Builder&
JwtRsaSsaPssParameters::Builder::SetModulusSizeInBits(
    int modulus_size_in_bits) {
  modulus_size_in_bits_ = modulus_size_in_bits;
  return *this;
}

JwtRsaSsaPssParameters::Builder&
JwtRsaSsaPssParameters::Builder::SetPublicExponent(
    const BigInteger& public_exponent) {
  public_exponent_ = public_exponent;
  return *this;
}

absl::StatusOr<JwtRsaSsaPssParameters>
JwtRsaSsaPssParameters::Builder::Build() {
  if (!algorithm_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Algorithm is not set.");
  }

  if (!kid_strategy_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Kid strategy is not set.");
  }

  if (!modulus_size_in_bits_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Key size is not set.");
  }

  // Validate modulus size.
  if (*modulus_size_in_bits_ < 2048) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid key size: must be at least 2048 bits, got ",
                     *modulus_size_in_bits_, " bits."));
  }

  // Validate the public exponent: public exponent needs to be odd, greater than
  // 65536 and (for consistency with BoringSSL), smaller that 32 bits.
  absl::Status exponent_status =
      internal::ValidateRsaPublicExponent(public_exponent_.GetValue());
  if (!exponent_status.ok()) {
    return exponent_status;
  }

  // Validate algorithm.
  static const auto kSupportedAlgorithms = new absl::flat_hash_set<Algorithm>(
      {Algorithm::kPs256, Algorithm::kPs384, Algorithm::kPs512});
  if (!kSupportedAlgorithms->contains(*algorithm_)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create JWT RSASSA-PSS parameters with unknown algorithm.");
  }

  // Validate kid strategy.
  static const auto kSupportedKidStrategies =
      new absl::flat_hash_set<KidStrategy>({KidStrategy::kBase64EncodedKeyId,
                                            KidStrategy::kIgnored,
                                            KidStrategy::kCustom});
  if (!kSupportedKidStrategies->contains(*kid_strategy_)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create JWT RSASSA-PSS parameters with unknown kid strategy.");
  }

  return JwtRsaSsaPssParameters(*algorithm_, *kid_strategy_,
                                  *modulus_size_in_bits_, public_exponent_);
}

bool JwtRsaSsaPssParameters::operator==(const Parameters& other) const {
  const JwtRsaSsaPssParameters* that =
      dynamic_cast<const JwtRsaSsaPssParameters*>(&other);
  if (that == nullptr) {
    return false;
  }

  return algorithm_ == that->algorithm_ &&
         kid_strategy_ == that->kid_strategy_ &&
         modulus_size_in_bits_ == that->modulus_size_in_bits_ &&
         public_exponent_ == that->public_exponent_;
}

// Returns the big endian encoded F4 value, which is the default value of the
// public exponent.
BigInteger JwtRsaSsaPssParameters::Builder::CreateDefaultPublicExponent() {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), kF4);

  std::string F4_string =
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).value();
  return BigInteger(F4_string);
}

}  // namespace tink
}  // namespace crypto
