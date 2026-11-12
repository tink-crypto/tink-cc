// Copyright 2026 Google LLC
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

#include "tink/signature/internal/ecdsa_prehash_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/digest.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/util.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/prehash_format.h"
#include "tink/signature/prehash.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::HashType> ToSubtleHashType(
    EcdsaParameters::HashType hash_type) {
  switch (hash_type) {
    case EcdsaParameters::HashType::kSha256:
      return subtle::HashType::SHA256;
    case EcdsaParameters::HashType::kSha384:
      return subtle::HashType::SHA384;
    case EcdsaParameters::HashType::kSha512:
      return subtle::HashType::SHA512;
    default:
      return absl::InvalidArgumentError(
          "Cannot convert ECDSA parameters hash type to subtle hash type.");
  }
}

class EcdsaPrehashBoringSsl : public Prehash {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  static absl::StatusOr<std::unique_ptr<Prehash>> New(
      const EcdsaPublicKey& public_key);

  absl::StatusOr<std::string> Compute(absl::string_view data) const override;

 private:
  explicit EcdsaPrehashBoringSsl(const EVP_MD* md, std::string prehash_prefix)
      : md_(md), prehash_prefix_(std::move(prehash_prefix)) {}

  const EVP_MD* md_;  // Owned by BoringSSL.
  std::string prehash_prefix_;
};

absl::StatusOr<std::unique_ptr<Prehash>> EcdsaPrehashBoringSsl::New(
    const EcdsaPublicKey& public_key) {
  ABSL_RETURN_IF_ERROR(CheckFipsCompatibility<EcdsaPrehashBoringSsl>());

  if (public_key.GetParameters().GetVariant() ==
      EcdsaParameters::Variant::kLegacy) {
    return absl::InvalidArgumentError(
        "Legacy variant is not supported for ECDSA Prehash.");
  }

  ABSL_ASSIGN_OR_RETURN(
      subtle::HashType hash_type,
      ToSubtleHashType(public_key.GetParameters().GetHashType()));
  ABSL_RETURN_IF_ERROR(internal::IsHashTypeSafeForSignature(hash_type));
  ABSL_ASSIGN_OR_RETURN(const EVP_MD* md,
                        internal::EvpHashFromHashType(hash_type));

  return absl::WrapUnique(new EcdsaPrehashBoringSsl(
      md, GetPrehashPrefix(public_key.GetIdRequirement())));
}

absl::StatusOr<std::string> EcdsaPrehashBoringSsl::Compute(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  unsigned int digest_size = 0;
  uint8_t digest[EVP_MAX_MD_SIZE];
  if (1 != EVP_Digest(data.data(), data.size(), digest, &digest_size, md_,
                      /*impl=*/nullptr)) {
    return absl::InternalError("Could not compute digest.");
  }
  return absl::StrCat(
      prehash_prefix_,
      absl::string_view(reinterpret_cast<const char*>(digest), digest_size));
}

}  // namespace

absl::StatusOr<std::unique_ptr<Prehash>> NewEcdsaPrehashBoringSsl(
    const EcdsaPublicKey& public_key) {
  return EcdsaPrehashBoringSsl::New(public_key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
