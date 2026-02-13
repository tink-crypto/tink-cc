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

#include "tink/signature/internal/composite_ml_dsa_util_boringssl.h"

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/sha.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::string> GetCompositeMlDsaLabel(
    const CompositeMlDsaParameters& parameters) {
  std::string label = "COMPSIG-";
  switch (parameters.GetMlDsaInstance()) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65:
      absl::StrAppend(&label, "MLDSA65");
      break;
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87:
      absl::StrAppend(&label, "MLDSA87");
      break;
    default:
      return absl::InvalidArgumentError("MLDSA instance is not supported.");
  }
  absl::StrAppend(&label, "-");
  switch (parameters.GetClassicalAlgorithm()) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519:
      absl::StrAppend(&label, "Ed25519");
      break;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
      absl::StrAppend(&label, "ECDSA-P256");
      break;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
      absl::StrAppend(&label, "ECDSA-P384");
      break;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521:
      absl::StrAppend(&label, "ECDSA-P521");
      break;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
      absl::StrAppend(&label, "RSA3072-PSS");
      break;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss:
      absl::StrAppend(&label, "RSA4096-PSS");
      break;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
      absl::StrAppend(&label, "RSA3072-PKCS15");
      break;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1:
      absl::StrAppend(&label, "RSA4096-PKCS15");
      break;
    default:
      return absl::InvalidArgumentError(
          "Classical algorithm is not supported.");
  }
  // All of the currently supported classical algorithms use SHA512 as pre-hash.
  absl::StrAppend(&label, "-SHA512");
  return label;
}

std::string ComputeCompositeMlDsaMessagePrime(absl::string_view label,
                                              absl::string_view message) {
  // M' = Prefix || Label || len(ctx) || ctx || PH( M )
  const absl::string_view kPrefix = "CompositeAlgorithmSignatures2025";
  std::string prehash;
  subtle::ResizeStringUninitialized(&prehash, SHA512_DIGEST_LENGTH);
  SHA512(reinterpret_cast<const unsigned char*>(message.data()), message.size(),
         reinterpret_cast<unsigned char*>(prehash.data()));
  // Here len(ctx) is a single byte containing the length of the context.
  // Since we use an empty context, we set it to '\x00'.
  return absl::StrCat(kPrefix, label, absl::string_view("\x00", 1), prehash);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
