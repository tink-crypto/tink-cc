// Copyright 2026 Google LLC
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

#include "tink/signature/internal/composite_ml_dsa_key_creator.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/partial_key_access.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/internal/ecdsa_key_creator.h"
#include "tink/signature/internal/ed25519_key_creator.h"
#include "tink/signature/internal/ml_dsa_key_creator.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_key_creator.h"
#include "tink/signature/internal/rsa_ssa_pss_key_creator.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/signature_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateEd25519PrivateKey() {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateEd25519Key(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateEcdsaP256PrivateKey() {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateEcdsaKey(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateEcdsaP384PrivateKey() {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateEcdsaKey(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateEcdsaP521PrivateKey() {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP521)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateEcdsaKey(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateRsaPss3072PrivateKey() {
  // Uses 0x10001 exponent by default.
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateRsaSsaPssKey(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateRsaPss4096PrivateKey() {
  // Uses 0x10001 exponent by default.
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
          .SetSaltLengthInBytes(48)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateRsaSsaPssKey(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateRsa3072Pkcs1PrivateKey() {
  // Uses 0x10001 exponent by default.
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateRsaSsaPkcs1Key(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateRsa4096Pkcs1PrivateKey() {
  // Uses 0x10001 exponent by default.
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  return CreateRsaSsaPkcs1Key(*parameters, /*id_requirement=*/absl::nullopt);
}

absl::StatusOr<MlDsaPrivateKey> GenerateMlDsa65PrivateKey() {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  if (!parameters.ok()) {
    return parameters.status();
  }
  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> key =
      CreateMlDsaKey(*parameters, /*id_requirement=*/absl::nullopt);
  if (!key.ok()) {
    return key.status();
  }
  return MlDsaPrivateKey(**key);
}

absl::StatusOr<MlDsaPrivateKey> GenerateMlDsa87PrivateKey() {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kNoPrefix);
  if (!parameters.ok()) {
    return parameters.status();
  }
  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> key =
      CreateMlDsaKey(*parameters, /*id_requirement=*/absl::nullopt);
  if (!key.ok()) {
    return key.status();
  }
  return MlDsaPrivateKey(**key);
}

absl::StatusOr<MlDsaPrivateKey> GenerateMlDsaPrivateKey(
    CompositeMlDsaParameters::MlDsaInstance instance) {
  switch (instance) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65:
      return GenerateMlDsa65PrivateKey();
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87:
      return GenerateMlDsa87PrivateKey();
    default:
      return absl::InvalidArgumentError("Unsupported ML-DSA instance");
  }
}

absl::StatusOr<std::unique_ptr<SignaturePrivateKey>>
GenerateClassicalPrivateKey(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm) {
  switch (algorithm) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519:
      return GenerateEd25519PrivateKey();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
      return GenerateEcdsaP256PrivateKey();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
      return GenerateEcdsaP384PrivateKey();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521:
      return GenerateEcdsaP521PrivateKey();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
      return GenerateRsaPss3072PrivateKey();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss:
      return GenerateRsaPss4096PrivateKey();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
      return GenerateRsa3072Pkcs1PrivateKey();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1:
      return GenerateRsa4096Pkcs1PrivateKey();
    default:
      return absl::InvalidArgumentError("Unsupported classical algorithm");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<CompositeMlDsaPrivateKey>>
CreateCompositeMlDsaKey(const CompositeMlDsaParameters& params,
                        absl::optional<int> id_requirement) {
  absl::StatusOr<MlDsaPrivateKey> ml_dsa_private_key =
      GenerateMlDsaPrivateKey(params.GetMlDsaInstance());
  if (!ml_dsa_private_key.ok()) {
    return ml_dsa_private_key.status();
  }
  absl::StatusOr<std::unique_ptr<SignaturePrivateKey>> classical_private_key =
      GenerateClassicalPrivateKey(params.GetClassicalAlgorithm());
  if (!classical_private_key.ok()) {
    return classical_private_key.status();
  }
  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(params, *ml_dsa_private_key,
                                       std::move(*classical_private_key),
                                       id_requirement, GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }
  return std::make_unique<CompositeMlDsaPrivateKey>(*private_key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
