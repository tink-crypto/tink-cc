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

#include "tink/signature/composite_ml_dsa_public_key.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/signature_parameters.h"
#include "tink/signature/signature_public_key.h"

namespace crypto {
namespace tink {
namespace {

template <typename T>
const T* CreateNewForInstance(const absl::StatusOr<T>& instance) {
  ABSL_CHECK(instance.ok());
  return new T(instance.value());
}

absl::flat_hash_map<CompositeMlDsaParameters::MlDsaInstance,
                    const SignatureParameters*>
CreateMlDsaInstanceMap() {
  return {{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
           CreateNewForInstance(
               MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                                       MlDsaParameters::Variant::kNoPrefix))},
          {CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
           CreateNewForInstance(
               MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                                       MlDsaParameters::Variant::kNoPrefix))}};
}

absl::flat_hash_map<CompositeMlDsaParameters::ClassicalAlgorithm,
                    const SignatureParameters*>
CreateClassicalAlgorithmMap() {
  return {
      // Ed25519 is unambiguous.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
       CreateNewForInstance(
           Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix))},
      // Requires ecdsa-with-SHA256.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
       CreateNewForInstance(
           EcdsaParameters::Builder()
               .SetCurveType(EcdsaParameters::CurveType::kNistP256)
               .SetHashType(EcdsaParameters::HashType::kSha256)
               .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
               .SetVariant(EcdsaParameters::Variant::kNoPrefix)
               .Build())},
      // Requires ecdsa-with-SHA384.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
       CreateNewForInstance(
           EcdsaParameters::Builder()
               .SetCurveType(EcdsaParameters::CurveType::kNistP384)
               .SetHashType(EcdsaParameters::HashType::kSha384)
               .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
               .SetVariant(EcdsaParameters::Variant::kNoPrefix)
               .Build())},
      // Requires ecdsa-with-SHA512.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
       CreateNewForInstance(
           EcdsaParameters::Builder()
               .SetCurveType(EcdsaParameters::CurveType::kNistP521)
               .SetHashType(EcdsaParameters::HashType::kSha512)
               .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
               .SetVariant(EcdsaParameters::Variant::kNoPrefix)
               .Build())},
      // Requires id-sha256 with salt length 32.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
       CreateNewForInstance(
           RsaSsaPssParameters::Builder()
               .SetModulusSizeInBits(3072)
               .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
               .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
               .SetSaltLengthInBytes(32)
               .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
               .Build())},
      // Requires id-sha384 with salt length 48.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
       CreateNewForInstance(
           RsaSsaPssParameters::Builder()
               .SetModulusSizeInBits(4096)
               .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
               .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
               .SetSaltLengthInBytes(48)
               .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
               .Build())},
      // Requires sha256WithRSAEncryption.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
       CreateNewForInstance(
           RsaSsaPkcs1Parameters::Builder()
               .SetModulusSizeInBits(3072)
               .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
               .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
               .Build())},
      // Requires sha384WithRSAEncryption.
      {CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
       CreateNewForInstance(
           RsaSsaPkcs1Parameters::Builder()
               .SetModulusSizeInBits(4096)
               .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
               .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
               .Build())}};
}

// Returns ML-DSA parameters according to
// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14#section-6.
// Note that the parameters are all of the kNoPrefix variant.
absl::StatusOr<const SignatureParameters*> GetParametersForMlDsaInstance(
    CompositeMlDsaParameters::MlDsaInstance ml_dsa_instance) {
  static const absl::NoDestructor<absl::flat_hash_map<
      CompositeMlDsaParameters::MlDsaInstance, const SignatureParameters*>>
      kMlDsaInstanceToParameters(CreateMlDsaInstanceMap());
  auto it = kMlDsaInstanceToParameters->find(ml_dsa_instance);
  if (it == kMlDsaInstanceToParameters->end()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Unsupported ML-DSA instance.");
  }
  return it->second;
}

// Returns classical parameters according to
// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14#section-6.
// Note that the parameters are all of the kNoPrefix variant.
absl::StatusOr<const SignatureParameters*> GetParametersForClassicalAlgorithm(
    CompositeMlDsaParameters::ClassicalAlgorithm classical_algorithm) {
  static const absl::NoDestructor<absl::flat_hash_map<
      CompositeMlDsaParameters::ClassicalAlgorithm, const SignatureParameters*>>
      kClassicalAlgorithmToParameters(CreateClassicalAlgorithmMap());
  auto it = kClassicalAlgorithmToParameters->find(classical_algorithm);
  if (it == kClassicalAlgorithmToParameters->end()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Unsupported classical algorithm.");
  }
  return it->second;
}

absl::StatusOr<std::string> ComputeOutputPrefix(
    const CompositeMlDsaParameters& parameters,
    absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case CompositeMlDsaParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case CompositeMlDsaParameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must have value with kTink");
      }
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid variant: ", parameters.GetVariant()));
  }
}

}  // namespace

CompositeMlDsaPublicKey::CompositeMlDsaPublicKey(
    const CompositeMlDsaPublicKey& other)
    : parameters_(other.parameters_),
      ml_dsa_public_key_(other.ml_dsa_public_key_),
      id_requirement_(other.id_requirement_),
      output_prefix_(other.output_prefix_) {
  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          *other.classical_public_key_);
  classical_public_key_ = std::move(classical_public_key_clone);
}

CompositeMlDsaPublicKey& CompositeMlDsaPublicKey::operator=(
    const CompositeMlDsaPublicKey& other) {
  if (this == &other) {
    return *this;
  }
  parameters_ = other.parameters_;
  ml_dsa_public_key_ = other.ml_dsa_public_key_;
  id_requirement_ = other.id_requirement_;
  output_prefix_ = other.output_prefix_;
  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          *other.classical_public_key_);
  classical_public_key_ = std::move(classical_public_key_clone);
  return *this;
}

absl::StatusOr<CompositeMlDsaPublicKey> CompositeMlDsaPublicKey::Create(
    const CompositeMlDsaParameters& parameters,
    const MlDsaPublicKey& ml_dsa_public_key,
    std::unique_ptr<SignaturePublicKey> classical_public_key,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  if (parameters.HasIdRequirement() && !id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters.HasIdRequirement() && id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }

  absl::StatusOr<const SignatureParameters*> ml_dsa_params =
      GetParametersForMlDsaInstance(parameters.GetMlDsaInstance());
  if (!ml_dsa_params.ok()) {
    return ml_dsa_params.status();
  }
  if (ml_dsa_public_key.GetParameters() != **ml_dsa_params) {
    return absl::InvalidArgumentError(
        "ML-DSA public key does not match parameters.");
  }

  absl::StatusOr<const SignatureParameters*> classical_params =
      GetParametersForClassicalAlgorithm(parameters.GetClassicalAlgorithm());
  if (!classical_params.ok()) {
    return classical_params.status();
  }
  if (classical_public_key->GetParameters() != **classical_params) {
    return absl::InvalidArgumentError(
        "Classical public key does not match parameters.");
  }

  absl::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }
  return CompositeMlDsaPublicKey(parameters, ml_dsa_public_key,
                                 std::move(classical_public_key),
                                 id_requirement, *output_prefix);
}

bool CompositeMlDsaPublicKey::operator==(const Key& other) const {
  const CompositeMlDsaPublicKey* that =
      dynamic_cast<const CompositeMlDsaPublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return GetParameters() == that->GetParameters() &&
         ml_dsa_public_key_ == that->ml_dsa_public_key_ &&
         *classical_public_key_ == *that->classical_public_key_ &&
         id_requirement_ == that->id_requirement_;
}

std::unique_ptr<Key> CompositeMlDsaPublicKey::Clone() const {
  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          *classical_public_key_);
  return absl::WrapUnique(new CompositeMlDsaPublicKey(
      parameters_, ml_dsa_public_key_, std::move(classical_public_key_clone),
      id_requirement_, output_prefix_));
}

}  // namespace tink
}  // namespace crypto
