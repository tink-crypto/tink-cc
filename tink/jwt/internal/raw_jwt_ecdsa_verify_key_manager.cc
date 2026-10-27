// Copyright 2021 Google LLC
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

#include "tink/jwt/internal/raw_jwt_ecdsa_verify_key_manager.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/jwt/internal/jwt_ecdsa_proto_serialization_impl.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using JwtEcdsaPublicKeyProto = ::google::crypto::tink::JwtEcdsaPublicKey;

absl::StatusOr<JwtEcdsaPublicKey> ParseJwtEcdsaPublicKey(
    const JwtEcdsaPublicKeyProto& jwt_ecdsa_public_key) {
  static const internal::SerializationRegistry* registry = []() {
    internal::SerializationRegistry::Builder builder;
    ABSL_CHECK_OK(
        internal::RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(
            builder));
    return new internal::SerializationRegistry(std::move(builder).Build());
  }();
  ABSL_ASSIGN_OR_RETURN(
      internal::ProtoKeySerialization serialization,
      internal::ProtoKeySerialization::Create(
          RawJwtEcdsaVerifyKeyManager().get_key_type(),
          RestrictedData(jwt_ecdsa_public_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPublic,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt));
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(serialization, InsecureSecretKeyAccess::Get()));
  const auto* public_key = dynamic_cast<const JwtEcdsaPublicKey*>(key.get());
  if (public_key == nullptr) {
    return absl::InternalError("Failed to cast to JwtEcdsaPublicKey");
  }
  return *public_key;
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
RawJwtEcdsaVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const JwtEcdsaPublicKeyProto& jwt_ecdsa_public_key) const {
  ABSL_ASSIGN_OR_RETURN(JwtEcdsaPublicKey public_key,
                        ParseJwtEcdsaPublicKey(jwt_ecdsa_public_key));
  return subtle::EcdsaVerifyBoringSsl::New(
      public_key.GetEcdsaPublicKey(GetPartialKeyAccess()));
}

absl::StatusOr<EllipticCurveType>
RawJwtEcdsaVerifyKeyManager::CurveForEcdsaAlgorithm(
    const JwtEcdsaAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
      return EllipticCurveType::NIST_P256;
    case JwtEcdsaAlgorithm::ES384:
      return EllipticCurveType::NIST_P384;
    case JwtEcdsaAlgorithm::ES512:
      return EllipticCurveType::NIST_P521;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported Ecdsa Algorithm");
  }
}

absl::StatusOr<HashType> RawJwtEcdsaVerifyKeyManager::HashForEcdsaAlgorithm(
    const JwtEcdsaAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
      return HashType::SHA256;
    case JwtEcdsaAlgorithm::ES384:
      return HashType::SHA384;
    case JwtEcdsaAlgorithm::ES512:
      return HashType::SHA512;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported Ecdsa Algorithm");
  }
}

absl::Status RawJwtEcdsaVerifyKeyManager::ValidateAlgorithm(
    const JwtEcdsaAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
    case JwtEcdsaAlgorithm::ES384:
    case JwtEcdsaAlgorithm::ES512:
      return absl::OkStatus();
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported Ecdsa Algorithm");
  }
  return absl::OkStatus();
}

absl::Status RawJwtEcdsaVerifyKeyManager::ValidateKey(
    const JwtEcdsaPublicKeyProto& key) const {
  ABSL_RETURN_IF_ERROR(ValidateVersion(key.version(), get_version()));
  return ValidateAlgorithm(key.algorithm());
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
