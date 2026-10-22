// Copyright 2017 Google Inc.
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

#include "tink/signature/ecdsa_verify_key_manager.h"

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
#include "tink/key.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::EcdsaParams;
using EcdsaPublicKeyProto = ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;

absl::StatusOr<EcdsaPublicKey> ParseEcdsaPublicKeyWithNoPrefix(
    const EcdsaPublicKeyProto& ecdsa_public_key) {
  static const internal::SerializationRegistry* registry = []() {
    internal::SerializationRegistry::Builder builder;
    ABSL_CHECK_OK(
        internal::RegisterEcdsaProtoSerializationWithRegistryBuilder(builder));
    return new internal::SerializationRegistry(std::move(builder).Build());
  }();
  // KeyTypeManager primitives only receive the raw key proto (without
  // OutputPrefixType or key ID) and must produce raw (kNoPrefix) primitives;
  // the output prefix is handled by PublicKeyVerifyWrapper.
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          EcdsaVerifyKeyManager().get_key_type(),
          RestrictedData(ecdsa_public_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPublic,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt);
  ABSL_RETURN_IF_ERROR(serialization.status());
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(*serialization, InsecureSecretKeyAccess::Get()));
  const auto* public_key = dynamic_cast<const EcdsaPublicKey*>(key.get());
  if (public_key == nullptr) {
    return absl::InternalError("Failed to cast to EcdsaPublicKey");
  }
  return *public_key;
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
EcdsaVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const EcdsaPublicKeyProto& ecdsa_public_key) const {
  ABSL_ASSIGN_OR_RETURN(EcdsaPublicKey public_key,
                        ParseEcdsaPublicKeyWithNoPrefix(ecdsa_public_key));
  return subtle::EcdsaVerifyBoringSsl::New(public_key);
}

absl::Status EcdsaVerifyKeyManager::ValidateParams(
    const EcdsaParams& params) const {
  switch (params.encoding()) {
    case EcdsaSignatureEncoding::DER:  // fall through
    case EcdsaSignatureEncoding::IEEE_P1363:
      break;
    default:
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Unsupported signature encoding: %d", params.encoding());
  }
  switch (params.curve()) {
    case EllipticCurveType::NIST_P256:
      // Using SHA512 for curve P256 is fine. However, only the 256
      // leftmost bits of the hash is used in signature computation.
      // Therefore, we don't allow it here to prevent security illusion.
      if (params.hash_type() != HashType::SHA256) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "Only SHA256 is supported for NIST P256.");
      }
      break;
    case EllipticCurveType::NIST_P384:
      // Allow using SHA384 and SHA512 with NIST-P384.
      if ((params.hash_type() != HashType::SHA384) &&
          (params.hash_type() != HashType::SHA512)) {
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            "Only SHA384 and SHA512 are supported for this curve.");
      }
      break;
    case EllipticCurveType::NIST_P521:
      if (params.hash_type() != HashType::SHA512) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "Only SHA512 is supported for this curve.");
      }
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported elliptic curve");
  }
  return absl::OkStatus();
}

absl::Status EcdsaVerifyKeyManager::ValidateKey(
    const EcdsaPublicKeyProto& key) const {
  ABSL_RETURN_IF_ERROR(ValidateVersion(key.version(), get_version()));
  return ValidateParams(key.params());
}

}  // namespace tink
}  // namespace crypto
