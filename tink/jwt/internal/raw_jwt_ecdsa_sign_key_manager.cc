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

#include "tink/jwt/internal/raw_jwt_ecdsa_sign_key_manager.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/jwt/internal/jwt_ecdsa_proto_serialization_impl.h"
#include "tink/jwt/internal/raw_jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/restricted_data.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::google::crypto::tink::JwtEcdsaKeyFormat;
using JwtEcdsaPrivateKeyProto = ::google::crypto::tink::JwtEcdsaPrivateKey;
using JwtEcdsaPublicKeyProto = ::google::crypto::tink::JwtEcdsaPublicKey;

absl::StatusOr<JwtEcdsaPrivateKey> ParseJwtEcdsaPrivateKey(
    const JwtEcdsaPrivateKeyProto& jwt_ecdsa_private_key) {
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
          RawJwtEcdsaSignKeyManager().get_key_type(),
          RestrictedData(jwt_ecdsa_private_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt));
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(serialization, InsecureSecretKeyAccess::Get()));
  const auto* private_key = dynamic_cast<const JwtEcdsaPrivateKey*>(key.get());
  if (private_key == nullptr) {
    return absl::InternalError("Failed to cast to JwtEcdsaPrivateKey");
  }
  return *private_key;
}

}  // namespace

absl::StatusOr<JwtEcdsaPrivateKeyProto> RawJwtEcdsaSignKeyManager::CreateKey(
    const JwtEcdsaKeyFormat& jwt_ecdsa_key_format) const {
  // Generate new EC key.
  ABSL_ASSIGN_OR_RETURN(google::crypto::tink::EllipticCurveType curve,
                        RawJwtEcdsaVerifyKeyManager::CurveForEcdsaAlgorithm(
                            jwt_ecdsa_key_format.algorithm()));

  ABSL_ASSIGN_OR_RETURN(internal::EcKey ec_key,
                        internal::NewEcKey(util::Enums::ProtoToSubtle(curve)));

  // Build EcdsaPrivateKey.
  JwtEcdsaPrivateKeyProto jwt_ecdsa_private_key;
  jwt_ecdsa_private_key.set_version(get_version());
  jwt_ecdsa_private_key.set_key_value(ec_key.priv.AsStringView());
  JwtEcdsaPublicKeyProto* jwt_ecdsa_public_key =
      jwt_ecdsa_private_key.mutable_public_key();
  jwt_ecdsa_public_key->set_version(get_version());
  jwt_ecdsa_public_key->set_x(ec_key.pub_x);
  jwt_ecdsa_public_key->set_y(ec_key.pub_y);
  jwt_ecdsa_public_key->set_algorithm(jwt_ecdsa_key_format.algorithm());
  return jwt_ecdsa_private_key;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
RawJwtEcdsaSignKeyManager::PublicKeySignFactory::Create(
    const JwtEcdsaPrivateKeyProto& jwt_ecdsa_private_key) const {
  ABSL_ASSIGN_OR_RETURN(JwtEcdsaPrivateKey private_key,
                        ParseJwtEcdsaPrivateKey(jwt_ecdsa_private_key));
  return subtle::EcdsaSignBoringSsl::New(
      private_key.GetEcdsaPrivateKey(GetPartialKeyAccess()));
}

absl::Status RawJwtEcdsaSignKeyManager::ValidateKey(
    const JwtEcdsaPrivateKeyProto& key) const {
  ABSL_RETURN_IF_ERROR(ValidateVersion(key.version(), get_version()));
  return RawJwtEcdsaVerifyKeyManager().ValidateKey(key.public_key());
}

absl::Status RawJwtEcdsaSignKeyManager::ValidateKeyFormat(
    const JwtEcdsaKeyFormat& key_format) const {
  return RawJwtEcdsaVerifyKeyManager::ValidateAlgorithm(key_format.algorithm());
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
