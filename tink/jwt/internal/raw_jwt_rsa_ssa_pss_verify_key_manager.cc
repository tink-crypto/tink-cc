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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_verify_key_manager.h"

#include <memory>
#include <optional>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "openssl/bn.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_proto_serialization_impl.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/validation.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using JwtRsaSsaPssPublicKeyProto =
    ::google::crypto::tink::JwtRsaSsaPssPublicKey;

absl::StatusOr<JwtRsaSsaPssPublicKey> ParseJwtRsaSsaPssPublicKey(
    const JwtRsaSsaPssPublicKeyProto& jwt_rsa_ssa_pss_public_key) {
  static const internal::SerializationRegistry* registry = []() {
    auto* registry = new internal::SerializationRegistry();
    ABSL_CHECK_OK(internal::RegisterJwtRsaSsaPssProtoSerializationWithRegistry(
        *registry));
    return registry;
  }();
  ABSL_ASSIGN_OR_RETURN(
      internal::ProtoKeySerialization serialization,
      internal::ProtoKeySerialization::Create(
          RawJwtRsaSsaPssVerifyKeyManager().get_key_type(),
          RestrictedData(jwt_rsa_ssa_pss_public_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPublic,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt));
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(serialization, InsecureSecretKeyAccess::Get()));
  const auto* public_key =
      dynamic_cast<const JwtRsaSsaPssPublicKey*>(key.get());
  if (public_key == nullptr) {
    return absl::InternalError("Failed to cast to JwtRsaSsaPssPublicKey");
  }
  return *public_key;
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
RawJwtRsaSsaPssVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const JwtRsaSsaPssPublicKeyProto& rsa_ssa_pss_public_key) const {
  ABSL_ASSIGN_OR_RETURN(JwtRsaSsaPssPublicKey public_key,
                        ParseJwtRsaSsaPssPublicKey(rsa_ssa_pss_public_key));
  return subtle::RsaSsaPssVerifyBoringSsl::New(
      public_key.GetRsaSsaPssPublicKey(GetPartialKeyAccess()));
}

absl::Status RawJwtRsaSsaPssVerifyKeyManager::ValidateKey(
    const JwtRsaSsaPssPublicKeyProto& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) {
    return status;
  }
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(key.n());
  if (!n.ok()) {
    return n.status();
  }
  absl::Status modulus_status =
      internal::ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }
  absl::Status exponent_status = internal::ValidateRsaPublicExponent(key.e());
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  return ValidateAlgorithm(key.algorithm());
}

absl::Status RawJwtRsaSsaPssVerifyKeyManager::ValidateAlgorithm(
    const JwtRsaSsaPssAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssAlgorithm::PS256:
    case JwtRsaSsaPssAlgorithm::PS384:
    case JwtRsaSsaPssAlgorithm::PS512:
      return absl::OkStatus();
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported RSA SSA PSS Algorithm");
  }
  return absl::OkStatus();
}

}  // namespace tink
}  // namespace crypto
