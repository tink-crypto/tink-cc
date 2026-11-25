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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_sign_key_manager.h"

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
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_proto_serialization_impl.h"
#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/sig_util.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/util/validation.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using JwtRsaSsaPkcs1PrivateKeyProto =
    ::google::crypto::tink::JwtRsaSsaPkcs1PrivateKey;
using JwtRsaSsaPkcs1PublicKeyProto =
    ::google::crypto::tink::JwtRsaSsaPkcs1PublicKey;

namespace {
JwtRsaSsaPkcs1PrivateKeyProto RsaPrivateKeySubtleToProto(
    const internal::RsaPrivateKey& private_key) {
  JwtRsaSsaPkcs1PrivateKeyProto key_proto;
  key_proto.set_version(RawJwtRsaSsaPkcs1SignKeyManager().get_version());
  key_proto.set_d(private_key.d.AsStringView());
  key_proto.set_p(private_key.p.AsStringView());
  key_proto.set_q(private_key.q.AsStringView());
  key_proto.set_dp(private_key.dp.AsStringView());
  key_proto.set_dq(private_key.dq.AsStringView());
  key_proto.set_crt(private_key.crt.AsStringView());
  JwtRsaSsaPkcs1PublicKeyProto* public_key_proto =
      key_proto.mutable_public_key();
  public_key_proto->set_version(
      RawJwtRsaSsaPkcs1SignKeyManager().get_version());
  public_key_proto->set_n(private_key.n);
  public_key_proto->set_e(private_key.e);
  return key_proto;
}

absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> ParseJwtRsaSsaPkcs1PrivateKey(
    const JwtRsaSsaPkcs1PrivateKeyProto& jwt_rsa_ssa_pkcs1_private_key) {
  static const internal::SerializationRegistry* registry = []() {
    auto* registry = new internal::SerializationRegistry();
    ABSL_CHECK_OK(
        internal::RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistry(
            *registry));
    return registry;
  }();
  ABSL_ASSIGN_OR_RETURN(
      internal::ProtoKeySerialization serialization,
      internal::ProtoKeySerialization::Create(
          RawJwtRsaSsaPkcs1SignKeyManager().get_key_type(),
          RestrictedData(jwt_rsa_ssa_pkcs1_private_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt));
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(serialization, InsecureSecretKeyAccess::Get()));
  const auto* private_key =
      dynamic_cast<const JwtRsaSsaPkcs1PrivateKey*>(key.get());
  if (private_key == nullptr) {
    return absl::InternalError("Failed to cast to JwtRsaSsaPkcs1PrivateKey");
  }
  return *private_key;
}

}  // namespace

absl::StatusOr<JwtRsaSsaPkcs1PrivateKeyProto>
RawJwtRsaSsaPkcs1SignKeyManager::CreateKey(
    const JwtRsaSsaPkcs1KeyFormat& jwt_rsa_ssa_pkcs1_key_format) const {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(jwt_rsa_ssa_pkcs1_key_format.public_exponent());
  if (!e.ok()) {
    return e.status();
  }

  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;
  absl::Status status = internal::NewRsaKeyPair(
      jwt_rsa_ssa_pkcs1_key_format.modulus_size_in_bits(), e->get(),
      &private_key, &public_key);
  if (!status.ok()) {
    return status;
  }

  JwtRsaSsaPkcs1PrivateKeyProto key_proto =
      RsaPrivateKeySubtleToProto(private_key);
  JwtRsaSsaPkcs1PublicKeyProto* public_key_proto =
      key_proto.mutable_public_key();
  public_key_proto->set_algorithm(jwt_rsa_ssa_pkcs1_key_format.algorithm());

  return key_proto;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
RawJwtRsaSsaPkcs1SignKeyManager::PublicKeySignFactory::Create(
    const JwtRsaSsaPkcs1PrivateKeyProto& private_key) const {
  ABSL_ASSIGN_OR_RETURN(JwtRsaSsaPkcs1PrivateKey parsed_key,
                        ParseJwtRsaSsaPkcs1PrivateKey(private_key));
  const RsaSsaPkcs1PrivateKey& rsa_private_key =
      parsed_key.GetRsaSsaPkcs1PrivateKey(GetPartialKeyAccess());
  ABSL_ASSIGN_OR_RETURN(std::unique_ptr<PublicKeySign> signer,
                        subtle::RsaSsaPkcs1SignBoringSsl::New(rsa_private_key));
  // To check that the key is correct, we sign a test message with private key
  // and verify with public key.
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<PublicKeyVerify> verifier,
      subtle::RsaSsaPkcs1VerifyBoringSsl::New(rsa_private_key.GetPublicKey()));
  absl::Status sign_verify_result = SignAndVerify(signer.get(), verifier.get());
  if (!sign_verify_result.ok()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "security bug: signing with private key followed by "
                        "verifying with public key failed");
  }
  return signer;
}

absl::Status RawJwtRsaSsaPkcs1SignKeyManager::ValidateKey(
    const JwtRsaSsaPkcs1PrivateKeyProto& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return RawJwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(key.public_key());
}

absl::Status RawJwtRsaSsaPkcs1SignKeyManager::ValidateKeyFormat(
    const JwtRsaSsaPkcs1KeyFormat& key_format) const {
  absl::Status modulus_status =
      internal::ValidateRsaModulusSize(key_format.modulus_size_in_bits());
  if (!modulus_status.ok()) {
    return modulus_status;
  }
  absl::Status exponent_status =
      internal::ValidateRsaPublicExponent(key_format.public_exponent());
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  return RawJwtRsaSsaPkcs1VerifyKeyManager().ValidateAlgorithm(
      key_format.algorithm());
}

}  // namespace tink
}  // namespace crypto
