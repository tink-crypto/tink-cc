// Copyright 2018 Google Inc.
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

#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"

#include <memory>
#include <optional>
#include <string>

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
#include "tink/key.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_proto_serialization_impl.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/sig_util.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/util/validation.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::RsaSsaPkcs1KeyFormat;
using RsaSsaPkcs1PrivateKeyProto =
    ::google::crypto::tink::RsaSsaPkcs1PrivateKey;

namespace {
RsaSsaPkcs1PrivateKeyProto RsaPrivateKeySubtleToProto(
    const internal::RsaPrivateKey& private_key) {
  RsaSsaPkcs1PrivateKeyProto key_proto;
  key_proto.set_version(RsaSsaPkcs1SignKeyManager().get_version());
  key_proto.set_d(std::string(private_key.d.AsStringView()));
  key_proto.set_p(std::string(private_key.p.AsStringView()));
  key_proto.set_q(std::string(private_key.q.AsStringView()));
  key_proto.set_dp(std::string(private_key.dp.AsStringView()));
  key_proto.set_dq(std::string(private_key.dq.AsStringView()));
  key_proto.set_crt(std::string(private_key.crt.AsStringView()));
  auto* public_key_proto = key_proto.mutable_public_key();
  public_key_proto->set_version(RsaSsaPkcs1SignKeyManager().get_version());
  public_key_proto->set_n(private_key.n);
  public_key_proto->set_e(private_key.e);
  return key_proto;
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> ParseRsaSsaPkcs1PrivateKeyWithNoPrefix(
    const RsaSsaPkcs1PrivateKeyProto& rsa_ssa_pkcs1_private_key) {
  static const internal::SerializationRegistry* registry = []() {
    auto* registry = new internal::SerializationRegistry();
    ABSL_CHECK_OK(
        internal::RegisterRsaSsaPkcs1ProtoSerializationWithRegistry(*registry));
    return registry;
  }();
  // KeyTypeManager primitives only receive the raw key proto (without
  // OutputPrefixType or key ID) and must produce raw (kNoPrefix) primitives;
  // the output prefix is handled by PublicKeySignWrapper.
  ABSL_ASSIGN_OR_RETURN(
      internal::ProtoKeySerialization serialization,
      internal::ProtoKeySerialization::Create(
          RsaSsaPkcs1SignKeyManager().get_key_type(),
          RestrictedData(rsa_ssa_pkcs1_private_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt));
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(serialization, InsecureSecretKeyAccess::Get()));
  const auto* private_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(key.get());
  if (private_key == nullptr) {
    return absl::InternalError("Failed to cast to RsaSsaPkcs1PrivateKey");
  }
  return *private_key;
}

}  // namespace

absl::StatusOr<RsaSsaPkcs1PrivateKeyProto> RsaSsaPkcs1SignKeyManager::CreateKey(
    const RsaSsaPkcs1KeyFormat& rsa_ssa_pkcs1_key_format) const {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(rsa_ssa_pkcs1_key_format.public_exponent());
  if (!e.ok()) {
    return e.status();
  }

  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;
  absl::Status status =
      internal::NewRsaKeyPair(rsa_ssa_pkcs1_key_format.modulus_size_in_bits(),
                              e->get(), &private_key, &public_key);
  if (!status.ok()) {
    return status;
  }

  RsaSsaPkcs1PrivateKeyProto key_proto =
      RsaPrivateKeySubtleToProto(private_key);
  auto* public_key_proto = key_proto.mutable_public_key();
  *public_key_proto->mutable_params() = rsa_ssa_pkcs1_key_format.params();

  return key_proto;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
RsaSsaPkcs1SignKeyManager::PublicKeySignFactory::Create(
    const RsaSsaPkcs1PrivateKeyProto& private_key) const {
  ABSL_ASSIGN_OR_RETURN(RsaSsaPkcs1PrivateKey key,
                        ParseRsaSsaPkcs1PrivateKeyWithNoPrefix(private_key));
  ABSL_ASSIGN_OR_RETURN(std::unique_ptr<PublicKeySign> signer,
                        subtle::RsaSsaPkcs1SignBoringSsl::New(key));
  // To check that the key is correct, we sign a test message with private key
  // and verify with public key.
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<PublicKeyVerify> verifier,
      RsaSsaPkcs1VerifyKeyManager().GetPrimitive<PublicKeyVerify>(
          private_key.public_key()));
  absl::Status sign_verify_result = SignAndVerify(signer.get(), verifier.get());
  if (!sign_verify_result.ok()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "security bug: signing with private key followed by "
                        "verifying with public key failed");
  }
  return signer;
}

absl::Status RsaSsaPkcs1SignKeyManager::ValidateKey(
    const RsaSsaPkcs1PrivateKeyProto& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return RsaSsaPkcs1VerifyKeyManager().ValidateKey(key.public_key());
}

absl::Status RsaSsaPkcs1SignKeyManager::ValidateKeyFormat(
    const RsaSsaPkcs1KeyFormat& key_format) const {
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
  return RsaSsaPkcs1VerifyKeyManager().ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
