// Copyright 2018 Google LLC
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

#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
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
#include "tink/signature/internal/rsa_ssa_pss_proto_serialization_impl.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/sig_util.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"
#include "tink/util/validation.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::RsaSsaPssKeyFormat;
using RsaSsaPssPrivateKeyProto = ::google::crypto::tink::RsaSsaPssPrivateKey;

namespace {

std::unique_ptr<RsaSsaPssPrivateKeyProto> RsaPrivateKeySubtleToProto(
    const internal::RsaPrivateKey& private_key) {
  auto key_proto = std::make_unique<RsaSsaPssPrivateKeyProto>();
  key_proto->set_version(RsaSsaPssSignKeyManager().get_version());
  key_proto->set_d(private_key.d.AsStringView());
  key_proto->set_p(private_key.p.AsStringView());
  key_proto->set_q(private_key.q.AsStringView());
  key_proto->set_dp(private_key.dp.AsStringView());
  key_proto->set_dq(private_key.dq.AsStringView());
  key_proto->set_crt(private_key.crt.AsStringView());
  auto* public_key_proto = key_proto->mutable_public_key();
  public_key_proto->set_version(RsaSsaPssSignKeyManager().get_version());
  public_key_proto->set_n(private_key.n);
  public_key_proto->set_e(private_key.e);
  return key_proto;
}

absl::StatusOr<RsaSsaPssPrivateKey> ParseRsaSsaPssPrivateKeyWithNoPrefix(
    const RsaSsaPssPrivateKeyProto& rsa_ssa_pss_private_key) {
  static const internal::SerializationRegistry* registry = []() {
    auto* registry = new internal::SerializationRegistry();
    ABSL_CHECK_OK(
        internal::RegisterRsaSsaPssProtoSerializationWithRegistry(*registry));
    return registry;
  }();
  // KeyTypeManager primitives only receive the raw key proto (without
  // OutputPrefixType or key ID) and must produce raw (kNoPrefix) primitives;
  // the output prefix is handled by PublicKeySignWrapper.
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          RsaSsaPssSignKeyManager().get_key_type(),
          RestrictedData(rsa_ssa_pss_private_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt);
  ABSL_RETURN_IF_ERROR(serialization.status());
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(*serialization, InsecureSecretKeyAccess::Get()));
  const auto* private_key = dynamic_cast<const RsaSsaPssPrivateKey*>(key.get());
  if (private_key == nullptr) {
    return absl::InternalError("Failed to cast to RsaSsaPssPrivateKey");
  }
  return *private_key;
}

}  // namespace

absl::StatusOr<RsaSsaPssPrivateKeyProto> RsaSsaPssSignKeyManager::CreateKey(
    const RsaSsaPssKeyFormat& key_format) const {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(key_format.public_exponent());
  if (!e.ok()) {
    return e.status();
  }

  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;
  absl::Status status = internal::NewRsaKeyPair(
      key_format.modulus_size_in_bits(), e->get(), &private_key, &public_key);
  if (!status.ok()) {
    return status;
  }

  RsaSsaPssPrivateKeyProto key_proto =
      std::move(*RsaPrivateKeySubtleToProto(private_key));
  *key_proto.mutable_public_key()->mutable_params() = key_format.params();
  return key_proto;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
RsaSsaPssSignKeyManager::PublicKeySignFactory::Create(
    const RsaSsaPssPrivateKeyProto& private_key) const {
  ABSL_ASSIGN_OR_RETURN(RsaSsaPssPrivateKey key,
                        ParseRsaSsaPssPrivateKeyWithNoPrefix(private_key));
  ABSL_ASSIGN_OR_RETURN(std::unique_ptr<PublicKeySign> signer,
                        subtle::RsaSsaPssSignBoringSsl::New(key));
  // To check that the key is correct, we sign a test message with private key
  // and verify with public key.
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<PublicKeyVerify> verifier,
      RsaSsaPssVerifyKeyManager().GetPrimitive<PublicKeyVerify>(
          private_key.public_key()));
  absl::Status sign_verify_result = SignAndVerify(signer.get(), verifier.get());
  if (!sign_verify_result.ok()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "security bug: signing with private key followed by "
                        "verifying with public key failed");
  }
  return signer;
}

absl::Status RsaSsaPssSignKeyManager::ValidateKey(
    const RsaSsaPssPrivateKeyProto& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return RsaSsaPssVerifyKeyManager().ValidateKey(key.public_key());
}

absl::Status RsaSsaPssSignKeyManager::ValidateKeyFormat(
    const RsaSsaPssKeyFormat& key_format) const {
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
  return RsaSsaPssVerifyKeyManager().ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
