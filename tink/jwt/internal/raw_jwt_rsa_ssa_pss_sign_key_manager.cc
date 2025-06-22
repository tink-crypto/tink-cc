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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_sign_key_manager.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_verify_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/sig_util.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Enums;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPssKeyFormat;
using ::google::crypto::tink::JwtRsaSsaPssPrivateKey;
using ::google::crypto::tink::JwtRsaSsaPssPublicKey;

namespace {
std::unique_ptr<JwtRsaSsaPssPrivateKey> RsaPrivateKeySubtleToProto(
    const internal::RsaPrivateKey& private_key) {
  auto key_proto = absl::make_unique<JwtRsaSsaPssPrivateKey>();
  key_proto->set_version(RawJwtRsaSsaPssSignKeyManager().get_version());
  key_proto->set_d(util::SecretDataAsStringView(private_key.d));
  key_proto->set_p(util::SecretDataAsStringView(private_key.p));
  key_proto->set_q(util::SecretDataAsStringView(private_key.q));
  key_proto->set_dp(util::SecretDataAsStringView(private_key.dp));
  key_proto->set_dq(util::SecretDataAsStringView(private_key.dq));
  key_proto->set_crt(util::SecretDataAsStringView(private_key.crt));
  JwtRsaSsaPssPublicKey* public_key_proto = key_proto->mutable_public_key();
  public_key_proto->set_version(RawJwtRsaSsaPssSignKeyManager().get_version());
  public_key_proto->set_n(private_key.n);
  public_key_proto->set_e(private_key.e);
  return key_proto;
}

internal::RsaPrivateKey RsaPrivateKeyProtoToSubtle(
    const JwtRsaSsaPssPrivateKey& key_proto) {
  internal::RsaPrivateKey key;
  key.n = key_proto.public_key().n();
  key.e = key_proto.public_key().e();
  key.d = util::SecretDataFromStringView(key_proto.d());
  key.p = util::SecretDataFromStringView(key_proto.p());
  key.q = util::SecretDataFromStringView(key_proto.q());
  key.dp = util::SecretDataFromStringView(key_proto.dp());
  key.dq = util::SecretDataFromStringView(key_proto.dq());
  key.crt = util::SecretDataFromStringView(key_proto.crt());
  return key;
}

}  // namespace

absl::StatusOr<JwtRsaSsaPssPrivateKey> RawJwtRsaSsaPssSignKeyManager::CreateKey(
    const JwtRsaSsaPssKeyFormat& key_format) const {
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

  JwtRsaSsaPssPrivateKey key_proto =
      std::move(*RsaPrivateKeySubtleToProto(private_key));
  key_proto.mutable_public_key()->set_algorithm(key_format.algorithm());
  return key_proto;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
RawJwtRsaSsaPssSignKeyManager::PublicKeySignFactory::Create(
    const JwtRsaSsaPssPrivateKey& private_key) const {
  auto key = RsaPrivateKeyProtoToSubtle(private_key);
  JwtRsaSsaPssAlgorithm algorithm = private_key.public_key().algorithm();
  absl::StatusOr<HashType> hash =
      RawJwtRsaSsaPssVerifyKeyManager::HashForPssAlgorithm(algorithm);
  if (!hash.ok()) {
    return hash.status();
  }
  absl::StatusOr<int> salt_length =
      RawJwtRsaSsaPssVerifyKeyManager::SaltLengthForPssAlgorithm(algorithm);
  if (!salt_length.ok()) {
    return salt_length.status();
  }
  internal::RsaSsaPssParams params;
  params.sig_hash = Enums::ProtoToSubtle(*hash);
  params.mgf1_hash = Enums::ProtoToSubtle(*hash);
  params.salt_length = *salt_length;
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      subtle::RsaSsaPssSignBoringSsl::New(key, params);
  if (!signer.ok()) return signer.status();
  // To check that the key is correct, we sign a test message with private key
  // and verify with public key.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RawJwtRsaSsaPssVerifyKeyManager().GetPrimitive<PublicKeyVerify>(
          private_key.public_key());
  if (!verifier.ok()) return verifier.status();
  absl::Status sign_verify_result =
      SignAndVerify(signer->get(), verifier->get());
  if (!sign_verify_result.ok()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "security bug: signing with private key followed by "
                        "verifying with public key failed");
  }
  return signer;
}

absl::Status RawJwtRsaSsaPssSignKeyManager::ValidateKey(
    const JwtRsaSsaPssPrivateKey& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return RawJwtRsaSsaPssVerifyKeyManager().ValidateKey(key.public_key());
}

absl::Status RawJwtRsaSsaPssSignKeyManager::ValidateKeyFormat(
    const JwtRsaSsaPssKeyFormat& key_format) const {
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
  return RawJwtRsaSsaPssVerifyKeyManager::ValidateAlgorithm(
      key_format.algorithm());
}

}  // namespace tink
}  // namespace crypto
