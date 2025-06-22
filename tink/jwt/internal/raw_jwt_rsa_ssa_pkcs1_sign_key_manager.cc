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
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/sig_util.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using google::crypto::tink::JwtRsaSsaPkcs1PrivateKey;
using ::google::crypto::tink::JwtRsaSsaPkcs1PublicKey;

namespace {
JwtRsaSsaPkcs1PrivateKey RsaPrivateKeySubtleToProto(
    const internal::RsaPrivateKey& private_key) {
  JwtRsaSsaPkcs1PrivateKey key_proto;
  key_proto.set_version(RawJwtRsaSsaPkcs1SignKeyManager().get_version());
  key_proto.set_d(util::SecretDataAsStringView(private_key.d));
  key_proto.set_p(util::SecretDataAsStringView(private_key.p));
  key_proto.set_q(util::SecretDataAsStringView(private_key.q));
  key_proto.set_dp(util::SecretDataAsStringView(private_key.dp));
  key_proto.set_dq(util::SecretDataAsStringView(private_key.dq));
  key_proto.set_crt(util::SecretDataAsStringView(private_key.crt));
  JwtRsaSsaPkcs1PublicKey* public_key_proto = key_proto.mutable_public_key();
  public_key_proto->set_version(
      RawJwtRsaSsaPkcs1SignKeyManager().get_version());
  public_key_proto->set_n(private_key.n);
  public_key_proto->set_e(private_key.e);
  return key_proto;
}

internal::RsaPrivateKey RsaPrivateKeyProtoToSubtle(
    const JwtRsaSsaPkcs1PrivateKey& key_proto) {
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

absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
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

  JwtRsaSsaPkcs1PrivateKey key_proto = RsaPrivateKeySubtleToProto(private_key);
  JwtRsaSsaPkcs1PublicKey* public_key_proto = key_proto.mutable_public_key();
  public_key_proto->set_algorithm(jwt_rsa_ssa_pkcs1_key_format.algorithm());

  return key_proto;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
RawJwtRsaSsaPkcs1SignKeyManager::PublicKeySignFactory::Create(
    const JwtRsaSsaPkcs1PrivateKey& private_key) const {
  internal::RsaPrivateKey key = RsaPrivateKeyProtoToSubtle(private_key);
  absl::StatusOr<google::crypto::tink::HashType> hash =
      RawJwtRsaSsaPkcs1VerifyKeyManager::HashForPkcs1Algorithm(
          private_key.public_key().algorithm());
  if (!hash.ok()) {
    return hash.status();
  }
  internal::RsaSsaPkcs1Params params;
  params.hash_type = Enums::ProtoToSubtle(*hash);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      subtle::RsaSsaPkcs1SignBoringSsl::New(key, params);
  if (!signer.ok()) return signer.status();
  // To check that the key is correct, we sign a test message with private key
  // and verify with public key.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RawJwtRsaSsaPkcs1VerifyKeyManager().GetPrimitive<PublicKeyVerify>(
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

absl::Status RawJwtRsaSsaPkcs1SignKeyManager::ValidateKey(
    const JwtRsaSsaPkcs1PrivateKey& key) const {
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
