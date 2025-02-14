// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/internal/jwt_signature_config_v0.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/configuration.h"
#include "tink/ec_point.h"
#include "tink/internal/configuration_impl.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"
#include "tink/jwt/internal/jwt_public_key_verify_impl.h"
#include "tink/jwt/internal/jwt_public_key_verify_internal.h"
#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_verify_key_manager.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_proto_serialization.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_proto_serialization.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_proto_serialization.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

util::StatusOr<EcdsaParameters> RawEcdsaParamsFromJwtEcdsaParams(
    const JwtEcdsaParameters& params) {
  EcdsaParameters::Builder builder;
  builder.SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363);
  builder.SetVariant(EcdsaParameters::Variant::kNoPrefix);
  switch (params.GetAlgorithm()) {
    case JwtEcdsaParameters::Algorithm::kEs256: {
      builder.SetCurveType(EcdsaParameters::CurveType::kNistP256);
      builder.SetHashType(EcdsaParameters::HashType::kSha256);
      break;
    }
    case JwtEcdsaParameters::Algorithm::kEs384: {
      builder.SetCurveType(EcdsaParameters::CurveType::kNistP384);
      builder.SetHashType(EcdsaParameters::HashType::kSha384);
      break;
    }
    case JwtEcdsaParameters::Algorithm::kEs512: {
      builder.SetCurveType(EcdsaParameters::CurveType::kNistP521);
      builder.SetHashType(EcdsaParameters::HashType::kSha512);
      break;
    }
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported algorithm: ", params.GetAlgorithm()));
  }
  return builder.Build();
}

util::StatusOr<std::string> AlgorithmName(
    const JwtEcdsaParameters::Algorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return std::string("ES256");
    case JwtEcdsaParameters::Algorithm::kEs384:
      return std::string("ES384");
    case JwtEcdsaParameters::Algorithm::kEs512:
      return std::string("ES512");
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
  }
}

util::StatusOr<std::unique_ptr<PublicKeySign>> NewEcdsaSigner(
    const EcdsaParameters& params, const EcPoint& public_point,
    const RestrictedBigInteger& private_key_value) {
  util::StatusOr<EcdsaPublicKey> ecdsa_public_key = EcdsaPublicKey::Create(
      params, public_point,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!ecdsa_public_key.ok()) {
    return ecdsa_public_key.status();
  }
  util::StatusOr<EcdsaPrivateKey> raw_ecdsa_private_key =
      EcdsaPrivateKey::Create(*ecdsa_public_key, private_key_value,
                              GetPartialKeyAccess());
  if (!ecdsa_public_key.ok()) {
    return ecdsa_public_key.status();
  }
  return subtle::EcdsaSignBoringSsl::New(*raw_ecdsa_private_key);
}

util::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
NewJwtEcdsaSignInternal(const JwtEcdsaPrivateKey& jwt_ecdsa_private_key) {
  const JwtEcdsaParameters* jwt_ecdsa_params =
      dynamic_cast<const JwtEcdsaParameters*>(
          &jwt_ecdsa_private_key.GetParameters());
  if (jwt_ecdsa_params == nullptr) {
    // Should never happen.
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to cast JwtEcdsaParameters");
  }

  util::StatusOr<EcdsaParameters> raw_ecdsa_parameters =
      RawEcdsaParamsFromJwtEcdsaParams(*jwt_ecdsa_params);
  if (!raw_ecdsa_parameters.ok()) {
    return raw_ecdsa_parameters.status();
  }

  util::StatusOr<std::unique_ptr<PublicKeySign>> ecdsa_sign_boringssl =
      NewEcdsaSigner(
          raw_ecdsa_parameters.value(),
          jwt_ecdsa_private_key.GetPublicKey().GetPublicPoint(
              GetPartialKeyAccess()),
          jwt_ecdsa_private_key.GetPrivateKeyValue(GetPartialKeyAccess()));
  if (!ecdsa_sign_boringssl.ok()) {
    return ecdsa_sign_boringssl.status();
  }

  util::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_ecdsa_params->GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_ecdsa_params->GetKidStrategy()) {
    case JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId: {
      std::string kid = jwt_ecdsa_private_key.GetPublicKey().GetKid().value();
      // NOTE: This currently cannot be tested using Tink public APIs: the
      // keyset wrapper always deals with "RAW" keys.
      // https://github.com/tink-crypto/tink-cc/blob/ed2008a7b9f09b726a9fff4d96bb9b18093e71c3/tink/internal/keyset_wrapper_impl.h#L83
      return JwtPublicKeySignImpl::WithKid(*std::move(ecdsa_sign_boringssl),
                                           *algorithm_name, kid);
    }
    case JwtEcdsaParameters::KidStrategy::kCustom: {
      std::string custom_kid =
          jwt_ecdsa_private_key.GetPublicKey().GetKid().value();
      return JwtPublicKeySignImpl::RawWithCustomKid(
          *std::move(ecdsa_sign_boringssl), *algorithm_name, custom_kid);
    }
    case JwtEcdsaParameters::KidStrategy::kIgnored:
      return JwtPublicKeySignImpl::Raw(*std::move(ecdsa_sign_boringssl),
                                       *algorithm_name);
    default:
      // Should never happen.
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

util::StatusOr<std::unique_ptr<JwtPublicKeyVerifyInternal>>
NewJwtEcdsaVerifyInternal(const JwtEcdsaPublicKey& jwt_ecdsa_public_key) {
  const JwtEcdsaParameters* jwt_ecdsa_params =
      dynamic_cast<const JwtEcdsaParameters*>(
          &jwt_ecdsa_public_key.GetParameters());
  if (jwt_ecdsa_params == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to cast JwtEcdsaParameters");
  }
  util::StatusOr<EcdsaParameters> raw_ecdsa_parameters =
      RawEcdsaParamsFromJwtEcdsaParams(*jwt_ecdsa_params);
  if (!raw_ecdsa_parameters.ok()) {
    return raw_ecdsa_parameters.status();
  }
  util::StatusOr<EcdsaPublicKey> ecdsa_public_key = EcdsaPublicKey::Create(
      raw_ecdsa_parameters.value(),
      jwt_ecdsa_public_key.GetPublicPoint(GetPartialKeyAccess()), absl::nullopt,
      GetPartialKeyAccess());
  if (!ecdsa_public_key.ok()) {
    return ecdsa_public_key.status();
  }

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> ecdsa_verify_boringssl =
      subtle::EcdsaVerifyBoringSsl::New(*ecdsa_public_key);

  util::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_ecdsa_params->GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_ecdsa_params->GetKidStrategy()) {
    case JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId: {
      std::string kid = jwt_ecdsa_public_key.GetKid().value();
      // NOTE: This currently cannot be tested using Tink public APIs: the
      // keyset wrapper always deals with "RAW" keys.
      // https://github.com/tink-crypto/tink-cc/blob/ed2008a7b9f09b726a9fff4d96bb9b18093e71c3/tink/internal/keyset_wrapper_impl.h#L83
      return JwtPublicKeyVerifyImpl::WithKid(*std::move(ecdsa_verify_boringssl),
                                             *algorithm_name, kid);
    }
    case JwtEcdsaParameters::KidStrategy::kCustom: {
      std::string custom_kid = jwt_ecdsa_public_key.GetKid().value();
      return JwtPublicKeyVerifyImpl::RawWithCustomKid(
          *std::move(ecdsa_verify_boringssl), *algorithm_name, custom_kid);
    }
    case JwtEcdsaParameters::KidStrategy::kIgnored:
      return JwtPublicKeyVerifyImpl::Raw(*std::move(ecdsa_verify_boringssl),
                                         *algorithm_name);
    default:
      // Should never happen.
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

util::StatusOr<std::string> AlgorithmName(
    const JwtRsaSsaPkcs1Parameters::Algorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs256:
      return std::string("RS256");
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs384:
      return std::string("RS3072");
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs512:
      return std::string("RS4096");
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
  }
}

util::StatusOr<std::unique_ptr<PublicKeySign>> NewRsaSsaPkcs1Signer(
    const RsaSsaPkcs1Parameters& params,
    const JwtRsaSsaPkcs1PrivateKey& jwt_rsa_ssa_pkcs1_private_key) {
  util::StatusOr<RsaSsaPkcs1PublicKey> rsa_ssa_pkcs1_public_key =
      RsaSsaPkcs1PublicKey::Create(
          params,
          jwt_rsa_ssa_pkcs1_private_key.GetPublicKey().GetModulus(
              GetPartialKeyAccess()),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!rsa_ssa_pkcs1_public_key.ok()) {
    return rsa_ssa_pkcs1_public_key.status();
  }
  util::StatusOr<RsaSsaPkcs1PrivateKey> raw_rsa_ssa_pkcs1_private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*rsa_ssa_pkcs1_public_key)
          .SetPrimeP(
              jwt_rsa_ssa_pkcs1_private_key.GetPrimeP(GetPartialKeyAccess()))
          .SetPrimeQ(
              jwt_rsa_ssa_pkcs1_private_key.GetPrimeQ(GetPartialKeyAccess()))
          .SetPrivateExponent(
              jwt_rsa_ssa_pkcs1_private_key.GetPrivateExponent())
          .SetPrimeExponentP(jwt_rsa_ssa_pkcs1_private_key.GetPrimeExponentP())
          .SetPrimeExponentQ(jwt_rsa_ssa_pkcs1_private_key.GetPrimeExponentQ())
          .SetCrtCoefficient(jwt_rsa_ssa_pkcs1_private_key.GetCrtCoefficient())
          .Build(GetPartialKeyAccess());
  if (!rsa_ssa_pkcs1_public_key.ok()) {
    return rsa_ssa_pkcs1_public_key.status();
  }
  return subtle::RsaSsaPkcs1SignBoringSsl::New(*raw_rsa_ssa_pkcs1_private_key);
}

util::StatusOr<RsaSsaPkcs1Parameters>
RawRsaSsaPkcs1ParamsFromJwtRsaSsaPkcs1Params(
    const JwtRsaSsaPkcs1Parameters& params) {
  RsaSsaPkcs1Parameters::Builder builder;
  builder.SetModulusSizeInBits(params.GetModulusSizeInBits());
  builder.SetPublicExponent(params.GetPublicExponent());
  builder.SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix);
  switch (params.GetAlgorithm()) {
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs256:
      builder.SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256);
      break;
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs384:
      builder.SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384);
      break;
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs512:
      builder.SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512);
      break;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported algorithm: ", params.GetAlgorithm()));
  }
  return builder.Build();
}

util::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
NewJwtRsaSsaPkcs1SignInternal(
    const JwtRsaSsaPkcs1PrivateKey& jwt_rsa_ssa_pkcs1_private_key) {
  const JwtRsaSsaPkcs1Parameters* jwt_rsa_ssa_pkcs1_params =
      dynamic_cast<const JwtRsaSsaPkcs1Parameters*>(
          &jwt_rsa_ssa_pkcs1_private_key.GetParameters());
  if (jwt_rsa_ssa_pkcs1_params == nullptr) {
    // Should never happen.
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to cast JwtRsaSsaPkcs1Parameters");
  }

  util::StatusOr<RsaSsaPkcs1Parameters> raw_rsa_ssa_pkcs1_params =
      RawRsaSsaPkcs1ParamsFromJwtRsaSsaPkcs1Params(*jwt_rsa_ssa_pkcs1_params);
  if (!raw_rsa_ssa_pkcs1_params.ok()) {
    return raw_rsa_ssa_pkcs1_params.status();
  }

  util::StatusOr<std::unique_ptr<PublicKeySign>> raw_signer =
      NewRsaSsaPkcs1Signer(*raw_rsa_ssa_pkcs1_params,
                           jwt_rsa_ssa_pkcs1_private_key);
  if (!raw_signer.ok()) {
    return raw_signer.status();
  }

  util::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_rsa_ssa_pkcs1_params->GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_rsa_ssa_pkcs1_params->GetKidStrategy()) {
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId: {
      std::string kid =
          jwt_rsa_ssa_pkcs1_private_key.GetPublicKey().GetKid().value();
      // NOTE: This currently cannot be tested using Tink public APIs: the
      // keyset wrapper always deals with "RAW" keys.
      // https://github.com/tink-crypto/tink-cc/blob/ed2008a7b9f09b726a9fff4d96bb9b18093e71c3/tink/internal/keyset_wrapper_impl.h#L83
      return JwtPublicKeySignImpl::WithKid(*std::move(raw_signer),
                                           *algorithm_name, kid);
    }
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom: {
      std::string custom_kid =
          jwt_rsa_ssa_pkcs1_private_key.GetPublicKey().GetKid().value();
      return JwtPublicKeySignImpl::RawWithCustomKid(
          *std::move(raw_signer), *algorithm_name, custom_kid);
    }
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored:
      return JwtPublicKeySignImpl::Raw(*std::move(raw_signer), *algorithm_name);
    default:
      // Should never happen.
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

util::StatusOr<std::unique_ptr<JwtPublicKeyVerifyInternal>>
NewJwtRsaSsaPkcs1VerifyInternal(
    const JwtRsaSsaPkcs1PublicKey& jwt_rsa_ssa_pkcs1_public_key) {
  const JwtRsaSsaPkcs1Parameters* jwt_rsa_ssa_pkcs1_params =
      dynamic_cast<const JwtRsaSsaPkcs1Parameters*>(
          &jwt_rsa_ssa_pkcs1_public_key.GetParameters());
  if (jwt_rsa_ssa_pkcs1_params == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to cast JwtRsaSsaPkcs1Parameters");
  }
  util::StatusOr<RsaSsaPkcs1Parameters> raw_rsa_ssa_pkcs1_parameters =
      RawRsaSsaPkcs1ParamsFromJwtRsaSsaPkcs1Params(*jwt_rsa_ssa_pkcs1_params);
  if (!raw_rsa_ssa_pkcs1_parameters.ok()) {
    return raw_rsa_ssa_pkcs1_parameters.status();
  }
  util::StatusOr<RsaSsaPkcs1PublicKey> rsa_ssa_pkcs1_public_key =
      RsaSsaPkcs1PublicKey::Create(
          raw_rsa_ssa_pkcs1_parameters.value(),
          jwt_rsa_ssa_pkcs1_public_key.GetModulus(GetPartialKeyAccess()),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!rsa_ssa_pkcs1_public_key.ok()) {
    return rsa_ssa_pkcs1_public_key.status();
  }

  util::StatusOr<std::unique_ptr<PublicKeyVerify>>
      rsa_ssa_pkcs1_verify_boringssl =
          subtle::RsaSsaPkcs1VerifyBoringSsl::New(*rsa_ssa_pkcs1_public_key);

  util::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_rsa_ssa_pkcs1_params->GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_rsa_ssa_pkcs1_params->GetKidStrategy()) {
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId: {
      std::string kid = jwt_rsa_ssa_pkcs1_public_key.GetKid().value();
      // NOTE: This currently cannot be tested using Tink public APIs: the
      // keyset wrapper always deals with "RAW" keys.
      // https://github.com/tink-crypto/tink-cc/blob/ed2008a7b9f09b726a9fff4d96bb9b18093e71c3/tink/internal/keyset_wrapper_impl.h#L83
      return JwtPublicKeyVerifyImpl::WithKid(
          *std::move(rsa_ssa_pkcs1_verify_boringssl), *algorithm_name, kid);
    }
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom: {
      std::string custom_kid = jwt_rsa_ssa_pkcs1_public_key.GetKid().value();
      return JwtPublicKeyVerifyImpl::RawWithCustomKid(
          *std::move(rsa_ssa_pkcs1_verify_boringssl), *algorithm_name,
          custom_kid);
    }
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored:
      return JwtPublicKeyVerifyImpl::Raw(
          *std::move(rsa_ssa_pkcs1_verify_boringssl), *algorithm_name);
    default:
      // Should never happen.
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

util::StatusOr<std::unique_ptr<PublicKeySign>> NewRsaSsaPssSigner(
    const RsaSsaPssParameters& params,
    const JwtRsaSsaPssPrivateKey& jwt_rsa_ssa_pss_private_key) {
  util::StatusOr<RsaSsaPssPublicKey> rsa_ssa_pss_public_key =
      RsaSsaPssPublicKey::Create(
          params,
          jwt_rsa_ssa_pss_private_key.GetPublicKey().GetModulus(
              GetPartialKeyAccess()),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!rsa_ssa_pss_public_key.ok()) {
    return rsa_ssa_pss_public_key.status();
  }
  util::StatusOr<RsaSsaPssPrivateKey> raw_rsa_ssa_pss_private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*rsa_ssa_pss_public_key)
          .SetPrimeP(
              jwt_rsa_ssa_pss_private_key.GetPrimeP(GetPartialKeyAccess()))
          .SetPrimeQ(
              jwt_rsa_ssa_pss_private_key.GetPrimeQ(GetPartialKeyAccess()))
          .SetPrivateExponent(jwt_rsa_ssa_pss_private_key.GetPrivateExponent())
          .SetPrimeExponentP(jwt_rsa_ssa_pss_private_key.GetPrimeExponentP())
          .SetPrimeExponentQ(jwt_rsa_ssa_pss_private_key.GetPrimeExponentQ())
          .SetCrtCoefficient(jwt_rsa_ssa_pss_private_key.GetCrtCoefficient())
          .Build(GetPartialKeyAccess());
  if (!rsa_ssa_pss_public_key.ok()) {
    return rsa_ssa_pss_public_key.status();
  }
  return subtle::RsaSsaPssSignBoringSsl::New(*raw_rsa_ssa_pss_private_key);
}

util::StatusOr<RsaSsaPssParameters> RawRsaSsaPssParamsFromJwtRsaSsaPssParams(
    const JwtRsaSsaPssParameters& params) {
  RsaSsaPssParameters::Builder builder;
  builder.SetModulusSizeInBits(params.GetModulusSizeInBits());
  builder.SetPublicExponent(params.GetPublicExponent());
  builder.SetVariant(RsaSsaPssParameters::Variant::kNoPrefix);
  // See https://datatracker.ietf.org/doc/html/rfc7518#section-3.5.
  switch (params.GetAlgorithm()) {
    case JwtRsaSsaPssParameters::Algorithm::kPs256:
      builder.SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256);
      builder.SetSigHashType(RsaSsaPssParameters::HashType::kSha256);
      builder.SetSaltLengthInBytes(32);
      break;
    case JwtRsaSsaPssParameters::Algorithm::kPs384:
      builder.SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384);
      builder.SetSigHashType(RsaSsaPssParameters::HashType::kSha384);
      builder.SetSaltLengthInBytes(48);
      break;
    case JwtRsaSsaPssParameters::Algorithm::kPs512:
      builder.SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512);
      builder.SetSigHashType(RsaSsaPssParameters::HashType::kSha512);
      builder.SetSaltLengthInBytes(64);
      break;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported algorithm: ", params.GetAlgorithm()));
  }
  return builder.Build();
}

util::StatusOr<std::string> AlgorithmName(
    const JwtRsaSsaPssParameters::Algorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssParameters::Algorithm::kPs256:
      return std::string("PS256");
    case JwtRsaSsaPssParameters::Algorithm::kPs384:
      return std::string("PS3072");
    case JwtRsaSsaPssParameters::Algorithm::kPs512:
      return std::string("PS4096");
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
  }
}

util::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
NewJwtRsaSsaPssSignInternal(
    const JwtRsaSsaPssPrivateKey& jwt_rsa_ssa_pss_private_key) {
  const JwtRsaSsaPssParameters* jwt_rsa_ssa_pss_params =
      dynamic_cast<const JwtRsaSsaPssParameters*>(
          &jwt_rsa_ssa_pss_private_key.GetParameters());
  if (jwt_rsa_ssa_pss_params == nullptr) {
    // Should never happen.
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to cast JwtRsaSsaPssParameters");
  }

  util::StatusOr<RsaSsaPssParameters> raw_rsa_ssa_pss_params =
      RawRsaSsaPssParamsFromJwtRsaSsaPssParams(*jwt_rsa_ssa_pss_params);
  if (!raw_rsa_ssa_pss_params.ok()) {
    return raw_rsa_ssa_pss_params.status();
  }

  util::StatusOr<std::unique_ptr<PublicKeySign>> raw_signer =
      NewRsaSsaPssSigner(*raw_rsa_ssa_pss_params, jwt_rsa_ssa_pss_private_key);
  if (!raw_signer.ok()) {
    return raw_signer.status();
  }

  util::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_rsa_ssa_pss_params->GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_rsa_ssa_pss_params->GetKidStrategy()) {
    case JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId: {
      std::string kid =
          jwt_rsa_ssa_pss_private_key.GetPublicKey().GetKid().value();
      // NOTE: This currently cannot be tested using Tink public APIs: the
      // keyset wrapper always deals with "RAW" keys.
      // https://github.com/tink-crypto/tink-cc/blob/ed2008a7b9f09b726a9fff4d96bb9b18093e71c3/tink/internal/keyset_wrapper_impl.h#L83
      return JwtPublicKeySignImpl::WithKid(*std::move(raw_signer),
                                           *algorithm_name, kid);
    }
    case JwtRsaSsaPssParameters::KidStrategy::kCustom: {
      std::string custom_kid =
          jwt_rsa_ssa_pss_private_key.GetPublicKey().GetKid().value();
      return JwtPublicKeySignImpl::RawWithCustomKid(
          *std::move(raw_signer), *algorithm_name, custom_kid);
    }
    case JwtRsaSsaPssParameters::KidStrategy::kIgnored:
      return JwtPublicKeySignImpl::Raw(*std::move(raw_signer), *algorithm_name);
    default:
      // Should never happen.
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

util::StatusOr<std::unique_ptr<JwtPublicKeyVerifyInternal>>
NewJwtRsaSsaPssVerifyInternal(
    const JwtRsaSsaPssPublicKey& jwt_rsa_ssa_pss_public_key) {
  const JwtRsaSsaPssParameters* jwt_rsa_ssa_pss_params =
      dynamic_cast<const JwtRsaSsaPssParameters*>(
          &jwt_rsa_ssa_pss_public_key.GetParameters());
  if (jwt_rsa_ssa_pss_params == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to cast JwtRsaSsaPssParameters");
  }
  util::StatusOr<RsaSsaPssParameters> raw_rsa_ssa_pss_parameters =
      RawRsaSsaPssParamsFromJwtRsaSsaPssParams(*jwt_rsa_ssa_pss_params);
  if (!raw_rsa_ssa_pss_parameters.ok()) {
    return raw_rsa_ssa_pss_parameters.status();
  }
  util::StatusOr<RsaSsaPssPublicKey> rsa_ssa_pss_public_key =
      RsaSsaPssPublicKey::Create(
          raw_rsa_ssa_pss_parameters.value(),
          jwt_rsa_ssa_pss_public_key.GetModulus(GetPartialKeyAccess()),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!rsa_ssa_pss_public_key.ok()) {
    return rsa_ssa_pss_public_key.status();
  }

  util::StatusOr<std::unique_ptr<PublicKeyVerify>>
      rsa_ssa_pss_verify_boringssl =
          subtle::RsaSsaPssVerifyBoringSsl::New(*rsa_ssa_pss_public_key);

  util::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_rsa_ssa_pss_params->GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_rsa_ssa_pss_params->GetKidStrategy()) {
    case JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId: {
      std::string kid = jwt_rsa_ssa_pss_public_key.GetKid().value();
      // NOTE: This currently cannot be tested using Tink public APIs: the
      // keyset wrapper always deals with "RAW" keys.
      // https://github.com/tink-crypto/tink-cc/blob/ed2008a7b9f09b726a9fff4d96bb9b18093e71c3/tink/internal/keyset_wrapper_impl.h#L83
      return JwtPublicKeyVerifyImpl::WithKid(
          *std::move(rsa_ssa_pss_verify_boringssl), *algorithm_name, kid);
    }
    case JwtRsaSsaPssParameters::KidStrategy::kCustom: {
      std::string custom_kid = jwt_rsa_ssa_pss_public_key.GetKid().value();
      return JwtPublicKeyVerifyImpl::RawWithCustomKid(
          *std::move(rsa_ssa_pss_verify_boringssl), *algorithm_name,
          custom_kid);
    }
    case JwtRsaSsaPssParameters::KidStrategy::kIgnored:
      return JwtPublicKeyVerifyImpl::Raw(
          *std::move(rsa_ssa_pss_verify_boringssl), *algorithm_name);
    default:
      // Should never happen.
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

}  // namespace

util::Status AddJwtSignatureV0(Configuration& config) {
  util::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<JwtPublicKeySignWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<JwtPublicKeyVerifyWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  // JWT ECDSA.
  status = RegisterJwtEcdsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status =
      internal::ConfigurationImpl::AddPrimitiveGetter<JwtPublicKeySignInternal,
                                                      JwtEcdsaPrivateKey>(
          NewJwtEcdsaSignInternal, config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveGetter<
      JwtPublicKeyVerifyInternal, JwtEcdsaPublicKey>(NewJwtEcdsaVerifyInternal,
                                                     config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtEcdsaSignKeyManager>(),
      absl::make_unique<JwtEcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }

  // JWT RSA SSA PKCS1.
  status = RegisterJwtRsaSsaPkcs1ProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status =
      internal::ConfigurationImpl::AddPrimitiveGetter<JwtPublicKeySignInternal,
                                                      JwtRsaSsaPkcs1PrivateKey>(
          NewJwtRsaSsaPkcs1SignInternal, config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveGetter<
      JwtPublicKeyVerifyInternal, JwtRsaSsaPkcs1PublicKey>(
      NewJwtRsaSsaPkcs1VerifyInternal, config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtRsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<JwtRsaSsaPkcs1VerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }

  // JWT RSA SSA PSS.
  status = RegisterJwtRsaSsaPssProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status =
      internal::ConfigurationImpl::AddPrimitiveGetter<JwtPublicKeySignInternal,
                                                      JwtRsaSsaPssPrivateKey>(
          NewJwtRsaSsaPssSignInternal, config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveGetter<
      JwtPublicKeyVerifyInternal, JwtRsaSsaPssPublicKey>(
      NewJwtRsaSsaPssVerifyInternal, config);
  if (!status.ok()) {
    return status;
  }

  return internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtRsaSsaPssSignKeyManager>(),
      absl::make_unique<JwtRsaSsaPssVerifyKeyManager>(), config);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
