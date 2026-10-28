// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/predefined_signature_parameters.h"

#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/slh_dsa_parameters.h"

namespace tink_parameters {
namespace {

using ::crypto::tink::BigInteger;
using ::crypto::tink::EcdsaParameters;
using ::crypto::tink::Ed25519Parameters;
using ::crypto::tink::MlDsaParameters;
using ::crypto::tink::RsaSsaPkcs1Parameters;
using ::crypto::tink::RsaSsaPssParameters;
using ::crypto::tink::SlhDsaParameters;

// Big-endian encoding of the RSA public exponent 65537 (aka F4).
BigInteger F4() { return BigInteger(absl::string_view("\x01\x00\x01", 3)); }

EcdsaParameters CreateEcdsaParameters(
    EcdsaParameters::HashType hash_type, EcdsaParameters::CurveType curve_type,
    EcdsaParameters::SignatureEncoding signature_encoding,
    EcdsaParameters::Variant variant) {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetHashType(hash_type)
          .SetCurveType(curve_type)
          .SetSignatureEncoding(signature_encoding)
          .SetVariant(variant)
          .Build();
  ABSL_CHECK_OK(parameters);
  return *std::move(parameters);
}

RsaSsaPkcs1Parameters CreateRsaSsaPkcs1Parameters(
    RsaSsaPkcs1Parameters::HashType hash_type, int modulus_size_in_bits,
    RsaSsaPkcs1Parameters::Variant variant) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetHashType(hash_type)
          .SetModulusSizeInBits(modulus_size_in_bits)
          .SetPublicExponent(F4())
          .SetVariant(variant)
          .Build();
  ABSL_CHECK_OK(parameters);
  return *std::move(parameters);
}

RsaSsaPssParameters CreateRsaSsaPssParameters(
    RsaSsaPssParameters::HashType hash_type, int salt_length_in_bytes,
    int modulus_size_in_bits, RsaSsaPssParameters::Variant variant) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetSigHashType(hash_type)
          .SetMgf1HashType(hash_type)
          .SetSaltLengthInBytes(salt_length_in_bytes)
          .SetModulusSizeInBits(modulus_size_in_bits)
          .SetPublicExponent(F4())
          .SetVariant(variant)
          .Build();
  ABSL_CHECK_OK(parameters);
  return *std::move(parameters);
}

SlhDsaParameters CreateSlhDsaSha2_128sParameters(
    SlhDsaParameters::Variant variant) {
  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, variant);
  ABSL_CHECK_OK(parameters);
  return *std::move(parameters);
}

MlDsaParameters CreateMlDsaParameters(MlDsaParameters::Instance instance,
                                      MlDsaParameters::Variant variant) {
  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(instance, variant);
  ABSL_CHECK_OK(parameters);
  return *std::move(parameters);
}

Ed25519Parameters CreateEd25519Parameters(Ed25519Parameters::Variant variant) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(variant);
  ABSL_CHECK_OK(parameters);
  return *std::move(parameters);
}

}  // namespace

const EcdsaParameters& EcdsaP256() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha256,
                            EcdsaParameters::CurveType::kNistP256,
                            EcdsaParameters::SignatureEncoding::kDer,
                            EcdsaParameters::Variant::kTink));
  return *kParameters;
}

const EcdsaParameters& EcdsaP256RawDer() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha256,
                            EcdsaParameters::CurveType::kNistP256,
                            EcdsaParameters::SignatureEncoding::kDer,
                            EcdsaParameters::Variant::kNoPrefix));
  return *kParameters;
}

const EcdsaParameters& EcdsaP384Sha384() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha384,
                            EcdsaParameters::CurveType::kNistP384,
                            EcdsaParameters::SignatureEncoding::kDer,
                            EcdsaParameters::Variant::kTink));
  return *kParameters;
}

const EcdsaParameters& EcdsaP384Sha512() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha512,
                            EcdsaParameters::CurveType::kNistP384,
                            EcdsaParameters::SignatureEncoding::kDer,
                            EcdsaParameters::Variant::kTink));
  return *kParameters;
}

const EcdsaParameters& EcdsaP521() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha512,
                            EcdsaParameters::CurveType::kNistP521,
                            EcdsaParameters::SignatureEncoding::kDer,
                            EcdsaParameters::Variant::kTink));
  return *kParameters;
}

const EcdsaParameters& EcdsaP256Ieee() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha256,
                            EcdsaParameters::CurveType::kNistP256,
                            EcdsaParameters::SignatureEncoding::kIeeeP1363,
                            EcdsaParameters::Variant::kTink));
  return *kParameters;
}

const EcdsaParameters& EcdsaP384Ieee() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha512,
                            EcdsaParameters::CurveType::kNistP384,
                            EcdsaParameters::SignatureEncoding::kIeeeP1363,
                            EcdsaParameters::Variant::kTink));
  return *kParameters;
}

const EcdsaParameters& EcdsaP256Raw() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha256,
                            EcdsaParameters::CurveType::kNistP256,
                            EcdsaParameters::SignatureEncoding::kIeeeP1363,
                            EcdsaParameters::Variant::kNoPrefix));
  return *kParameters;
}

const EcdsaParameters& EcdsaP521Ieee() {
  static const absl::NoDestructor<EcdsaParameters> kParameters(
      CreateEcdsaParameters(EcdsaParameters::HashType::kSha512,
                            EcdsaParameters::CurveType::kNistP521,
                            EcdsaParameters::SignatureEncoding::kIeeeP1363,
                            EcdsaParameters::Variant::kTink));
  return *kParameters;
}

const Ed25519Parameters& Ed25519() {
  static const absl::NoDestructor<Ed25519Parameters> kParameters(
      CreateEd25519Parameters(Ed25519Parameters::Variant::kTink));
  return *kParameters;
}

const Ed25519Parameters& Ed25519WithRawOutput() {
  static const absl::NoDestructor<Ed25519Parameters> kParameters(
      CreateEd25519Parameters(Ed25519Parameters::Variant::kNoPrefix));
  return *kParameters;
}

const RsaSsaPkcs1Parameters& RsaSsaPkcs13072Sha256F4() {
  static const absl::NoDestructor<RsaSsaPkcs1Parameters> kParameters(
      CreateRsaSsaPkcs1Parameters(RsaSsaPkcs1Parameters::HashType::kSha256,
                                  /*modulus_size_in_bits=*/3072,
                                  RsaSsaPkcs1Parameters::Variant::kTink));
  return *kParameters;
}

const RsaSsaPkcs1Parameters& RsaSsaPkcs13072Sha256F4NoPrefix() {
  static const absl::NoDestructor<RsaSsaPkcs1Parameters> kParameters(
      CreateRsaSsaPkcs1Parameters(RsaSsaPkcs1Parameters::HashType::kSha256,
                                  /*modulus_size_in_bits=*/3072,
                                  RsaSsaPkcs1Parameters::Variant::kNoPrefix));
  return *kParameters;
}

const RsaSsaPkcs1Parameters& RsaSsaPkcs14096Sha512F4() {
  static const absl::NoDestructor<RsaSsaPkcs1Parameters> kParameters(
      CreateRsaSsaPkcs1Parameters(RsaSsaPkcs1Parameters::HashType::kSha512,
                                  /*modulus_size_in_bits=*/4096,
                                  RsaSsaPkcs1Parameters::Variant::kTink));
  return *kParameters;
}

const RsaSsaPssParameters& RsaSsaPss3072Sha256Sha256F4() {
  static const absl::NoDestructor<RsaSsaPssParameters> kParameters(
      CreateRsaSsaPssParameters(RsaSsaPssParameters::HashType::kSha256,
                                /*salt_length_in_bytes=*/32,
                                /*modulus_size_in_bits=*/3072,
                                RsaSsaPssParameters::Variant::kTink));
  return *kParameters;
}

const RsaSsaPssParameters& RsaSsaPss4096Sha512Sha512F4() {
  static const absl::NoDestructor<RsaSsaPssParameters> kParameters(
      CreateRsaSsaPssParameters(RsaSsaPssParameters::HashType::kSha512,
                                /*salt_length_in_bytes=*/64,
                                /*modulus_size_in_bits=*/4096,
                                RsaSsaPssParameters::Variant::kTink));
  return *kParameters;
}

const MlDsaParameters& MlDsa44() {
  static const absl::NoDestructor<MlDsaParameters> kParameters(
      CreateMlDsaParameters(MlDsaParameters::Instance::kMlDsa44,
                            MlDsaParameters::Variant::kTink));
  return *kParameters;
}

const MlDsaParameters& MlDsa44NoPrefix() {
  static const absl::NoDestructor<MlDsaParameters> kParameters(
      CreateMlDsaParameters(MlDsaParameters::Instance::kMlDsa44,
                            MlDsaParameters::Variant::kNoPrefix));
  return *kParameters;
}

const SlhDsaParameters& SlhDsaSha2_128s() {
  static const absl::NoDestructor<SlhDsaParameters> kParameters(
      CreateSlhDsaSha2_128sParameters(SlhDsaParameters::Variant::kTink));
  return *kParameters;
}

const SlhDsaParameters& SlhDsaSha2_128sNoPrefix() {
  static const absl::NoDestructor<SlhDsaParameters> kParameters(
      CreateSlhDsaSha2_128sParameters(SlhDsaParameters::Variant::kNoPrefix));
  return *kParameters;
}

}  // namespace tink_parameters
