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

#ifndef TINK_SIGNATURE_PREDEFINED_SIGNATURE_PARAMETERS_H_
#define TINK_SIGNATURE_PREDEFINED_SIGNATURE_PARAMETERS_H_

#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/slh_dsa_parameters.h"

namespace tink_parameters {

// Pre-generated `Parameters` objects for `PublicKeySign` and `PublicKeyVerify`
// keys.
//
// Note: if you want to keep dependencies small, consider inlining the
// parameters here.

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: DER
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kTink`
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP256()`.
const crypto::tink::EcdsaParameters& EcdsaP256();

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: DER
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kNoPrefix`
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP256RawDer()`.
const crypto::tink::EcdsaParameters& EcdsaP256RawDer();

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-384
//   - Signature encoding: DER
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kTink`
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP384Sha512()`.
const crypto::tink::EcdsaParameters& EcdsaP384Sha512();

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-521
//   - Signature encoding: DER
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kTink`
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP521()`.
const crypto::tink::EcdsaParameters& EcdsaP521();

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: IEEE_P1363 (this is the encoding that JWS and
//     WebCrypto use).
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kTink`
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP256Ieee()`.
const crypto::tink::EcdsaParameters& EcdsaP256Ieee();

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-384
//   - Signature encoding: IEEE_P1363 (this is the encoding that JWS and
//     WebCrypto use).
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kTink`
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP384Ieee()`.
const crypto::tink::EcdsaParameters& EcdsaP384Ieee();

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: IEEE_P1363 (this is the encoding that JWS and
//     WebCrypto use).
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kNoPrefix`
//
// Digital signatures generated using these parameters are 64 bytes.
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP256Raw()`.
const crypto::tink::EcdsaParameters& EcdsaP256Raw();

// Returns parameters that generate new instances of `EcdsaPrivateKey` objects
// with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-521
//   - Signature encoding: IEEE_P1363 (this is the encoding that JWS and
//     WebCrypto use).
//   - Variant: `crypto::tink::EcdsaParameters::Variant::kTink`
// Equivalent to `crypto::tink::SignatureKeyTemplates::EcdsaP521Ieee()`.
const crypto::tink::EcdsaParameters& EcdsaP521Ieee();

// Returns parameters that generate new instances of `Ed25519PrivateKey`
// objects with variant `crypto::tink::Ed25519Parameters::Variant::kTink`.
// Equivalent to `crypto::tink::SignatureKeyTemplates::Ed25519()`.
const crypto::tink::Ed25519Parameters& Ed25519();

// Returns parameters that generate new instances of `Ed25519PrivateKey`
// objects with variant `crypto::tink::Ed25519Parameters::Variant::kNoPrefix`.
//
// The difference between `Ed25519WithRawOutput()` and `Ed25519()` is the
// format of signatures generated. `Ed25519WithRawOutput()` generates
// signatures without an output prefix, which are 64 bytes long.
// Equivalent to `crypto::tink::SignatureKeyTemplates::Ed25519WithRawOutput()`.
const crypto::tink::Ed25519Parameters& Ed25519WithRawOutput();

// Returns parameters that generate new instances of `RsaSsaPkcs1PrivateKey`
// objects with the following parameters:
//   - Hash function: SHA256
//   - Modulus size: 3072 bit
//   - Public exponent: 65537 (aka F4)
//   - Variant: `crypto::tink::RsaSsaPkcs1Parameters::Variant::kTink`
// Equivalent to
// `crypto::tink::SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4()`.
const crypto::tink::RsaSsaPkcs1Parameters& RsaSsaPkcs13072Sha256F4();

// Returns parameters that generate new instances of `RsaSsaPkcs1PrivateKey`
// objects with the following parameters:
//   - Hash function: SHA256
//   - Modulus size: 3072 bit
//   - Public exponent: 65537 (aka F4)
//   - Variant: `crypto::tink::RsaSsaPkcs1Parameters::Variant::kNoPrefix`
const crypto::tink::RsaSsaPkcs1Parameters& RsaSsaPkcs13072Sha256F4NoPrefix();

// Returns parameters that generate new instances of `RsaSsaPkcs1PrivateKey`
// objects with the following parameters:
//   - Hash function: SHA512
//   - Modulus size: 4096 bit
//   - Public exponent: 65537 (aka F4)
//   - Variant: `crypto::tink::RsaSsaPkcs1Parameters::Variant::kTink`
// Equivalent to
// `crypto::tink::SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4()`.
const crypto::tink::RsaSsaPkcs1Parameters& RsaSsaPkcs14096Sha512F4();

// Returns parameters that generate new instances of `RsaSsaPssPrivateKey`
// objects with the following parameters:
//   - Signature hash: SHA256
//   - MGF1 hash: SHA256
//   - Salt length: 32 (i.e., SHA256's output length)
//   - Modulus size: 3072 bit
//   - Public exponent: 65537 (aka F4)
//   - Variant: `crypto::tink::RsaSsaPssParameters::Variant::kTink`
// Equivalent to
// `crypto::tink::SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4()`.
const crypto::tink::RsaSsaPssParameters& RsaSsaPss3072Sha256Sha256F4();

// Returns parameters that generate new instances of `RsaSsaPssPrivateKey`
// objects with the following parameters:
//   - Signature hash: SHA512
//   - MGF1 hash: SHA512
//   - Salt length: 64 (i.e., SHA512's output length)
//   - Modulus size: 4096 bit
//   - Public exponent: 65537 (aka F4)
//   - Variant: `crypto::tink::RsaSsaPssParameters::Variant::kTink`
// Equivalent to
// `crypto::tink::SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4()`.
const crypto::tink::RsaSsaPssParameters& RsaSsaPss4096Sha512Sha512F4();

// Returns parameters that generate new instances of `MlDsaPrivateKey`
// objects with the following parameters:
//   - ML-DSA instance: ML-DSA-44
//   - Variant: `crypto::tink::MlDsaParameters::Variant::kTink`
const crypto::tink::MlDsaParameters& MlDsa44();

// Returns parameters that generate new instances of `MlDsaPrivateKey`
// objects with the following parameters:
//   - ML-DSA instance: ML-DSA-44
//   - Variant: `crypto::tink::MlDsaParameters::Variant::kNoPrefix`
const crypto::tink::MlDsaParameters& MlDsa44NoPrefix();

// Returns parameters that generate new instances of `SlhDsaPrivateKey`
// objects with the following parameters:
//   - Hash type: SHA-2
//   - Private key size: 64 bytes
//   - Signature type: Small
//   - Variant: `crypto::tink::SlhDsaParameters::Variant::kTink`
const crypto::tink::SlhDsaParameters& SlhDsaSha2_128s();

// Returns parameters that generate new instances of `SlhDsaPrivateKey`
// objects with the following parameters:
//   - Hash type: SHA-2
//   - Private key size: 64 bytes
//   - Signature type: Small
//   - Variant: `crypto::tink::SlhDsaParameters::Variant::kNoPrefix`
const crypto::tink::SlhDsaParameters& SlhDsaSha2_128sNoPrefix();

}  // namespace tink_parameters

#endif  // TINK_SIGNATURE_PREDEFINED_SIGNATURE_PARAMETERS_H_
