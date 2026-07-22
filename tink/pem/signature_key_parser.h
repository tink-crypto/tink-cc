// Copyright 2026 Google LLC
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

#ifndef TINK_PEM_SIGNATURE_KEY_PARSER_H_
#define TINK_PEM_SIGNATURE_KEY_PARSER_H_

#include "absl/base/nullability.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/partial_key_access_token.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"

ABSL_POINTERS_DEFAULT_NONNULL

namespace tink_pem {

// Parses a PEM encoded ECDSA private key into a Tink EcdsaPrivateKey.
//
// It can parse both RFC 5915 SEC1 format ("BEGIN EC PRIVATE KEY") and RFC 5208
// PKCS#8 format ("BEGIN PRIVATE KEY").
absl::StatusOr<crypto::tink::EcdsaPrivateKey> PemToEcdsaPrivateKey(
    absl::string_view pem_private_key,
    const crypto::tink::EcdsaParameters& parameters,
    crypto::tink::SecretKeyAccessToken secret_key_access,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded Ed25519 private key into a Tink Ed25519PrivateKey.
//
// It can parse RFC 5208 PKCS#8 format ("BEGIN PRIVATE KEY").
absl::StatusOr<crypto::tink::Ed25519PrivateKey> PemToEd25519PrivateKey(
    absl::string_view pem_private_key,
    const crypto::tink::Ed25519Parameters& parameters,
    crypto::tink::SecretKeyAccessToken secret_key_access,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded RSA-SSA-PSS private key into a Tink RsaSsaPssPrivateKey.
//
// It can parse both PKCS#1 format ("BEGIN RSA PRIVATE KEY") and RFC 5208
// PKCS#8 format ("BEGIN PRIVATE KEY").
// NOTE: only RFC 3279, 1.2.840.113549.1.1.1 format is supported.
// TODO: b/532411253 - Revisit this if support for other RSA formats is needed.
absl::StatusOr<crypto::tink::RsaSsaPssPrivateKey> PemToRsaSsaPssPrivateKey(
    absl::string_view pem_private_key,
    const crypto::tink::RsaSsaPssParameters& parameters,
    crypto::tink::SecretKeyAccessToken secret_key_access,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded RSA-SSA-PKCS1 private key into a Tink
// RsaSsaPkcs1PrivateKey.
//
// It can parse both PKCS#1 format ("BEGIN RSA PRIVATE KEY") and RFC 5208
// PKCS#8 format ("BEGIN PRIVATE KEY").
// NOTE: only RFC 3279, 1.2.840.113549.1.1.1 format is supported.
// TODO: b/532411253 - Revisit this if support for other RSA formats is needed.
absl::StatusOr<crypto::tink::RsaSsaPkcs1PrivateKey> PemToRsaSsaPkcs1PrivateKey(
    absl::string_view pem_private_key,
    const crypto::tink::RsaSsaPkcs1Parameters& parameters,
    crypto::tink::SecretKeyAccessToken secret_key_access,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded ECDSA public key into a Tink EcdsaPublicKey.
absl::StatusOr<crypto::tink::EcdsaPublicKey> PemToEcdsaPublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::EcdsaParameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded Ed25519 public key into a Tink Ed25519PublicKey.
absl::StatusOr<crypto::tink::Ed25519PublicKey> PemToEd25519PublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::Ed25519Parameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded ML-DSA public key into a Tink MlDsaPublicKey.
absl::StatusOr<crypto::tink::MlDsaPublicKey> PemToMlDsaPublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::MlDsaParameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded RSA-SSA-PSS public key into a Tink RsaSsaPssPublicKey.
absl::StatusOr<crypto::tink::RsaSsaPssPublicKey> PemToRsaSsaPssPublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::RsaSsaPssParameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access);

// Parses a PEM encoded RSA-SSA-PKCS1 public key into a Tink
// RsaSsaPkcs1PublicKey.
absl::StatusOr<crypto::tink::RsaSsaPkcs1PublicKey> PemToRsaSsaPkcs1PublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::RsaSsaPkcs1Parameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access);

}  // namespace tink_pem

#endif  // TINK_PEM_SIGNATURE_KEY_PARSER_H_
