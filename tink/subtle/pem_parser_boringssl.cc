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
#include "tink/subtle/pem_parser_boringssl.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {
constexpr int kBsslOk = 1;

// Verifies that the given RSA pointer `rsa_key` points to a valid RSA key.
absl::Status VerifyRsaKey(const RSA* rsa_key) {
  if (rsa_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA key format");
  }
  // Check the key parameters.
  if (RSA_check_key(rsa_key) != kBsslOk) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA key format");
  }
  return absl::OkStatus();
}

// Converts an OpenSSL BIO (i.e., basic IO stream), `bio`, into a string.
absl::StatusOr<std::string> ConvertBioToString(BIO* bio) {
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  std::string pem_material;
  if (mem->data && mem->length) {
    pem_material.assign(mem->data, mem->length);
  }
  if (pem_material.empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to retrieve key material from BIO");
  }
  return pem_material;
}

// We explicitly set a failing passphrase callback function to make sure no
// default callback routine is used.
static int FailingPassphraseCallback(char* buf, int buf_size, int rwflag,
                                     void* u) {
  return -1;
}

}  // namespace

absl::StatusOr<std::unique_ptr<internal::RsaPublicKey>>
PemParser::ParseRsaPublicKey(absl::string_view pem_serialized_key) {
  // Read the RSA key into EVP_PKEY.
  internal::SslUniquePtr<BIO> rsa_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(rsa_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  internal::SslUniquePtr<EVP_PKEY> evp_rsa_key(
      PEM_read_bio_PUBKEY(rsa_key_bio.get(), /*x=*/nullptr,
                          &FailingPassphraseCallback, /*u=*/nullptr));

  if (evp_rsa_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Public Key parsing failed");
  }
  // No need to free bssl_rsa_key after use.
  const RSA* bssl_rsa_key = EVP_PKEY_get0_RSA(evp_rsa_key.get());
  absl::Status verification_res = internal::RsaCheckPublicKey(bssl_rsa_key);
  if (!verification_res.ok()) {
    return verification_res;
  }

  // Get the public key parameters.
  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(bssl_rsa_key, &n_bn, &e_bn, &d_bn);

  // Public key should not have d_bn set.
  if (d_bn != nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA Public Key format");
  }

  // We are only interested in e and n.
  auto n_str = internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  auto e_str = internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  if (!n_str.ok()) {
    return n_str.status();
  }
  if (!e_str.ok()) {
    return e_str.status();
  }
  auto rsa_public_key = std::make_unique<internal::RsaPublicKey>();
  rsa_public_key->e = *std::move(e_str);
  rsa_public_key->n = *std::move(n_str);

  return std::move(rsa_public_key);
}

absl::StatusOr<std::unique_ptr<internal::RsaPrivateKey>>
PemParser::ParseRsaPrivateKey(absl::string_view pem_serialized_key) {
  // Read the private key into EVP_PKEY.
  internal::SslUniquePtr<BIO> rsa_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(rsa_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  // BoringSSL APIs to parse the PEM data.
  internal::SslUniquePtr<EVP_PKEY> evp_rsa_key(
      PEM_read_bio_PrivateKey(rsa_key_bio.get(), /*x=*/nullptr,
                              &FailingPassphraseCallback, /*u=*/nullptr));

  if (evp_rsa_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Private Key parsing failed");
  }

  // No need to free bssl_rsa_key after use.
  const RSA* bssl_rsa_key = EVP_PKEY_get0_RSA(evp_rsa_key.get());

  auto is_valid_key = VerifyRsaKey(bssl_rsa_key);
  if (!is_valid_key.ok()) {
    return is_valid_key;
  }

  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(bssl_rsa_key, &n_bn, &e_bn, &d_bn);

  // Save exponents.
  auto rsa_private_key = std::make_unique<internal::RsaPrivateKey>();
  auto n_str = internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  auto e_str = internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  auto d_str = internal::BignumToSecretData(d_bn, BN_num_bytes(d_bn));
  if (!n_str.ok()) {
    return n_str.status();
  }
  if (!e_str.ok()) {
    return e_str.status();
  }
  if (!d_str.ok()) {
    return d_str.status();
  }
  rsa_private_key->n = *std::move(n_str);
  rsa_private_key->e = *std::move(e_str);
  rsa_private_key->d = *std::move(d_str);

  // Save factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(bssl_rsa_key, &p_bn, &q_bn);
  auto p_str = internal::BignumToSecretData(p_bn, BN_num_bytes(p_bn));
  auto q_str = internal::BignumToSecretData(q_bn, BN_num_bytes(q_bn));
  if (!p_str.ok()) {
    return p_str.status();
  }
  if (!q_str.ok()) {
    return q_str.status();
  }
  rsa_private_key->p = *std::move(p_str);
  rsa_private_key->q = *std::move(q_str);

  // Save CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(bssl_rsa_key, &dp_bn, &dq_bn, &crt_bn);
  auto dp_str = internal::BignumToSecretData(dp_bn, BN_num_bytes(dp_bn));
  auto dq_str = internal::BignumToSecretData(dq_bn, BN_num_bytes(dq_bn));
  auto crt_str = internal::BignumToSecretData(crt_bn, BN_num_bytes(crt_bn));
  if (!dp_str.ok()) {
    return dp_str.status();
  }
  if (!dq_str.ok()) {
    return dq_str.status();
  }
  if (!crt_str.ok()) {
    return crt_str.status();
  }
  rsa_private_key->dp = *std::move(dp_str);
  rsa_private_key->dq = *std::move(dq_str);
  rsa_private_key->crt = *std::move(crt_str);

  return std::move(rsa_private_key);
}

absl::StatusOr<std::string> PemParser::WriteRsaPublicKey(
    const internal::RsaPublicKey& rsa_public_key) {
  auto rsa_statusor = internal::RsaPublicKeyToRsa(rsa_public_key);
  if (!rsa_statusor.ok()) {
    return rsa_statusor.status();
  }

  internal::SslUniquePtr<RSA> rsa = *std::move(rsa_statusor);
  internal::SslUniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_RSA_PUBKEY(bio.get(), rsa.get())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to write openssl RSA key to write bio");
  }
  return ConvertBioToString(bio.get());
}

absl::StatusOr<std::string> PemParser::WriteRsaPrivateKey(
    const internal::RsaPrivateKey& rsa_private_key) {
  auto rsa_statusor = internal::RsaPrivateKeyToRsa(rsa_private_key);
  if (!rsa_statusor.ok()) {
    return rsa_statusor.status();
  }

  internal::SslUniquePtr<RSA> rsa = *std::move(rsa_statusor);
  internal::SslUniquePtr<EVP_PKEY> evp(EVP_PKEY_new());
  EVP_PKEY_set1_RSA(evp.get(), rsa.get());

  internal::SslUniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_PrivateKey(bio.get(), evp.get(),
                                /*enc=*/nullptr, /*kstr=*/nullptr,
                                /*klen=*/0,
                                /*cb=*/nullptr, /*u=*/nullptr)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to write openssl RSA key to write bio");
  }
  return ConvertBioToString(bio.get());
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
