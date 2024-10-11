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

#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// Verifies an RSA-SSA PSS signature using `rsa_public_key` over
// `message_digest`; `message_digest` is the digest of the original message
// computed with `sig_md`, `mgf1_md` is the hash function for generating the
// mask (if nullptr, `sig_md` is used), and `salt_length` the salt length in
// bytes.
//
// This function is equivalent to BoringSSL's `RSA_verify_pss_mgf1`[1], and
// differs from it only in that it uses `RSA_public_decrypt` instead of
// `RSA_sign_raw`, because the latter is not defined in OpenSSL. In BoringSSL
// `RSA_public_decrypt` is essentially an alias for `RSA_verify_raw` [2].
//
// OpenSSL uses the same sequence of API calls [3].
//
// [1]https://github.com/google/boringssl/blob/master/crypto/fipsmodule/rsa/rsa.c#L633
// [2]https://github.com/google/boringssl/blob/master/crypto/fipsmodule/rsa/rsa.c#L354
// [3]https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pmeth.c#L279
util::Status SslRsaSsaPssVerify(RSA* rsa_public_key,
                                absl::string_view signature,
                                absl::string_view message_digest,
                                const EVP_MD* sig_md, const EVP_MD* mgf1_md,
                                int32_t salt_length) {
  const int kHashSize = EVP_MD_size(sig_md);
  // Make sure the size of the digest is correct.
  if (message_digest.size() != kHashSize) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Size of the digest doesn't match the one "
                     "of the hashing algorithm; expected ",
                     kHashSize, " got ", message_digest.size()));
  }
  const int kRsaModulusSize = RSA_size(rsa_public_key);
  std::vector<uint8_t> recovered_message_digest(kRsaModulusSize);
  int recovered_message_digest_size = RSA_public_decrypt(
      /*flen=*/signature.size(),
      /*from=*/reinterpret_cast<const uint8_t*>(signature.data()),
      /*to=*/recovered_message_digest.data(), /*rsa=*/rsa_public_key,
      /*padding=*/RSA_NO_PADDING);
  if (recovered_message_digest_size != kRsaModulusSize) {
    internal::GetSslErrors();
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid signature size (likely an incorrect key is "
                     "used); expected ",
                     kRsaModulusSize, " got ", recovered_message_digest_size));
  }
  if (RSA_verify_PKCS1_PSS_mgf1(
          rsa_public_key,
          reinterpret_cast<const uint8_t*>(message_digest.data()), sig_md,
          mgf1_md, recovered_message_digest.data(), salt_length) != 1) {
    internal::GetSslErrors();
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "PSS padding verification failed.");
  }
  return util::OkStatus();
}

util::StatusOr<subtle::HashType> ToSubtle(
    crypto::tink::RsaSsaPssParameters::HashType hash_type) {
  switch (hash_type) {
    case crypto::tink::RsaSsaPssParameters::HashType::kSha256:
      return subtle::HashType::SHA256;
    case crypto::tink::RsaSsaPssParameters::HashType::kSha384:
      return subtle::HashType::SHA384;
    case crypto::tink::RsaSsaPssParameters::HashType::kSha512:
      return subtle::HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported hash:", hash_type));
  }
}

}  // namespace

util::StatusOr<std::unique_ptr<PublicKeyVerify>> RsaSsaPssVerifyBoringSsl::New(
    const RsaSsaPssPublicKey& key) {
  internal::RsaPublicKey public_key;
  public_key.n = std::string(key.GetModulus(GetPartialKeyAccess()).GetValue());
  public_key.e =
      std::string(key.GetParameters().GetPublicExponent().GetValue());
  internal::RsaSsaPssParams params;
  util::StatusOr<subtle::HashType> mgf1_hash =
      ToSubtle(key.GetParameters().GetMgf1HashType());
  if (!mgf1_hash.ok()) {
    return mgf1_hash.status();
  }
  params.mgf1_hash = *mgf1_hash;
  util::StatusOr<subtle::HashType> sig_hash =
      ToSubtle(key.GetParameters().GetSigHashType());
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }
  params.sig_hash = *sig_hash;
  params.salt_length = key.GetParameters().GetSaltLengthInBytes();
  return New(
      public_key, params, key.GetOutputPrefix(),
      key.GetParameters().GetVariant() == RsaSsaPssParameters::Variant::kLegacy
          ? std::string(1, 0)
          : "");
}

util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>>
RsaSsaPssVerifyBoringSsl::New(const internal::RsaPublicKey& pub_key,
                              const internal::RsaSsaPssParams& params) {
  return New(pub_key, params, "", "");
}

util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>>
RsaSsaPssVerifyBoringSsl::New(const internal::RsaPublicKey& pub_key,
                              const internal::RsaSsaPssParams& params,
                              absl::string_view output_prefix,
                              absl::string_view message_suffix) {
  util::Status res =
      internal::CheckFipsCompatibility<RsaSsaPssVerifyBoringSsl>();
  if (!res.ok()) {
    return res;
  }

  // Check if the hash type is safe to use.
  util::Status is_safe = internal::IsHashTypeSafeForSignature(params.sig_hash);
  if (!is_safe.ok()) {
    return is_safe;
  }
  util::StatusOr<const EVP_MD*> sig_hash =
      internal::EvpHashFromHashType(params.sig_hash);
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }

  // TODO(quannguyen): check mgf1_hash function and salt length.
  util::StatusOr<const EVP_MD*> mgf1_hash =
      internal::EvpHashFromHashType(params.mgf1_hash);
  if (!mgf1_hash.ok()) {
    return mgf1_hash.status();
  }

  // The RSA modulus and exponent are checked as part of the conversion to
  // internal::SslUniquePtr<RSA>.
  util::StatusOr<internal::SslUniquePtr<RSA>> rsa =
      internal::RsaPublicKeyToRsa(pub_key);
  if (!rsa.ok()) {
    return rsa.status();
  }

  return {absl::WrapUnique(new RsaSsaPssVerifyBoringSsl(
      *std::move(rsa), *sig_hash, *mgf1_hash, params.salt_length, output_prefix,
      message_suffix))};
}

util::Status RsaSsaPssVerifyBoringSsl::VerifyWithoutPrefix(
    absl::string_view signature, absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);
  util::StatusOr<std::string> digest = internal::ComputeHash(data, *sig_hash_);
  if (!digest.ok()) {
    return digest.status();
  }
  return SslRsaSsaPssVerify(rsa_.get(), signature, *digest, sig_hash_,
                            mgf1_hash_, salt_length_);
}

util::Status RsaSsaPssVerifyBoringSsl::Verify(absl::string_view signature,
                                              absl::string_view data) const {
  if (output_prefix_.empty() && message_suffix_.empty()) {
    return VerifyWithoutPrefix(signature, data);
  }
  if (!absl::StartsWith(signature, output_prefix_)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "OutputPrefix does not match");
  }
  // Stores a copy of the data in case message_suffix_ is not empty.
  // Needs to stay alive until this method is done.
  std::string data_copy_holder;
  if (!message_suffix_.empty()) {
    data_copy_holder = absl::StrCat(data, message_suffix_);
    data = data_copy_holder;
  }
  return VerifyWithoutPrefix(absl::StripPrefix(signature, output_prefix_),
                             data);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
