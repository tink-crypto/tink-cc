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

#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPkcs1VerifyBoringSsl::New(const RsaSsaPkcs1PublicKey& key) {
  internal::RsaPublicKey public_key;
  public_key.n = std::string(key.GetModulus(GetPartialKeyAccess()).GetValue());
  public_key.e =
      std::string(key.GetParameters().GetPublicExponent().GetValue());
  internal::RsaSsaPkcs1Params params;
  switch (key.GetParameters().GetHashType()) {
    case crypto::tink::RsaSsaPkcs1Parameters::HashType::kSha256:
      params.hash_type = SHA256;
      break;
    case crypto::tink::RsaSsaPkcs1Parameters::HashType::kSha384:
      params.hash_type = SHA384;
      break;
    case crypto::tink::RsaSsaPkcs1Parameters::HashType::kSha512:
      params.hash_type = SHA512;
      break;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported hash:", key.GetParameters().GetHashType()));
  }
  return New(public_key, params, key.GetOutputPrefix(),
             key.GetParameters().GetVariant() ==
                     RsaSsaPkcs1Parameters::Variant::kLegacy
                 ? std::string(1, 0)
                 : "");
}

util::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>>
RsaSsaPkcs1VerifyBoringSsl::New(const internal::RsaPublicKey& pub_key,
                                const internal::RsaSsaPkcs1Params& params) {
  return New(pub_key, params, "", "");
}

util::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>>
RsaSsaPkcs1VerifyBoringSsl::New(const internal::RsaPublicKey& pub_key,
                                const internal::RsaSsaPkcs1Params& params,
                                absl::string_view output_prefix,
                                absl::string_view message_suffix) {
  absl::Status status =
      internal::CheckFipsCompatibility<RsaSsaPkcs1VerifyBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  // Check if the hash type is safe to use.
  absl::Status is_safe = internal::IsHashTypeSafeForSignature(params.hash_type);
  if (!is_safe.ok()) {
    return is_safe;
  }

  util::StatusOr<const EVP_MD*> sig_hash =
      internal::EvpHashFromHashType(params.hash_type);
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }

  // The RSA modulus and exponent are checked as part of the conversion to
  // internal::SslUniquePtr<RSA>.
  util::StatusOr<internal::SslUniquePtr<RSA>> rsa =
      internal::RsaPublicKeyToRsa(pub_key);
  if (!rsa.ok()) {
    return rsa.status();
  }

  std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl> verify(
      new RsaSsaPkcs1VerifyBoringSsl(*std::move(rsa), *sig_hash, output_prefix,
                                     message_suffix));
  return std::move(verify);
}

absl::Status RsaSsaPkcs1VerifyBoringSsl::VerifyWithoutPrefix(
    absl::string_view signature, absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  util::StatusOr<std::string> digest = internal::ComputeHash(data, *sig_hash_);
  if (!digest.ok()) {
    return digest.status();
  }

  if (RSA_verify(EVP_MD_type(sig_hash_),
                 /*digest=*/reinterpret_cast<const uint8_t*>(digest->data()),
                 /*digest_len=*/digest->size(),
                 /*sig=*/reinterpret_cast<const uint8_t*>(signature.data()),
                 /*sig_len=*/signature.length(),
                 /*rsa=*/rsa_.get()) != 1) {
    // Signature is invalid.
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Signature is not valid.");
  }

  return absl::OkStatus();
}

absl::Status RsaSsaPkcs1VerifyBoringSsl::Verify(absl::string_view signature,
                                                absl::string_view data) const {
  if (output_prefix_.empty() && message_suffix_.empty()) {
    return VerifyWithoutPrefix(signature, data);
  }
  if (!absl::StartsWith(signature, output_prefix_)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
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
