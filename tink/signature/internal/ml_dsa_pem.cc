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
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/ml_dsa_pem.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "tink/internal/ssl_unique_ptr.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

// We explicitly set a failing passphrase callback function to make sure no
// default callback routine is used.
int FailingPassphraseCallback(char* buf, int buf_size, int rwflag, void* u) {
  return -1;
}

absl::StatusOr<std::string> ParseMldsaPublicKey(
    absl::string_view pem_serialized_key, int expected_pkey_id,
    size_t expected_key_size, absl::string_view expected_key_name) {
  internal::SslUniquePtr<BIO> pub_key_bio(BIO_new(BIO_s_mem()));
  if (pub_key_bio == nullptr) {
    return absl::Status(absl::StatusCode::kInternal, "Failed to create BIO");
  }
  if (BIO_write(pub_key_bio.get(), pem_serialized_key.data(),
                pem_serialized_key.size()) <= 0) {
    return absl::Status(absl::StatusCode::kInternal, "Failed to write to BIO");
  }

  internal::SslUniquePtr<EVP_PKEY> evp_pub_key(
      PEM_read_bio_PUBKEY(pub_key_bio.get(), /*x=*/nullptr,
                          &FailingPassphraseCallback, /*u=*/nullptr));
  if (evp_pub_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Public Key parsing failed");
  }

  if (EVP_PKEY_id(evp_pub_key.get()) != expected_pkey_id) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("PEM key is not a ", expected_key_name, " public key"));
  }

  const size_t kMaxKeySize = 2592;
  if (expected_key_size > kMaxKeySize) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Requested key size ", expected_key_size,
                     " exceeds maximum supported ", kMaxKeySize));
  }

  uint8_t public_key[kMaxKeySize] = {0};
  size_t out_len_pub = expected_key_size;
  if (EVP_PKEY_get_raw_public_key(evp_pub_key.get(), public_key,
                                  &out_len_pub) != 1) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("invalid ", expected_key_name, " public key"));
  }
  if (out_len_pub != expected_key_size) {
    return absl::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Invalid public key size; expected ",
                                     expected_key_size, " got ", out_len_pub));
  }

  return std::string(reinterpret_cast<char*>(public_key), expected_key_size);
}

}  // namespace

absl::StatusOr<std::string> ParseMldsa65PublicKey(
    absl::string_view pem_serialized_key) {
  return ParseMldsaPublicKey(pem_serialized_key, EVP_PKEY_ML_DSA_65, 1952,
                             "ML-DSA-65");
}

absl::StatusOr<std::string> ParseMldsa87PublicKey(
    absl::string_view pem_serialized_key) {
  return ParseMldsaPublicKey(pem_serialized_key, EVP_PKEY_ML_DSA_87, 2592,
                             "ML-DSA-87");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
