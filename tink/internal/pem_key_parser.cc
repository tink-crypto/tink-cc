// Copyright 2026 Google Inc.
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

#include "tink/internal/pem_key_parser.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

int NoopFailingPassphraseCallback(char* buf, int size, int rwflag, void* u) {
  return 0;
}

}  // namespace

absl::StatusOr<Ed25519Key> ParseEd25519PrivateKey(
    absl::string_view pem_serialized_key) {
  // Read the private key into EVP_PKEY.
  SslUniquePtr<BIO> ed25519_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(ed25519_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  // BoringSSL APIs to parse the PEM data.
  SslUniquePtr<EVP_PKEY> evp_ed25519_key(PEM_read_bio_PrivateKey(
      ed25519_key_bio.get(), /*out=*/nullptr, &NoopFailingPassphraseCallback,
      /*userdata=*/nullptr));
  if (evp_ed25519_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Private Key parsing failed");
  }

  const size_t priv_key_size = Ed25519KeyPrivKeySize();
  SecretBuffer raw_private_key(priv_key_size);
  size_t out_len_priv = priv_key_size;
  if (EVP_PKEY_get_raw_private_key(
          evp_ed25519_key.get(), raw_private_key.data(), &out_len_priv) != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "invalid ed25519 private key");
  }
  if (out_len_priv != priv_key_size) {
    crypto::tink::util::SafeZeroMemory(raw_private_key.data(), priv_key_size);
    return absl::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Invalid private key size; expected ",
                                     priv_key_size, " got ", out_len_priv));
  }
  crypto::tink::util::SecretData private_key =
      crypto::tink::util::internal::AsSecretData(raw_private_key);
  crypto::tink::util::SafeZeroMemory(raw_private_key.data(), priv_key_size);

  const size_t pub_key_size = Ed25519KeyPubKeySize();
  std::string public_key;
  crypto::tink::subtle::ResizeStringUninitialized(&public_key, pub_key_size);
  size_t out_len_pub = pub_key_size;
  if (EVP_PKEY_get_raw_public_key(evp_ed25519_key.get(),
                                  reinterpret_cast<uint8_t*>(&public_key[0]),
                                  &out_len_pub) != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "invalid ed25519 public key");
  }
  if (out_len_pub != pub_key_size) {
    return absl::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Invalid public key size; expected ",
                                     pub_key_size, " got ", out_len_pub));
  }

  auto key = Ed25519Key();
  key.private_key = std::move(private_key);
  key.public_key = std::move(public_key);
  return std::move(key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
