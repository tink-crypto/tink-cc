// Copyright 2025 Google LLC
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

#include "tink/internal/mlkem_util.h"

#include <cstddef>
#include <cstdint>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "openssl/bytestring.h"
#include "openssl/mlkem.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

constexpr int64_t kMlKem768KeyPubKeySize = 1184;
constexpr int64_t kMlKem1024KeyPubKeySize = 1568;
constexpr int64_t kMlKemKeyPrivKeySize = 64;

// Generates a new ML-KEM-768 key.
absl::StatusOr<MlKemKey> GenerateMlKem768Key() {
  MlKemKey key;
  subtle::ResizeStringUninitialized(&key.public_key, kMlKem768KeyPubKeySize);
  SecretBuffer private_key_buffer(kMlKemKeyPrivKeySize);
  absl::Status status = CallWithCoreDumpProtection([&]() {
    auto bssl_private_key = util::MakeSecretUniquePtr<MLKEM768_private_key>();
    MLKEM768_generate_key(reinterpret_cast<uint8_t*>(key.public_key.data()),
                          private_key_buffer.data(), bssl_private_key.get());
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }
  key.private_key = util::internal::AsSecretData(std::move(private_key_buffer));
  return key;
}

// Generates a new ML-KEM-1024 key.
absl::StatusOr<MlKemKey> GenerateMlKem1024Key() {
  MlKemKey key;
  subtle::ResizeStringUninitialized(&key.public_key, kMlKem1024KeyPubKeySize);
  SecretBuffer private_key_buffer(kMlKemKeyPrivKeySize);
  absl::Status status = CallWithCoreDumpProtection([&]() {
    auto bssl_private_key = util::MakeSecretUniquePtr<MLKEM1024_private_key>();
    MLKEM1024_generate_key(reinterpret_cast<uint8_t*>(key.public_key.data()),
                           private_key_buffer.data(), bssl_private_key.get());
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }
  key.private_key = util::internal::AsSecretData(std::move(private_key_buffer));
  return key;
}

// Creates an ML-KEM-768 key from a private key.
absl::StatusOr<MlKemKey> MlKem768KeyFromPrivateKey(
    const SecretData& private_key) {
  MlKemKey key;
  subtle::ResizeStringUninitialized(&key.public_key, kMlKem768KeyPubKeySize);
  absl::Status status = CallWithCoreDumpProtection([&]() {
    auto bssl_private_key = util::MakeSecretUniquePtr<MLKEM768_private_key>();
    if (!MLKEM768_private_key_from_seed(
            bssl_private_key.get(),
            reinterpret_cast<const uint8_t*>(private_key.data()),
            private_key.size())) {
      return absl::Status(absl::StatusCode::kInternal,
                          "Failed to expand ML-KEM-768 private key from seed.");
    }

    auto bssl_public_key = absl::make_unique<MLKEM768_public_key>();
    MLKEM768_public_from_private(bssl_public_key.get(), bssl_private_key.get());

    CBB cbb;
    size_t size;
    if (!CBB_init_fixed(&cbb, reinterpret_cast<uint8_t*>(key.public_key.data()),
                        key.public_key.size()) ||
        !MLKEM768_marshal_public_key(&cbb, bssl_public_key.get()) ||
        !CBB_finish(&cbb, /*out_data=*/nullptr, &size) ||
        size != key.public_key.size()) {
      return absl::Status(absl::StatusCode::kInternal,
                          "MLKEM768_marshal_public_key failed");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }
  key.private_key = private_key;
  return key;
}

// Creates an ML-KEM-1024 key from a private key.
absl::StatusOr<MlKemKey> MlKem1024KeyFromPrivateKey(
    const SecretData& private_key) {
  MlKemKey key;
  subtle::ResizeStringUninitialized(&key.public_key, kMlKem1024KeyPubKeySize);
  absl::Status status = CallWithCoreDumpProtection([&]() {
    auto bssl_private_key = util::MakeSecretUniquePtr<MLKEM1024_private_key>();
    if (!MLKEM1024_private_key_from_seed(
            bssl_private_key.get(),
            reinterpret_cast<const uint8_t*>(private_key.data()),
            private_key.size())) {
      return absl::Status(
          absl::StatusCode::kInternal,
          "Failed to expand ML-KEM-1024 private key from seed.");
    }

    auto bssl_public_key = absl::make_unique<MLKEM1024_public_key>();
    MLKEM1024_public_from_private(bssl_public_key.get(),
                                  bssl_private_key.get());

    CBB cbb;
    size_t size;
    if (!CBB_init_fixed(&cbb, reinterpret_cast<uint8_t*>(key.public_key.data()),
                        key.public_key.size()) ||
        !MLKEM1024_marshal_public_key(&cbb, bssl_public_key.get()) ||
        !CBB_finish(&cbb, /*out_data=*/nullptr, &size) ||
        size != key.public_key.size()) {
      return absl::Status(absl::StatusCode::kInternal,
                          "MLKEM1024_marshal_public_key failed");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }
  key.private_key = private_key;
  return key;
}

}  // namespace

absl::StatusOr<MlKemKey> NewMlKemKey(MlKemKeySize key_size) {
  switch (key_size) {
    case MlKemKeySize::ML_KEM768:
      return GenerateMlKem768Key();
    case MlKemKeySize::ML_KEM1024:
      return GenerateMlKem1024Key();
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid MlKemKeySize");
  }
}

absl::StatusOr<MlKemKey> MlKemKeyFromPrivateKey(const SecretData& private_key,
                                                MlKemKeySize key_size) {
  if (private_key.size() != kMlKemKeyPrivKeySize) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid length for private key");
  }
  switch (key_size) {
    case MlKemKeySize::ML_KEM768:
      return MlKem768KeyFromPrivateKey(private_key);
    case MlKemKeySize::ML_KEM1024:
      return MlKem1024KeyFromPrivateKey(private_key);
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid MlKemKeySize");
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
