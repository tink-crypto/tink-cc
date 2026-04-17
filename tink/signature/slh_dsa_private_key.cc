// Copyright 2024 Google LLC
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

#include "tink/signature/slh_dsa_private_key.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/mem.h"
#include "openssl/slhdsa.h"
#endif
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/slh_dsa_public_key.h"

#ifdef OPENSSL_IS_BORINGSSL
#include "tink/signature/internal/slh_dsa_parameter_set.h"
#endif

namespace crypto {
namespace tink {

namespace {

#ifdef OPENSSL_IS_BORINGSSL
using PublicFromPrivateFunc = void (*)(uint8_t*, const uint8_t*);

absl::StatusOr<PublicFromPrivateFunc> GetPublicFromPrivateFunc(
    const internal::SlhDsaParameterSet& parameter_set) {
  if (parameter_set == internal::SlhDsaParameterSet::Sha2_128s()) {
    return SLHDSA_SHA2_128S_public_from_private;
  }
  if (parameter_set == internal::SlhDsaParameterSet::Shake_256f()) {
    return SLHDSA_SHAKE_256F_public_from_private;
  }
  return absl::Status(
      absl::StatusCode::kInvalidArgument,
      "SLH-DSA parameter combination is not supported by BoringSSL.");
}
#endif

}  // namespace

absl::StatusOr<SlhDsaPrivateKey> SlhDsaPrivateKey::Create(
    const SlhDsaPublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "SLH-DSA is only supported in BoringSSL builds.");
#else
  // Only 64-byte, 96-byte and 128-byte private keys are supported.
  if (private_key_bytes.size() != 64 && private_key_bytes.size() != 96 &&
      private_key_bytes.size() != 128) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "SLH-DSA private key length must be 64, 96, or 128 bytes.");
  }

  if (public_key.GetParameters().GetPrivateKeySizeInBytes() !=
      private_key_bytes.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Private key size does not match parameters");
  }

  absl::StatusOr<internal::SlhDsaParameterSet> parameter_set =
      internal::GetSlhDsaParameterSet(public_key.GetParameters());
  if (!parameter_set.ok()) {
    return parameter_set.status();
  }

  int public_key_size = parameter_set->GetPublicKeySizeInBytes();

  absl::StatusOr<PublicFromPrivateFunc> public_from_private_func =
      GetPublicFromPrivateFunc(*parameter_set);
  if (!public_from_private_func.ok()) {
    return public_from_private_func.status();
  }

  // Confirm that the private key and public key are a valid SLH-DSA key pair.
  std::string public_key_bytes_regen;
  public_key_bytes_regen.resize(public_key_size);

  internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&public_key_bytes_regen[0],
                                                   public_key_size);

    (*public_from_private_func)(
        reinterpret_cast<uint8_t*>(&public_key_bytes_regen[0]),
        reinterpret_cast<const uint8_t*>(
            private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get())
                .data()));
    internal::DfsanClearLabel(&public_key_bytes_regen[0], public_key_size);
  });

  absl::string_view expected_public_key_bytes =
      public_key.GetPublicKeyBytes(token);

  if (CRYPTO_memcmp(expected_public_key_bytes.data(),
                    public_key_bytes_regen.data(), public_key_size) != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid SLH-DSA key pair");
  }

  return SlhDsaPrivateKey(public_key, private_key_bytes);
#endif
}

bool SlhDsaPrivateKey::operator==(const Key& other) const {
  const SlhDsaPrivateKey* that = dynamic_cast<const SlhDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
