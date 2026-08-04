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
#include "absl/types/optional.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#include "tink/internal/fips_utils.h"  // IWYU pragma: keep
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/util/secret_data.h"
#if defined(OPENSSL_IS_BORINGSSL) && !defined(TINK_USE_ONLY_FIPS)
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

#if defined(OPENSSL_IS_BORINGSSL) && !defined(TINK_USE_ONLY_FIPS)
#include "tink/signature/internal/slh_dsa_parameter_set.h"
#endif

namespace crypto {
namespace tink {

namespace {

#if defined(OPENSSL_IS_BORINGSSL) && !defined(TINK_USE_ONLY_FIPS)
absl::Status GetPublicFromPrivate(
    const internal::SlhDsaParameterSet& parameter_set,
    std::string& public_key_bytes, const SecretData& private_key_bytes) {
  if (parameter_set == internal::SlhDsaParameterSet::Sha2_128s()) {
    SLHDSA_SHA2_128S_public_from_private(
        reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
        private_key_bytes.data());
    return absl::OkStatus();
  }
  if (parameter_set == internal::SlhDsaParameterSet::Shake_256f()) {
    SLHDSA_SHAKE_256F_public_from_private(
        reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
        private_key_bytes.data());
    return absl::OkStatus();
  }
  return absl::Status(
      absl::StatusCode::kInvalidArgument,
      "SLH-DSA parameter combination is not supported by BoringSSL.");
}

absl::Status GetKeyPairFromSeed(
    const internal::SlhDsaParameterSet& parameter_set,
    std::string& public_key_bytes, internal::SecretBuffer& private_key_bytes,
    const SecretData& private_seed_bytes) {
  if (parameter_set == internal::SlhDsaParameterSet::Sha2_128s()) {
    SLHDSA_SHA2_128S_generate_key_from_seed(
        reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
        private_key_bytes.data(), private_seed_bytes.data());
    return absl::OkStatus();
  }
  if (parameter_set == internal::SlhDsaParameterSet::Shake_256f()) {
    SLHDSA_SHAKE_256F_generate_key_from_seed(
        reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
        private_key_bytes.data(), private_seed_bytes.data());
    return absl::OkStatus();
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
#if !defined(OPENSSL_IS_BORINGSSL) || defined(TINK_USE_ONLY_FIPS)
  return absl::UnimplementedError(
      "SLH-DSA is only supported in non-FIPS BoringSSL builds.");
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

  // Confirm that the private key and public key are a valid SLH-DSA key pair.
  std::string public_key_bytes_regen;
  public_key_bytes_regen.resize(public_key_size);

  absl::Status status = absl::OkStatus();
  internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&public_key_bytes_regen[0],
                                                   public_key_size);

    status = GetPublicFromPrivate(
        *parameter_set, public_key_bytes_regen,
        private_key_bytes.Get(InsecureSecretKeyAccess::Get()));
    internal::DfsanClearLabel(&public_key_bytes_regen[0], public_key_size);
  });
  if (!status.ok()) {
    return status;
  }

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

absl::StatusOr<SlhDsaPrivateKey> SlhDsaPrivateKey::Create(
    const SlhDsaParameters& parameters, const RestrictedData& private_key_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
#if !defined(OPENSSL_IS_BORINGSSL) || defined(TINK_USE_ONLY_FIPS)
  return absl::UnimplementedError(
      "SLH-DSA is only supported in non-FIPS BoringSSL builds.");
#else
  // Only 64-byte, 96-byte and 128-byte private keys are supported.
  if (private_key_bytes.size() != 64 && private_key_bytes.size() != 96 &&
      private_key_bytes.size() != 128) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "SLH-DSA private key length must be 64, 96, or 128 bytes.");
  }

  if (parameters.GetPrivateKeySizeInBytes() != private_key_bytes.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Private key size does not match parameters");
  }

  absl::StatusOr<internal::SlhDsaParameterSet> parameter_set =
      internal::GetSlhDsaParameterSet(parameters);
  if (!parameter_set.ok()) {
    return parameter_set.status();
  }

  int public_key_size = parameter_set->GetPublicKeySizeInBytes();

  std::string public_key_bytes;
  public_key_bytes.resize(public_key_size);

  absl::Status status = absl::OkStatus();
  internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&public_key_bytes[0],
                                                   public_key_size);

    absl::Status status = GetPublicFromPrivate(
        *parameter_set, public_key_bytes,
        private_key_bytes.Get(InsecureSecretKeyAccess::Get()));
    internal::DfsanClearLabel(&public_key_bytes[0], public_key_size);
  });
  if (!status.ok()) {
    return status;
  }

  absl::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      parameters, public_key_bytes, id_requirement, token);
  if (!public_key.ok()) {
    return public_key.status();
  }

  return SlhDsaPrivateKey(*public_key, private_key_bytes);
#endif
}

absl::StatusOr<SlhDsaPrivateKey> SlhDsaPrivateKey::CreateFromSeed(
    const SlhDsaParameters& parameters,
    const RestrictedData& private_seed_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
#if !defined(OPENSSL_IS_BORINGSSL) || defined(TINK_USE_ONLY_FIPS)
  return absl::UnimplementedError(
      "SLH-DSA is only supported in non-FIPS BoringSSL builds.");
#else
  // Only 48-byte, 72-byte and 96-byte private keys are supported.
  if (private_seed_bytes.size() != 48 && private_seed_bytes.size() != 72 &&
      private_seed_bytes.size() != 96) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "SLH-DSA private seed length must be 48, 72, or 96 bytes.");
  }

  absl::StatusOr<internal::SlhDsaParameterSet> parameter_set =
      internal::GetSlhDsaParameterSet(parameters);
  if (!parameter_set.ok()) {
    return parameter_set.status();
  }

  if (parameter_set->GetPrivateSeedSizeInBytes() != private_seed_bytes.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Private key size does not match parameters");
  }

  int public_key_size = parameter_set->GetPublicKeySizeInBytes();
  int private_key_size = parameter_set->GetPrivateKeySizeInBytes();

  std::string public_key_bytes;
  public_key_bytes.resize(public_key_size);
  internal::SecretBuffer private_key_bytes(private_key_size);

  absl::Status status = absl::OkStatus();
  internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&public_key_bytes[0],
                                                   public_key_size);

    status = GetKeyPairFromSeed(
        *parameter_set, public_key_bytes, private_key_bytes,
        private_seed_bytes.Get(InsecureSecretKeyAccess::Get()));
    internal::DfsanClearLabel(&public_key_bytes[0], public_key_size);
  });
  if (!status.ok()) {
    return status;
  }

  absl::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      parameters, public_key_bytes, id_requirement, token);
  if (!public_key.ok()) {
    return public_key.status();
  }

  return SlhDsaPrivateKey(
      *public_key,
      RestrictedData(util::internal::AsSecretData(private_key_bytes),
                     InsecureSecretKeyAccess::Get()));
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
