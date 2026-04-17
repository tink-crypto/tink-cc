// Copyright 2024 Google LLC
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

#include "tink/signature/internal/slh_dsa_sign_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/slhdsa.h"
#endif  // OPENSSL_IS_BORINGSSL
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/internal/slh_dsa_parameter_set.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

#ifdef OPENSSL_IS_BORINGSSL
using SignFunc = int (*)(uint8_t*, const uint8_t*, const uint8_t*, size_t,
                         const uint8_t*, size_t);

absl::StatusOr<SignFunc> GetSignFunc(const SlhDsaParameterSet& parameter_set) {
  if (parameter_set == SlhDsaParameterSet::Sha2_128s()) {
    return SLHDSA_SHA2_128S_sign;
  }
  if (parameter_set == SlhDsaParameterSet::Shake_256f()) {
    return SLHDSA_SHAKE_256F_sign;
  }
  return absl::Status(
      absl::StatusCode::kInvalidArgument,
      "SLH-DSA parameter combination is not supported by BoringSSL.");
}

absl::StatusOr<size_t> GetSignatureSize(
    const SlhDsaParameterSet& parameter_set) {
  if (parameter_set == SlhDsaParameterSet::Sha2_128s()) {
    return SLHDSA_SHA2_128S_SIGNATURE_BYTES;
  }
  if (parameter_set == SlhDsaParameterSet::Shake_256f()) {
    return SLHDSA_SHAKE_256F_SIGNATURE_BYTES;
  }
  return absl::Status(
      absl::StatusCode::kInvalidArgument,
      "SLH-DSA parameter combination is not supported by BoringSSL.");
}

class SlhDsaSignBoringSsl : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  explicit SlhDsaSignBoringSsl(const SlhDsaPrivateKey& private_key)
      : private_key_(private_key) {}

  ~SlhDsaSignBoringSsl() override = default;

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

 private:
  SlhDsaPrivateKey private_key_;
};

absl::StatusOr<std::string> SlhDsaSignBoringSsl::Sign(
    absl::string_view data) const {
  absl::StatusOr<SlhDsaParameterSet> parameter_set =
      GetSlhDsaParameterSet(private_key_.GetPublicKey().GetParameters());
  if (!parameter_set.ok()) {
    return parameter_set.status();
  }

  absl::StatusOr<SignFunc> sign_func = GetSignFunc(*parameter_set);
  if (!sign_func.ok()) {
    return sign_func.status();
  }

  absl::StatusOr<size_t> signature_size = GetSignatureSize(*parameter_set);
  if (!signature_size.ok()) {
    return signature_size.status();
  }

  // The signature will be prepended with the output prefix for TINK keys.
  std::string signature(private_key_.GetOutputPrefix());
  size_t signature_buffer_size =
      *signature_size + private_key_.GetOutputPrefix().size();
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  internal::CallWithCoreDumpProtection([&, sign_func_val = *sign_func]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    sign_func_val(reinterpret_cast<uint8_t*>(
                      &signature[0] + private_key_.GetOutputPrefix().size()),
                  private_key_.GetPrivateKeyBytes(GetPartialKeyAccess())
                      .Get(InsecureSecretKeyAccess::Get())
                      .data(),
                  reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                  /* context = */ nullptr, /* context_len = */ 0);
    internal::DfsanClearLabel(&signature[0], signature_buffer_size);
  });

  return signature;
}
#endif  // OPENSSL_IS_BORINGSSL

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewSlhDsaSignBoringSsl(
    const SlhDsaPrivateKey& private_key) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "SLH-DSA is only supported in BoringSSL builds.");
#else
  auto status = internal::CheckFipsCompatibility<SlhDsaSignBoringSsl>();
  if (!status.ok()) {
    return status;
  }
  absl::StatusOr<SlhDsaParameterSet> parameter_set =
      GetSlhDsaParameterSet(private_key.GetPublicKey().GetParameters());
  if (!parameter_set.ok()) {
    return parameter_set.status();
  }

  return {std::make_unique<SlhDsaSignBoringSsl>(std::move(private_key))};
#endif  // OPENSSL_IS_BORINGSSL
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
