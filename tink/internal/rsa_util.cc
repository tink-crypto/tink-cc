// Copyright 2021 Google LLC
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
#include "tink/internal/rsa_util.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/ssl_util.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr int kMaxRsaModulusSizeBits = 16 * 1024;
// Mitigate DoS attacks by limiting the exponent size. 33 bits was chosen as
// the limit based on the recommendations in [1] and [2]. Windows CryptoAPI
// doesn't support values larger than 32 bits [3], so it is unlikely that
// exponents larger than 32 bits are being used for anything Windows commonly
// does.
//
// [1] https://www.imperialviolet.org/2012/03/16/rsae.html
// [2] https://www.imperialviolet.org/2012/03/17/rsados.html
// [3] https://msdn.microsoft.com/en-us/library/aa387685(VS.85).aspx
constexpr int kMaxRsaExponentBits = 33;

absl::Status ValidateRsaModulusSize(size_t modulus_size) {
  if (modulus_size < 2048) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Modulus size is ", modulus_size,
                     " only modulus size >= 2048-bit is supported"));
  }

  // In FIPS only mode we check here if the modulus is 2048- or 3072-bit, as
  // these are the only size which is covered by the FIPS validation and
  // supported by Tink. See
  // https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3318
  if (IsFipsModeEnabled()) {
    if (modulus_size != 2048 && modulus_size != 3072) {
      return absl::Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Modulus size is ", modulus_size,
                       " only modulus size 2048 or 3072 is supported."));
    }
  }

  return absl::OkStatus();
}

absl::Status ValidateRsaPublicExponent(const BIGNUM* exponent) {
  if (exponent == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must not be NULL.");
  }

  if (BN_is_odd(exponent) == 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must be odd.");
  }

  if (CompareBignumWithWord(exponent, /*word=*/65536) <= 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must be greater than 65536.");
  }

  // OpenSSL doesn't pose a limit to the size of the exponent, so for
  // consistency w.r.t. BoringSSL, we enforce it here.
  if (BN_num_bits(exponent) > 32) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Exponent size must be smaller than 32 bits");
  }
  return absl::OkStatus();
}

absl::Status ValidateRsaPublicExponent(absl::string_view exponent) {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(exponent);
  if (!e.ok()) {
    return e.status();
  }
  return ValidateRsaPublicExponent(e->get());
}

absl::Status NewRsaKeyPair(int modulus_size_in_bits, const BIGNUM* e,
                           RsaPrivateKey* private_key,
                           RsaPublicKey* public_key) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Could not initialize RSA.");
  }

  absl::Status exponent_validation_res = ValidateRsaPublicExponent(e);
  if (!exponent_validation_res.ok()) {
    return exponent_validation_res;
  }

  internal::SslUniquePtr<BIGNUM> e_copy(BN_new());
  if (BN_copy(e_copy.get(), e) == nullptr) {
    return absl::Status(absl::StatusCode::kInternal, internal::GetSslErrors());
  }
  if (RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e_copy.get(),
                          /*cb=*/nullptr) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Error generating private key: ",
                                     internal::GetSslErrors()));
  }

  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);

  // Save exponents.
  absl::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  if (!n_str.ok()) {
    return n_str.status();
  }
  absl::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  if (!e_str.ok()) {
    return e_str.status();
  }
  absl::StatusOr<SecretData> d_str =
      internal::BignumToSecretData(d_bn, (modulus_size_in_bits + 7) / 8);
  if (!d_str.ok()) {
    return d_str.status();
  }
  private_key->n = *std::move(n_str);
  private_key->e = *std::move(e_str);
  private_key->d = *std::move(d_str);
  public_key->n = private_key->n;
  public_key->e = private_key->e;

  // Save factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);
  absl::StatusOr<SecretData> p_str =
      internal::BignumToSecretData(p_bn, BN_num_bytes(p_bn));
  if (!p_str.ok()) {
    return p_str.status();
  }
  absl::StatusOr<SecretData> q_str =
      internal::BignumToSecretData(q_bn, BN_num_bytes(q_bn));
  if (!q_str.ok()) {
    return q_str.status();
  }
  private_key->p = *std::move(p_str);
  private_key->q = *std::move(q_str);

  // Save CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &crt_bn);
  absl::StatusOr<SecretData> dp_str =
      internal::BignumToSecretData(dp_bn, BN_num_bytes(p_bn));
  if (!dp_str.ok()) {
    return dp_str.status();
  }
  absl::StatusOr<SecretData> dq_str =
      internal::BignumToSecretData(dq_bn, BN_num_bytes(q_bn));
  if (!dq_str.ok()) {
    return dq_str.status();
  }
  absl::StatusOr<SecretData> crt_str =
      internal::BignumToSecretData(crt_bn, BN_num_bytes(p_bn));
  if (!crt_str.ok()) {
    return crt_str.status();
  }
  private_key->dp = *std::move(dp_str);
  private_key->dq = *std::move(dq_str);
  private_key->crt = *std::move(crt_str);

  return absl::OkStatus();
}

absl::Status GetRsaModAndExponents(const RsaPrivateKey& key, RSA* rsa) {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(key.n);
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(key.e);
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> d =
      internal::SecretDataToBignum(key.d);
  if (!n.ok()) {
    return n.status();
  }
  if (!e.ok()) {
    return e.status();
  }
  if (!d.ok()) {
    return d.status();
  }
  if (CallWithCoreDumpProtection([&]() {
        return RSA_set0_key(rsa, n->get(), e->get(), d->get());
      }) != 1) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  // The RSA object takes ownership when RSA_set0_key is called.
  n->release();
  e->release();
  d->release();
  return absl::OkStatus();
}

absl::Status GetRsaPrimeFactors(const RsaPrivateKey& key, RSA* rsa) {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> p =
      internal::SecretDataToBignum(key.p);
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> q =
      internal::SecretDataToBignum(key.q);
  if (!p.ok()) {
    return p.status();
  }
  if (!q.ok()) {
    return q.status();
  }
  if (RSA_set0_factors(rsa, p->get(), q->get()) != 1) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  p->release();
  q->release();
  return absl::OkStatus();
}

absl::Status GetRsaCrtParams(const RsaPrivateKey& key, RSA* rsa) {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> dp =
      internal::SecretDataToBignum(key.dp);
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> dq =
      internal::SecretDataToBignum(key.dq);
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> crt =
      internal::SecretDataToBignum(key.crt);
  if (!dp.ok()) {
    return dp.status();
  }
  if (!dq.ok()) {
    return dq.status();
  }
  if (!crt.ok()) {
    return crt.status();
  }
  if (RSA_set0_crt_params(rsa, dp->get(), dq->get(), crt->get()) != 1) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  dp->release();
  dq->release();
  crt->release();
  return absl::OkStatus();
}

absl::StatusOr<internal::SslUniquePtr<RSA>> RsaPrivateKeyToRsa(
    const RsaPrivateKey& private_key) {
  auto n = internal::StringToBignum(private_key.n);
  if (!n.ok()) {
    return n.status();
  }
  auto validation_result = ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!validation_result.ok()) {
    return validation_result;
  }
  // Check RSA's public exponent
  auto exponent_status = ValidateRsaPublicExponent(private_key.e);
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  return CallWithCoreDumpProtection(
      [&]() -> absl::StatusOr<internal::SslUniquePtr<RSA>> {
        internal::SslUniquePtr<RSA> rsa(RSA_new());
        if (rsa.get() == nullptr) {
          return absl::Status(absl::StatusCode::kInternal,
                              "BoringSsl RSA allocation error");
        }
        absl::Status status = GetRsaModAndExponents(private_key, rsa.get());
        if (!status.ok()) {
          return status;
        }
        status = GetRsaPrimeFactors(private_key, rsa.get());
        if (!status.ok()) {
          return status;
        }
        status = GetRsaCrtParams(private_key, rsa.get());
        if (!status.ok()) {
          return status;
        }

        if (RSA_check_key(rsa.get()) == 0) {
          return absl::Status(absl::StatusCode::kInvalidArgument,
                              absl::StrCat("Could not load RSA key: ",
                                           internal::GetSslErrors()));
        }
#ifdef OPENSSL_IS_BORINGSSL
        if (RSA_check_fips(rsa.get()) == 0) {
          return absl::Status(absl::StatusCode::kInvalidArgument,
                              absl::StrCat("Could not load RSA key: ",
                                           internal::GetSslErrors()));
        }
#endif
        return std::move(rsa);
      });
}

absl::StatusOr<internal::SslUniquePtr<RSA>> RsaPrivateKeyToRsaFixedSizeInputs(
    const RsaPrivateKey& private_key) {
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(private_key.n);
  if (!n.ok()) {
    return n.status();
  }

  absl::Status validation_result =
      ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!validation_result.ok()) {
    return validation_result;
  }

  // Check RSA's public exponent
  absl::Status exponent_status = ValidateRsaPublicExponent(private_key.e);
  if (!exponent_status.ok()) {
    return exponent_status;
  }

  return CallWithCoreDumpProtection([&]() -> absl::StatusOr<
                                              internal::SslUniquePtr<RSA>> {
    /// Checks for sizes and leading zeros.
    const absl::string_view p_sd = util::SecretDataAsStringView(private_key.p);
    if (p_sd.size() > 1 && p_sd[0] == 0) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Prime factor p has leading zeros");
    }
    const absl::string_view q_sd = util::SecretDataAsStringView(private_key.q);
    if (q_sd.size() > 1 && q_sd[0] == 0) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Prime factor q has leading zeros");
    }

    if (private_key.dp.size() != private_key.p.size()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Prime exponent dp has incorrect length: expected ",
                       private_key.p.size(), " got ", private_key.dp.size()));
    }

    if (private_key.dq.size() != private_key.q.size()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Prime exponent dq has incorrect length: expected ",
                       private_key.q.size(), " got ", private_key.dq.size()));
    }

    if (private_key.crt.size() != private_key.p.size()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("CRT coefficient has incorrect length: expected ",
                       private_key.p.size(), " got ", private_key.crt.size()));
    }

    if (private_key.d.size() != private_key.n.size()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Private exponent d has incorrect length: expected ",
                       private_key.n.size(), " got ", private_key.d.size()));
    }

    internal::SslUniquePtr<RSA> rsa(RSA_new());
    if (rsa.get() == nullptr) {
      return absl::Status(absl::StatusCode::kInternal,
                          "BoringSsl RSA allocation error");
    }
    absl::Status status = GetRsaModAndExponents(private_key, rsa.get());
    if (!status.ok()) {
      return status;
    }
    status = GetRsaPrimeFactors(private_key, rsa.get());
    if (!status.ok()) {
      return status;
    }
    status = GetRsaCrtParams(private_key, rsa.get());
    if (!status.ok()) {
      return status;
    }

    if (RSA_check_key(rsa.get()) == 0) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
    }
#ifdef OPENSSL_IS_BORINGSSL
    if (RSA_check_fips(rsa.get()) == 0) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
    }
#endif
    return std::move(rsa);
  });
}

absl::StatusOr<internal::SslUniquePtr<RSA>> RsaPublicKeyToRsa(
    const RsaPublicKey& public_key) {
  auto n = internal::StringToBignum(public_key.n);
  if (!n.ok()) {
    return n.status();
  }
  auto e = internal::StringToBignum(public_key.e);
  if (!e.ok()) {
    return e.status();
  }
  auto validation_result = ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!validation_result.ok()) {
    return validation_result;
  }
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa.get() == nullptr) {
    return absl::Status(absl::StatusCode::kInternal, "RSA allocation error");
  }
  // The value d is null for a public RSA key.
  if (RSA_set0_key(rsa.get(), n->get(), e->get(),
                   /*d=*/nullptr) != 1) {
    return absl::Status(absl::StatusCode::kInternal, "Could not set RSA key.");
  }
  n->release();
  e->release();
  return std::move(rsa);
}

absl::Status RsaCheckPublicKey(const RSA* key) {
  if (key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "RSA key is null");
  }

  // BoringSSL `RSA_check_key` supports checking the public key.
  if (internal::IsBoringSsl()) {
    if (RSA_check_key(key) != 1) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid RSA key format");
    }
    return absl::OkStatus();
  }

  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  RSA_get0_key(key, &n, &e, &d);

  if (e == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "RSA key's public exponent is null");
  }
  if (n == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "RSA key's public modulus is null");
  }

  // Check the size of the public modulus.
  unsigned n_bits = BN_num_bits(n);
  if (n_bits > kMaxRsaModulusSizeBits) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(
            "RSA key's public modulus size is too large; expected at most ",
            kMaxRsaModulusSizeBits, " bits, got ", n_bits));
  }

  unsigned e_bits = BN_num_bits(e);
  // Valis size is 1 < e_bits <= kMaxRsaExponentBits.
  if (e_bits > kMaxRsaExponentBits || e_bits < 2) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public exponent size of ", e_bits, " bits"));
  }

  // The exponent must be odd to be relatively prime with phi(n).
  if (!BN_is_odd(e)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent is not odd");
  }

  // Verify |n > e| first taking the shortcut of making sure the size in bits of
  // n is larger than the maximum modulus size; if this not the case, directly
  // compare n and e.
  if (n_bits <= kMaxRsaExponentBits || BN_ucmp(n, e) <= 0) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "RSA key's public exponent is smaller than the modulus");
  }
  return absl::OkStatus();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
