// Copyright 2017 Google LLC
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

#include <cstdint>
#include <memory>
#include <string>

#include "benchmark/benchmark.h"
#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/ec_point.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

void EcdsaVerifyBenchmark(benchmark::State& state,
                          EcdsaParameters::Variant variant) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(
          EcdsaParameters::CurveType::kNistP256,
          EcdsaParameters::HashType::kSha256,
          EcdsaParameters::SignatureEncoding::kIeeeP1363, variant);
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ABSL_CHECK(private_key != nullptr);
  absl::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> signer =
      EcdsaSignBoringSsl::New(*private_key);
  ABSL_CHECK_OK(signer.status());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(private_key->GetPublicKey());
  ABSL_CHECK_OK(verifier.status());

  std::string data(state.range(0), 'x');
  absl::StatusOr<std::string> signature = (*signer)->Sign(data);
  ABSL_CHECK_OK(signature.status());
  for (auto s : state) {
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(signature);
    absl::Status status = (*verifier)->Verify(*signature, data);
    benchmark::DoNotOptimize(status);
    ABSL_CHECK_OK(status);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_EcdsaP256NoPrefixVerify(benchmark::State& state) {
  EcdsaVerifyBenchmark(state, EcdsaParameters::Variant::kNoPrefix);
}

void BM_EcdsaP256LegacyVerify(benchmark::State& state) {
  EcdsaVerifyBenchmark(state, EcdsaParameters::Variant::kLegacy);
}

constexpr int64_t kMaxDataSize = 1 << 23;  // 8 MiB

BENCHMARK(BM_EcdsaP256NoPrefixVerify)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);
BENCHMARK(BM_EcdsaP256LegacyVerify)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);

struct CurveConfig {
  EcdsaParameters::HashType hash_type;
  EllipticCurveType subtle_curve;
  HashType subtle_hash_type;
};

CurveConfig GetCurveConfig(EcdsaParameters::CurveType curve) {
  switch (curve) {
    case EcdsaParameters::CurveType::kNistP256:
      return {EcdsaParameters::HashType::kSha256, EllipticCurveType::NIST_P256,
              HashType::SHA256};
    case EcdsaParameters::CurveType::kNistP384:
      return {EcdsaParameters::HashType::kSha384, EllipticCurveType::NIST_P384,
              HashType::SHA384};
    case EcdsaParameters::CurveType::kNistP521:
      return {EcdsaParameters::HashType::kSha512, EllipticCurveType::NIST_P521,
              HashType::SHA512};
    default:
      ABSL_LOG(FATAL) << "Unsupported curve: " << static_cast<int>(curve);
  }
}

const EcdsaPrivateKey& GetPrivateKey(EcdsaParameters::CurveType curve) {
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(
          curve, GetCurveConfig(curve).hash_type,
          EcdsaParameters::SignatureEncoding::kIeeeP1363,
          EcdsaParameters::Variant::kNoPrefix);
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ABSL_CHECK(private_key != nullptr);
  return *private_key;
}

// Measures the cost of creating a verifier from an `EcdsaPublicKey`.
void EcdsaVerifierNewFromKeyBenchmark(benchmark::State& state,
                                      EcdsaParameters::CurveType curve) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  const EcdsaPublicKey& public_key = GetPrivateKey(curve).GetPublicKey();
  ABSL_CHECK_OK(EcdsaVerifyBoringSsl::New(public_key));
  for (auto s : state) {
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
        EcdsaVerifyBoringSsl::New(public_key);
    benchmark::DoNotOptimize(verifier);
  }
}

// Measures the cost of creating a verifier from a
// `SubtleUtilBoringSSL::EcKey`, as done by the legacy key managers.
void EcdsaVerifierNewFromEcKeyBenchmark(benchmark::State& state,
                                        EcdsaParameters::CurveType curve) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  const CurveConfig config = GetCurveConfig(curve);
  const EcPoint& public_point =
      GetPrivateKey(curve).GetPublicKey().GetPublicPoint(GetPartialKeyAccess());
  SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = config.subtle_curve;
  ec_key.pub_x = std::string(public_point.GetX().GetValue());
  ec_key.pub_y = std::string(public_point.GetY().GetValue());
  ABSL_CHECK_OK(EcdsaVerifyBoringSsl::New(ec_key, config.subtle_hash_type,
                                          EcdsaSignatureEncoding::IEEE_P1363));
  for (auto s : state) {
    absl::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> verifier =
        EcdsaVerifyBoringSsl::New(ec_key, config.subtle_hash_type,
                                  EcdsaSignatureEncoding::IEEE_P1363);
    benchmark::DoNotOptimize(verifier);
  }
}

void BM_EcdsaP256VerifierNewFromKey(benchmark::State& state) {
  EcdsaVerifierNewFromKeyBenchmark(state,
                                   EcdsaParameters::CurveType::kNistP256);
}
BENCHMARK(BM_EcdsaP256VerifierNewFromKey);

void BM_EcdsaP384VerifierNewFromKey(benchmark::State& state) {
  EcdsaVerifierNewFromKeyBenchmark(state,
                                   EcdsaParameters::CurveType::kNistP384);
}
BENCHMARK(BM_EcdsaP384VerifierNewFromKey);

void BM_EcdsaP521VerifierNewFromKey(benchmark::State& state) {
  EcdsaVerifierNewFromKeyBenchmark(state,
                                   EcdsaParameters::CurveType::kNistP521);
}
BENCHMARK(BM_EcdsaP521VerifierNewFromKey);

void BM_EcdsaP256VerifierNewFromEcKey(benchmark::State& state) {
  EcdsaVerifierNewFromEcKeyBenchmark(state,
                                     EcdsaParameters::CurveType::kNistP256);
}
BENCHMARK(BM_EcdsaP256VerifierNewFromEcKey);

void BM_EcdsaP384VerifierNewFromEcKey(benchmark::State& state) {
  EcdsaVerifierNewFromEcKeyBenchmark(state,
                                     EcdsaParameters::CurveType::kNistP384);
}
BENCHMARK(BM_EcdsaP384VerifierNewFromEcKey);

void BM_EcdsaP521VerifierNewFromEcKey(benchmark::State& state) {
  EcdsaVerifierNewFromEcKeyBenchmark(state,
                                     EcdsaParameters::CurveType::kNistP521);
}
BENCHMARK(BM_EcdsaP521VerifierNewFromEcKey);

// Measures creating a verifier and verifying a single short message, i.e. the
// cost paid by callers that create a new verifier for each signature.
void BM_EcdsaP256NewAndVerify(benchmark::State& state) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(
          EcdsaParameters::CurveType::kNistP256,
          EcdsaParameters::HashType::kSha256,
          EcdsaParameters::SignatureEncoding::kIeeeP1363,
          EcdsaParameters::Variant::kNoPrefix);
  const EcdsaPublicKey& public_key =
      GetPrivateKey(EcdsaParameters::CurveType::kNistP256).GetPublicKey();
  for (auto s : state) {
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
        EcdsaVerifyBoringSsl::New(public_key);
    ABSL_CHECK_OK(verifier);
    absl::Status status =
        (*verifier)->Verify(test_vector.signature, test_vector.message);
    ABSL_CHECK_OK(status);
    benchmark::DoNotOptimize(status);
  }
}
BENCHMARK(BM_EcdsaP256NewAndVerify);

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
