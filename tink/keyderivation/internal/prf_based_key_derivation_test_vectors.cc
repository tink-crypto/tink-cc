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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_key_derivation_test_vectors.h"

#include <optional>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {

using ::crypto::tink::test::HexDecodeOrDie;

namespace {

absl::StatusOr<PrfBasedKeyDerivationTestVector> CreateHkdfTestVector() {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();

  ABSL_ASSIGN_OR_RETURN(XChaCha20Poly1305Parameters xchacha_params,
                        XChaCha20Poly1305Parameters::Create(
                            XChaCha20Poly1305Parameters::Variant::kTink));
  ABSL_ASSIGN_OR_RETURN(
      HkdfPrfParameters hkdf_params,
      HkdfPrfParameters::Create(
          /*key_size_in_bytes=*/32, HkdfPrfParameters::HashType::kSha256,
          /*salt=*/std::nullopt));
  ABSL_ASSIGN_OR_RETURN(
      HkdfPrfKey hkdf_key,
      HkdfPrfKey::Create(
          hkdf_params,
          RestrictedData(
              HexDecodeOrDie("000102030405060708090a0b0c0d0e0f101112131415161"
                             "718191a1b1c1d1e1f"),
              ska),
          pka));
  ABSL_ASSIGN_OR_RETURN(PrfBasedKeyDerivationParameters hkdf_xchacha_params,
                        PrfBasedKeyDerivationParameters::Builder()
                            .SetPrfParameters(hkdf_key.GetParameters())
                            .SetDerivedKeyParameters(xchacha_params)
                            .Build());
  ABSL_ASSIGN_OR_RETURN(
      PrfBasedKeyDerivationKey key,
      PrfBasedKeyDerivationKey::Create(hkdf_xchacha_params, hkdf_key,
                                       /*id_requirement=*/0x02030400, pka));
  return PrfBasedKeyDerivationTestVector{std::move(key)};
}

absl::StatusOr<PrfBasedKeyDerivationTestVector> CreateAesCmacTestVector() {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();

  ABSL_ASSIGN_OR_RETURN(XChaCha20Poly1305Parameters xchacha_params,
                        XChaCha20Poly1305Parameters::Create(
                            XChaCha20Poly1305Parameters::Variant::kNoPrefix));
  ABSL_ASSIGN_OR_RETURN(
      AesCmacPrfKey cmac_key,
      AesCmacPrfKey::Create(
          RestrictedData(
              HexDecodeOrDie("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a"
                             "6abf7158809cf4f3c"),
              ska),
          pka));
  ABSL_ASSIGN_OR_RETURN(PrfBasedKeyDerivationParameters cmac_xchacha_params,
                        PrfBasedKeyDerivationParameters::Builder()
                            .SetPrfParameters(cmac_key.GetParameters())
                            .SetDerivedKeyParameters(xchacha_params)
                            .Build());
  ABSL_ASSIGN_OR_RETURN(
      PrfBasedKeyDerivationKey key,
      PrfBasedKeyDerivationKey::Create(cmac_xchacha_params, cmac_key,
                                       /*id_requirement=*/std::nullopt, pka));
  return PrfBasedKeyDerivationTestVector{std::move(key)};
}

}  // namespace

const std::vector<PrfBasedKeyDerivationTestVector>&
CreatePrfBasedKeyDerivationTestVectors() {
  static const absl::NoDestructor<std::vector<PrfBasedKeyDerivationTestVector>>
      test_vectors([] {
        return std::vector<PrfBasedKeyDerivationTestVector>{
            GetPrfBasedKeyDerivationHkdfTestVector(),
            GetPrfBasedKeyDerivationAesCmacTestVector()};
      }());
  return *test_vectors;
}

const PrfBasedKeyDerivationTestVector&
GetPrfBasedKeyDerivationHkdfTestVector() {
  static const absl::NoDestructor<PrfBasedKeyDerivationTestVector> test_vector(
      [] {
        absl::StatusOr<PrfBasedKeyDerivationTestVector> test_vector =
            CreateHkdfTestVector();
        ABSL_CHECK_OK(test_vector);
        return *std::move(test_vector);
      }());
  return *test_vector;
}

const PrfBasedKeyDerivationTestVector&
GetPrfBasedKeyDerivationAesCmacTestVector() {
  static const absl::NoDestructor<PrfBasedKeyDerivationTestVector> test_vector(
      [] {
        absl::StatusOr<PrfBasedKeyDerivationTestVector> test_vector =
            CreateAesCmacTestVector();
        ABSL_CHECK_OK(test_vector);
        return *std::move(test_vector);
      }());
  return *test_vector;
}

}  // namespace crypto::tink::internal
