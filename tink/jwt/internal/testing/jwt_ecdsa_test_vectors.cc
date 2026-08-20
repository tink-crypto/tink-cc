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

#include "tink/jwt/internal/testing/jwt_ecdsa_test_vectors.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto::tink::jwt_internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;

struct JwtEcdsaTestVectorParams {
  subtle::EllipticCurveType curve;
  JwtEcdsaParameters::KidStrategy kid_strategy;
  JwtEcdsaParameters::Algorithm algorithm;
  absl::string_view pub_x_hex;
  absl::string_view pub_y_hex;
  absl::string_view priv_hex;
  std::optional<int> id_requirement;
  std::optional<std::string> custom_kid;
};

JwtEcdsaTestVector MakeJwtEcdsaTestVector(
    const JwtEcdsaTestVectorParams& params) {
  absl::StatusOr<JwtEcdsaParameters> jwt_params =
      JwtEcdsaParameters::Create(params.kid_strategy, params.algorithm);
  ABSL_CHECK_OK(jwt_params.status());

  EcPoint public_point(BigInteger(HexDecodeOrDie(params.pub_x_hex)),
                       BigInteger(HexDecodeOrDie(params.pub_y_hex)));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*jwt_params)
                                           .SetPublicPoint(public_point);
  if (params.id_requirement.has_value()) {
    builder.SetIdRequirement(*params.id_requirement);
  }
  if (params.custom_kid.has_value()) {
    builder.SetCustomKid(*params.custom_kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  RestrictedData private_key_value = RestrictedData(
      HexDecodeOrDie(params.priv_hex), InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return JwtEcdsaTestVector{*std::move(private_key)};
}

using JwtEcdsaTestVectorMap =
    absl::flat_hash_map<subtle::EllipticCurveType, JwtEcdsaTestVector>;

const JwtEcdsaTestVectorMap& CreateJwtEcdsaTestVectorsMap() {
  static const absl::NoDestructor<JwtEcdsaTestVectorMap> test_vectors(
      JwtEcdsaTestVectorMap{
          // P-256 (ES256) test vector from RFC 6979, Appendix A.2.5.
          {subtle::EllipticCurveType::NIST_P256,
           MakeJwtEcdsaTestVector(JwtEcdsaTestVectorParams{
               /*curve=*/subtle::EllipticCurveType::NIST_P256,
               /*kid_strategy=*/
               JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
               /*algorithm=*/JwtEcdsaParameters::Algorithm::kEs256,
               /*pub_x_hex=*/
               "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60"
               "F29FB6",
               /*pub_y_hex=*/
               "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4"
               "462299",
               /*priv_hex=*/
               "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B12"
               "0F6721",
               /*id_requirement=*/123,
               /*custom_kid=*/std::nullopt,
           })},
          // P-384 (ES384) test vector from RFC 6979, Appendix A.2.6.
          {subtle::EllipticCurveType::NIST_P384,
           MakeJwtEcdsaTestVector(JwtEcdsaTestVectorParams{
               /*curve=*/subtle::EllipticCurveType::NIST_P384,
               /*kid_strategy=*/JwtEcdsaParameters::KidStrategy::kCustom,
               /*algorithm=*/JwtEcdsaParameters::Algorithm::kEs384,
               /*pub_x_hex=*/
               "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B"
               "300C64DEF8F0EA9055866064A254515480BC13",
               /*pub_y_hex=*/
               "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F"
               "1C9DB1288B231C3AE0D4FE7344FD2533264720",
               /*priv_hex=*/
               "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA4774078"
               "7137D896D5724E4C70A825F872C9EA60D2EDF5",
               /*id_requirement=*/std::nullopt,
               /*custom_kid=*/"custom_kid",
           })},
          // P-521 (ES512) test vector from RFC 6979, Appendix A.2.7.
          {subtle::EllipticCurveType::NIST_P521,
           MakeJwtEcdsaTestVector(JwtEcdsaTestVectorParams{
               /*curve=*/subtle::EllipticCurveType::NIST_P521,
               /*kid_strategy=*/JwtEcdsaParameters::KidStrategy::kIgnored,
               /*algorithm=*/JwtEcdsaParameters::Algorithm::kEs512,
               /*pub_x_hex=*/
               "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB"
               "4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DC"
               "AC474B9A2F5023A4",
               /*pub_y_hex=*/
               "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D663"
               "0F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66"
               "956DFEAA2BFDFCF5",
               /*priv_hex=*/
               "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B6"
               "8C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC"
               "0C08B0E996B83538",
               /*id_requirement=*/std::nullopt,
               /*custom_kid=*/std::nullopt,
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<JwtEcdsaTestVector>& CreateJwtEcdsaTestVectors() {
  static const absl::NoDestructor<std::vector<JwtEcdsaTestVector>> test_vectors(
      [] {
        const JwtEcdsaTestVectorMap& test_vectors_map =
            CreateJwtEcdsaTestVectorsMap();
        std::vector<JwtEcdsaTestVector> result;
        result.reserve(test_vectors_map.size());
        for (const auto& [unused_params, test_vector] : test_vectors_map) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const JwtEcdsaTestVector& GetJwtEcdsaTestVector(
    subtle::EllipticCurveType curve) {
  const JwtEcdsaTestVectorMap& map = CreateJwtEcdsaTestVectorsMap();
  auto it = map.find(curve);
  ABSL_CHECK(it != map.end())
      << "No JWT ECDSA test vector found for elliptic curve: " << curve;
  return it->second;
}

const JwtEcdsaTestVector& GetJwtEcdsaWycheproofTestVector() {
  static const absl::NoDestructor<JwtEcdsaTestVector> test_vector(
      MakeJwtEcdsaTestVector(JwtEcdsaTestVectorParams{
          /*curve=*/subtle::EllipticCurveType::NIST_P256,
          /*kid_strategy=*/JwtEcdsaParameters::KidStrategy::kIgnored,
          /*algorithm=*/JwtEcdsaParameters::Algorithm::kEs256,
          /*pub_x_hex=*/
          "d38374c62db586c872bc1a7b235ebbb1b13f6d7ab2aa400f7de7dd92530eef06",
          /*pub_y_hex=*/
          "508f1ec72f82d3a6bb0d49e321d10d931785b47338fa5ff8d4ba84c3d9d5826c",
          /*priv_hex=*/
          "cb2e3da0f7083462b6a6cd0b9adc6907a51310e8884e08470627fac03aa62777",
          /*id_requirement=*/std::nullopt,
          /*custom_kid=*/std::nullopt,
      }));
  return *test_vector;
}

}  // namespace crypto::tink::jwt_internal
