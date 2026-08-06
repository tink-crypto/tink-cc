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

#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto::tink::jwt_internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;

JwtEcdsaTestVector MakeJwtEcdsaTestVector(subtle::EllipticCurveType curve,
                                          absl::string_view pub_x_hex,
                                          absl::string_view pub_y_hex,
                                          absl::string_view priv_hex) {
  return JwtEcdsaTestVector{
      curve,
      HexDecodeOrDie(pub_x_hex),
      HexDecodeOrDie(pub_y_hex),
      HexDecodeOrDie(priv_hex),
  };
}

using JwtEcdsaTestVectorMap =
    absl::flat_hash_map<subtle::EllipticCurveType, JwtEcdsaTestVector>;

const JwtEcdsaTestVectorMap& CreateJwtEcdsaTestVectorsMap() {
  static const absl::NoDestructor<JwtEcdsaTestVectorMap> test_vectors(
      JwtEcdsaTestVectorMap{
          {subtle::EllipticCurveType::NIST_P256,
           MakeJwtEcdsaTestVector(
               subtle::EllipticCurveType::NIST_P256,
               "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60"
               "F29FB6",
               "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4"
               "462299",
               "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B12"
               "0F6721")},
          {subtle::EllipticCurveType::NIST_P384,
           MakeJwtEcdsaTestVector(
               subtle::EllipticCurveType::NIST_P384,
               "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B"
               "300C64DEF8F0EA9055866064A254515480BC13",
               "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F"
               "1C9DB1288B231C3AE0D4FE7344FD2533264720",
               "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA4774078"
               "7137D896D5724E4C70A825F872C9EA60D2EDF5")},
          {subtle::EllipticCurveType::NIST_P521,
           MakeJwtEcdsaTestVector(
               subtle::EllipticCurveType::NIST_P521,
               "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB"
               "4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DC"
               "AC474B9A2F5023A4",
               "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D663"
               "0F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66"
               "956DFEAA2BFDFCF5",
               "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B6"
               "8C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC"
               "0C08B0E996B83538")},
      });
  return *test_vectors;
}

}  // namespace

const JwtEcdsaTestVector& CreateJwtEcdsaP256TestVector() {
  return GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256);
}

const JwtEcdsaTestVector& CreateJwtEcdsaP256WycheproofTestVector() {
  static const absl::NoDestructor<JwtEcdsaTestVector> test_vector(
      MakeJwtEcdsaTestVector(
          subtle::EllipticCurveType::NIST_P256,
          "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
          "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
          "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"));
  return *test_vector;
}

const JwtEcdsaTestVector& CreateJwtEcdsaP384TestVector() {
  return GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P384);
}

const JwtEcdsaTestVector& CreateJwtEcdsaP521TestVector() {
  return GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P521);
}

const JwtEcdsaTestVector& GetJwtEcdsaTestVector(
    subtle::EllipticCurveType curve) {
  const JwtEcdsaTestVectorMap& map = CreateJwtEcdsaTestVectorsMap();
  auto it = map.find(curve);
  ABSL_CHECK(it != map.end())
      << "No JWT ECDSA test vector found for elliptic curve: " << curve;
  return it->second;
}

}  // namespace crypto::tink::jwt_internal
