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

#include "tink/internal/testing/ec_test_vectors.h"

#include <string>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/util.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {

using ::crypto::tink::test::HexDecodeOrDie;

EcPoint P256Point() {
  return EcPoint(
      BigInteger(HexDecodeOrDie(
          "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")),
      BigInteger(HexDecodeOrDie(
          "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")));
}

RestrictedData P256SecretValue() {
  return RestrictedData(
      HexDecodeOrDie(
          "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
      InsecureSecretKeyAccess::Get());
}

EcPoint P384Point() {
  return EcPoint(
      BigInteger(HexDecodeOrDie("009d92e0330dfc60ba8b2be32e10f7d2f8457678a112ca"
                                "fd4544b29b7e6addf0249968f54c"
                                "732aa49bc4a38f467edb8424")),
      BigInteger(HexDecodeOrDie("0081a3a9c9e878b86755f018a8ec3c5e80921910af919b"
                                "95f18976e35acc04efa2962e277a"
                                "0b2c990ae92b62d6c75180ba")));
}

RestrictedData P384SecretValue() {
  return RestrictedData(
      HexDecodeOrDie("670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f"
                     "0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9"),
      InsecureSecretKeyAccess::Get());
}

EcPoint P521Point() {
  return EcPoint(
      BigInteger(HexDecodeOrDie(
          "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
          "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
          "3A4")),
      BigInteger(HexDecodeOrDie(
          "493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
          "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
          "CF5")));
}

RestrictedData P521SecretValue() {
  return RestrictedData(
      HexDecodeOrDie(
          "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
          "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
          "538"),
      InsecureSecretKeyAccess::Get());
}

std::string X25519PublicValue() {
  return HexDecodeOrDie(
      "90c5b6d9b337cc6c9c2e8ac44f1c0e7c41f23bdf7a04df3b9c8081c0c278352a");
}

RestrictedData X25519SecretValue() {
  return RestrictedData(
      HexDecodeOrDie(
          "97d2e385c9968fbe2dc0b85a182199ed7e0b5b4bb6060f76583c0893241f698d"),
      InsecureSecretKeyAccess::Get());
}

// Returns a valid static EC key for the given curve type from RFC 6979.
using EcKeyMap =
    absl::flat_hash_map<subtle::EllipticCurveType, internal::EcKey>;

namespace {

SecretData ParseBigIntOrDie(absl::string_view val, int length) {
  absl::StatusOr<SecretData> result = ParseBigIntToFixedLength(val, length);
  ABSL_CHECK_OK(result);
  return *result;
}

}  // namespace

const EcKeyMap& CreateEcKeyMap() {
  static const absl::NoDestructor<EcKeyMap> ec_keys(EcKeyMap{
      {subtle::EllipticCurveType::NIST_P256,
       internal::EcKey{
           subtle::EllipticCurveType::NIST_P256,
           std::string(util::SecretDataAsStringView(
               ParseBigIntOrDie(P256Point().GetX().GetValue(), 32))),
           std::string(util::SecretDataAsStringView(
               ParseBigIntOrDie(P256Point().GetY().GetValue(), 32))),
           ParseBigIntOrDie(
               P256SecretValue().GetSecret(InsecureSecretKeyAccess::Get()), 32),
       }},
      {subtle::EllipticCurveType::NIST_P384,
       internal::EcKey{
           subtle::EllipticCurveType::NIST_P384,
           std::string(util::SecretDataAsStringView(
               ParseBigIntOrDie(P384Point().GetX().GetValue(), 48))),
           std::string(util::SecretDataAsStringView(
               ParseBigIntOrDie(P384Point().GetY().GetValue(), 48))),
           ParseBigIntOrDie(
               P384SecretValue().GetSecret(InsecureSecretKeyAccess::Get()), 48),
       }},
      {subtle::EllipticCurveType::NIST_P521,
       internal::EcKey{
           subtle::EllipticCurveType::NIST_P521,
           std::string(util::SecretDataAsStringView(
               ParseBigIntOrDie(P521Point().GetX().GetValue(), 66))),
           std::string(util::SecretDataAsStringView(
               ParseBigIntOrDie(P521Point().GetY().GetValue(), 66))),
           ParseBigIntOrDie(
               P521SecretValue().GetSecret(InsecureSecretKeyAccess::Get()), 66),
       }},
      {subtle::EllipticCurveType::CURVE25519,
       internal::EcKey{
           subtle::EllipticCurveType::CURVE25519,
           X25519PublicValue(),
           "",
           util::SecretDataFromStringView(
               X25519SecretValue().GetSecret(InsecureSecretKeyAccess::Get())),
       }},
  });
  return *ec_keys;
}

const internal::EcKey& GetEcKey(subtle::EllipticCurveType curve_type) {
  const EcKeyMap& ec_keys = CreateEcKeyMap();
  EcKeyMap::const_iterator it = ec_keys.find(curve_type);
  ABSL_CHECK(it != ec_keys.end())
      << "No EC key found for curve: " << curve_type;
  return it->second;
}

}  // namespace crypto::tink::internal
