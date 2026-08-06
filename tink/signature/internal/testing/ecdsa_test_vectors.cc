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

#include "tink/signature/internal/testing/ecdsa_test_vectors.h"

#include <memory>
#include <optional>
#include <tuple>
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
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {
using ::crypto::tink::test::HexDecodeOrDie;

// Point from https://www.ietf.org/rfc/rfc6979.txt, A.2.5
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

struct EcdsaTestVectorParams {
  EcdsaParameters::CurveType curve_type;
  EcdsaParameters::HashType hash_type;
  EcdsaParameters::SignatureEncoding signature_encoding;
  EcdsaParameters::Variant variant;
  EcPoint public_point;
  RestrictedData private_key_value;
  std::optional<int> id_requirement;
  absl::string_view signature_hex;
  absl::string_view message_hex;
};

SignatureTestVector MakeEcdsaTestVector(const EcdsaTestVectorParams& params) {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(params.curve_type)
          .SetHashType(params.hash_type)
          .SetSignatureEncoding(params.signature_encoding)
          .SetVariant(params.variant)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, params.public_point,
                             params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, params.private_key_value, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());
  return SignatureTestVector(
      std::make_unique<EcdsaPrivateKey>(*std::move(private_key)),
      HexDecodeOrDie(params.signature_hex), HexDecodeOrDie(params.message_hex));
}

using EcdsaTestVectorMap = absl::flat_hash_map<
    std::tuple<EcdsaParameters::CurveType, EcdsaParameters::HashType,
               EcdsaParameters::SignatureEncoding, EcdsaParameters::Variant>,
    SignatureTestVector>;

const EcdsaTestVectorMap& CreateEcdsaTestVectorsMap() {
  static const absl::NoDestructor<EcdsaTestVectorMap> test_vectors(
      EcdsaTestVectorMap{
          {{EcdsaParameters::CurveType::kNistP256,
            EcdsaParameters::HashType::kSha256,
            EcdsaParameters::SignatureEncoding::kIeeeP1363,
            EcdsaParameters::Variant::kNoPrefix},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP256,
               /*hash_type=*/EcdsaParameters::HashType::kSha256,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kIeeeP1363,
               /*variant=*/EcdsaParameters::Variant::kNoPrefix,
               /*public_point=*/P256Point(),
               /*private_key_value=*/P256SecretValue(),
               /*id_requirement=*/std::nullopt,
               /*signature_hex=*/
               "70cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f8ce2855262b"
               "b"
               "5d0b69eefc4dea7b086aa62186e9a7c8600e7b0f1252f704271d5189e7a5cf"
               "03",
               /*message_hex=*/"",
           })},
          {{EcdsaParameters::CurveType::kNistP256,
            EcdsaParameters::HashType::kSha256,
            EcdsaParameters::SignatureEncoding::kDer,
            EcdsaParameters::Variant::kNoPrefix},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP256,
               /*hash_type=*/EcdsaParameters::HashType::kSha256,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kDer,
               /*variant=*/EcdsaParameters::Variant::kNoPrefix,
               /*public_point=*/P256Point(),
               /*private_key_value=*/P256SecretValue(),
               /*id_requirement=*/std::nullopt,
               /*signature_hex=*/
               "3046022100baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276a"
               "e"
               "1f4b3c63a2022100d404a3015cb229f7cb036c2b5f77cc546065eed4b75837"
               "cec2883d1e35d5eb9f",
               /*message_hex=*/"",
           })},
          {{EcdsaParameters::CurveType::kNistP256,
            EcdsaParameters::HashType::kSha256,
            EcdsaParameters::SignatureEncoding::kIeeeP1363,
            EcdsaParameters::Variant::kTink},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP256,
               /*hash_type=*/EcdsaParameters::HashType::kSha256,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kIeeeP1363,
               /*variant=*/EcdsaParameters::Variant::kTink,
               /*public_point=*/P256Point(),
               /*private_key_value=*/P256SecretValue(),
               /*id_requirement=*/0x99887766,
               /*signature_hex=*/
               "019988776670cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f"
               "8ce2855262bb5d0b69eefc4dea7b086aa62186e9a7c8600e7b0f1252f70427"
               "1d5189e7a5cf03",
               /*message_hex=*/"",
           })},
          {{EcdsaParameters::CurveType::kNistP256,
            EcdsaParameters::HashType::kSha256,
            EcdsaParameters::SignatureEncoding::kIeeeP1363,
            EcdsaParameters::Variant::kCrunchy},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP256,
               /*hash_type=*/EcdsaParameters::HashType::kSha256,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kIeeeP1363,
               /*variant=*/EcdsaParameters::Variant::kCrunchy,
               /*public_point=*/P256Point(),
               /*private_key_value=*/P256SecretValue(),
               /*id_requirement=*/0x99887766,
               /*signature_hex=*/
               "009988776670cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f"
               "8ce2855262bb5d0b69eefc4dea7b086aa62186e9a7c8600e7b0f1252f70427"
               "1d5189e7a5cf03",
               /*message_hex=*/"",
           })},
          {{EcdsaParameters::CurveType::kNistP256,
            EcdsaParameters::HashType::kSha256,
            EcdsaParameters::SignatureEncoding::kIeeeP1363,
            EcdsaParameters::Variant::kLegacy},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP256,
               /*hash_type=*/EcdsaParameters::HashType::kSha256,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kIeeeP1363,
               /*variant=*/EcdsaParameters::Variant::kLegacy,
               /*public_point=*/P256Point(),
               /*private_key_value=*/P256SecretValue(),
               /*id_requirement=*/0x99887766,
               /*signature_hex=*/
               "0099887766515b67e48efb8ebc12e0ce691cf210b18c1e96409667aaedd8d7"
               "44c64aff843a4e09ebfb9b6c40a6540dd0d835693ca08da8c1d8e434770511"
               "459088243b0bbb",
               /*message_hex=*/"",
           })},
          {{EcdsaParameters::CurveType::kNistP384,
            EcdsaParameters::HashType::kSha384,
            EcdsaParameters::SignatureEncoding::kIeeeP1363,
            EcdsaParameters::Variant::kNoPrefix},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP384,
               /*hash_type=*/EcdsaParameters::HashType::kSha384,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kIeeeP1363,
               /*variant=*/EcdsaParameters::Variant::kNoPrefix,
               /*public_point=*/P384Point(),
               /*private_key_value=*/P384SecretValue(),
               /*id_requirement=*/std::nullopt,
               /*signature_hex=*/
               "eb19dc251dcbb0aac7634c646b27ccc59a21d6231e08d2b6031ec729ecb0e9"
               "927b70bfa66d458b5e1b7186355644fa9150602bade9f0c358b9d28263cb42"
               "7f58bf7d9b892ac75f43ab048360b34ee81653f85ec2f10e6e4f0f0e0cafbe"
               "91f883",
               /*message_hex=*/"",
           })},
          {{EcdsaParameters::CurveType::kNistP384,
            EcdsaParameters::HashType::kSha512,
            EcdsaParameters::SignatureEncoding::kIeeeP1363,
            EcdsaParameters::Variant::kNoPrefix},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP384,
               /*hash_type=*/EcdsaParameters::HashType::kSha512,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kIeeeP1363,
               /*variant=*/EcdsaParameters::Variant::kNoPrefix,
               /*public_point=*/P384Point(),
               /*private_key_value=*/P384SecretValue(),
               /*id_requirement=*/std::nullopt,
               /*signature_hex=*/
               "3db99cec1a865909886f8863ccfa3147f21ccad262a41abc8d964fafa55141"
               "a9d89efa6bf0acb4e5ec357c6056542e7e016d4a653fde985aad594763900f"
               "3f9c4494f45f7a4450422640f57b0ad467950f78ddb56641676cb91d392410"
               "ed606d",
               /*message_hex=*/"",
           })},
          {{EcdsaParameters::CurveType::kNistP521,
            EcdsaParameters::HashType::kSha512,
            EcdsaParameters::SignatureEncoding::kIeeeP1363,
            EcdsaParameters::Variant::kNoPrefix},
           MakeEcdsaTestVector(EcdsaTestVectorParams{
               /*curve_type=*/EcdsaParameters::CurveType::kNistP521,
               /*hash_type=*/EcdsaParameters::HashType::kSha512,
               /*signature_encoding=*/
               EcdsaParameters::SignatureEncoding::kIeeeP1363,
               /*variant=*/EcdsaParameters::Variant::kNoPrefix,
               /*public_point=*/P521Point(),
               /*private_key_value=*/P521SecretValue(),
               /*id_requirement=*/std::nullopt,
               /*signature_hex=*/
               "00eaf6672f0696a46046d3b1572814b697c7904fe265fece75e33b90833d08"
               "af6513adfb6cbf0a4971442633c981d11cd068fcf9431cbe49448b4240a067"
               "d860f7fb0168a8d7bf1602050b2255e844aea1df8d8ad770053d2c915cca2a"
               "f6e175c2fb0944f6a9e3262fb9b99910e7fbd6ef4aca887b901ec78678d3ec"
               "48529c7f06e8c815",
               /*message_hex=*/"",
           })},
      });
  return *test_vectors;
}

}  // namespace

const SignatureTestVector& GetEcdsaTestVector(
    EcdsaParameters::CurveType curve_type, EcdsaParameters::HashType hash_type,
    EcdsaParameters::SignatureEncoding signature_encoding,
    EcdsaParameters::Variant variant) {
  const EcdsaTestVectorMap& map = CreateEcdsaTestVectorsMap();
  auto it = map.find(
      std::make_tuple(curve_type, hash_type, signature_encoding, variant));
  ABSL_CHECK(it != map.end()) << "No ECDSA test vector found.";
  return it->second;
}

const std::vector<SignatureTestVector>& CreateEcdsaTestVectors() {
  static const absl::NoDestructor<std::vector<SignatureTestVector>>
      test_vectors([] {
        std::vector<SignatureTestVector> result;
        result.reserve(CreateEcdsaTestVectorsMap().size());
        for (const auto& [unused_params, test_vector] :
             CreateEcdsaTestVectorsMap()) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}
}  // namespace internal
}  // namespace tink
}  // namespace crypto
