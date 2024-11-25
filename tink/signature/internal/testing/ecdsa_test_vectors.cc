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

#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
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

RestrictedBigInteger P256SecretValue() {
  return RestrictedBigInteger(
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

RestrictedBigInteger P384SecretValue() {
  return RestrictedBigInteger(
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

RestrictedBigInteger P521SecretValue() {
  return RestrictedBigInteger(
      HexDecodeOrDie(
          "FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
          "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
          "538"),
      InsecureSecretKeyAccess::Get());
}

SignatureTestVector CreateTestVector0() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P256Point(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "70cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f8ce2855262bb5d"
          "0b69eefc4dea7b086aa62186e9a7c8600e7b0f1252f704271d5189e7a5cf03"),
      HexDecodeOrDie(""));
}

// Signature encoding: DER
SignatureTestVector CreateTestVector1() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P256Point(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "3046022100baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276ae1f4b"
          "3c63a2022100d404a3"
          "015cb229f7cb036c2b5f77cc546065eed4b75837cec2883d1e35d5eb9f"),
      HexDecodeOrDie(""));
}

// Variant: TINK
SignatureTestVector CreateTestVector2() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P256Point(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "0199887766"
          "70cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f8ce2855262bb5d"
          "0b69eefc4dea7b086aa62186e9a7c8600e7b0f1252f704271d5189e7a5cf03"),
      HexDecodeOrDie(""));
}

// Variant: CRUNCHY
SignatureTestVector CreateTestVector3() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kCrunchy)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P256Point(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "0099887766"
          "70cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f8ce2855262bb5d"
          "0b69eefc4dea7b086aa62186e9a7c8600e7b0f1252f704271d5189e7a5cf03"),
      HexDecodeOrDie(""));
}

// Variant: CRUNCHY
SignatureTestVector CreateTestVector4() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kLegacy)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P256Point(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie("0099887766515b67e48efb8ebc12e0ce691cf210b18c1e96409667aae"
                     "dd8d744c64aff843a4e09ebfb9b6c40a6540dd0d835693ca08da8c1d8"
                     "e434770511459088243b0bbb"),
      HexDecodeOrDie(""));
}

// Non-empty message
SignatureTestVector CreateTestVector5() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P256Point(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "bfec68e554a26e161b657efb368a6cd0ec3499c92f2b6240e1b92fa724366a79ca37"
          "137274c9125e34c286439c848ce3594a3f9450f4108a2fc287a120dfab4f"),
      HexDecodeOrDie("001122"));
}

// NIST_P384, SHA384
SignatureTestVector CreateTestVector6() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P384Point(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P384SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "eb19dc251dcbb0aac7634c646b27ccc59a21d6231e08d2b6031ec729ecb0e9927b70"
          "bfa66d458b5e1b7186355644fa9150602bade9f0c358b9d28263cb427f58bf7d9b89"
          "2ac75f43ab048360b34ee81653f85ec2f10e6e4f0f0e0cafbe91f883"),
      HexDecodeOrDie(""));
}

// NIST_P384, SHA384
SignatureTestVector CreateTestVector7() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P384Point(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P384SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "3db99cec1a865909886f8863ccfa3147f21ccad262a41abc8d964fafa55141a9d89e"
          "fa6bf0acb4e5ec357c6056542e7e016d4a653fde985aad594763900f3f9c4494f45f"
          "7a4450422640f57b0ad467950f78ddb56641676cb91d392410ed606d"),
      HexDecodeOrDie(""));
}

// NIST_P384, SHA384
SignatureTestVector CreateTestVector8() {
  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP521)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, P521Point(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, P521SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());
  return SignatureTestVector(
      absl::make_unique<EcdsaPrivateKey>(*private_key),
      HexDecodeOrDie(
          "00eaf6672f0696a46046d3b1572814b697c7904fe265fece75e33b90833d08af6513"
          "adfb6cbf0a4971442633c981d11cd068fcf9431cbe49448b4240a067d860f7fb0168"
          "a8d7bf1602050b2255e844aea1df8d8ad770053d2c915cca2af6e175c2fb0944f6a9"
          "e3262fb9b99910e7fbd6ef4aca887b901ec78678d3ec48529c7f06e8c815"),
      HexDecodeOrDie(""));
}

}  // namespace

std::vector<SignatureTestVector> CreateEcdsaTestVectors() {
  return {CreateTestVector0(), CreateTestVector1(), CreateTestVector2(),
          CreateTestVector3(), CreateTestVector4(), CreateTestVector5(),
          CreateTestVector6(), CreateTestVector7(), CreateTestVector8()};
}
}  // namespace internal
}  // namespace tink
}  // namespace crypto
