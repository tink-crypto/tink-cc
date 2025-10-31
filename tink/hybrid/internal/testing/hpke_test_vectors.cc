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

#include "tink/hybrid/internal/testing/hpke_test_vectors.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::util::SecretDataFromStringView;

// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
std::string P256PointAsString() {
  std::string pub_key_x_p256_hex =
      "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
  std::string pub_key_y_p256_hex =
      "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
  return HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p256_hex, pub_key_y_p256_hex));
}

RestrictedData P256SecretValue() {
  SecretData secret_data = SecretDataFromStringView(HexDecodeOrDie(
      "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"));
  return RestrictedData(secret_data, InsecureSecretKeyAccess::Get());
}

HybridTestVector CreateTestVector0() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba742"
                     "34494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c1"
                     "15cf17875f59b069dffc8427cfb7f277ed4e370ae78f916e22"));
}

HybridTestVector CreateTestVector1() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters,
      HexDecodeOrDie(
          "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(HexDecodeOrDie("52c4a758a802cd8b936eceea314432798d5baf2d7e"
                                    "9235dc084ab1b9cfa2f736"),
                     InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("c202f5f26a59c446531b9e4e880f8730ff0aed444699cb1cd69a2c60e"
                     "07aba42d77a29b62c7af6b2cfda9c1529bb8d23c8"));
}

// AES_256_GCM
HybridTestVector CreateTestVector2() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("04b2de5915aa2bde7ad85745a632258caba46ed5be81297177dae45cd"
                     "cbcf49c92431ea80763f92f6b22115723a7d092994d40376f7618e9f2"
                     "ef82d5c44036e29eca440814ade6c8d5d9246abddaf5740331"));
}

// CHACHA20_POLY1305
HybridTestVector CreateTestVector3() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("04e0f41a312164058e2c36f1bc977e12a6fec8b13dc5fabc2441ec905"
                     "bc432145a0a5e50929815ec6944a3da1a186c0b9b428232086b218af0"
                     "61e9f814d8bd27808bce0bdb3c656d307f87ffe3bf13b0eb19"));
}

// TINK
HybridTestVector CreateTestVector4() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x886688aa,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "01886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"
          "4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"
          "b069dffc8427cfb7f277ed4e370ae78f916e22"));
}

// CRUNCHY
HybridTestVector CreateTestVector5() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x886688aa,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "00886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"
          "4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"
          "b069dffc8427cfb7f277ed4e370ae78f916e22"));
}

}  // namespace

std::vector<HybridTestVector> CreateHpkeTestVectors() {
  return {CreateTestVector0(), CreateTestVector1(), CreateTestVector2(),
          CreateTestVector3(), CreateTestVector4(), CreateTestVector5()};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
