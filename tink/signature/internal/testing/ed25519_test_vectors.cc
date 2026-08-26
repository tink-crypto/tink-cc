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

#include "tink/signature/internal/testing/ed25519_test_vectors.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {
using ::crypto::tink::test::HexDecodeOrDie;

// Test vectors are from
// https://datatracker.ietf.org/doc/html/rfc8032#section-7.1 - TEST 3.

constexpr absl::string_view kSignatureHex =
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d"
    "16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

constexpr absl::string_view kMessageHex = "af82";

RestrictedData Ed25519PrivateKeyBytes() {
  return RestrictedData(
      HexDecodeOrDie(
          "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
      InsecureSecretKeyAccess::Get());
}

std::string Ed25519PublicKeyBytes() {
  return HexDecodeOrDie(
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
}

// Test vector from
// https://datatracker.ietf.org/doc/html/rfc8032#section-7.1 - TEST 1.
constexpr absl::string_view kEmptyMessageSignatureHex =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

RestrictedData Ed25519EmptyMessagePrivateKeyBytes() {
  return RestrictedData(
      HexDecodeOrDie(
          "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
      InsecureSecretKeyAccess::Get());
}

std::string Ed25519EmptyMessagePublicKeyBytes() {
  return HexDecodeOrDie(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
}

struct Ed25519TestVectorParams {
  Ed25519Parameters::Variant variant;
  std::optional<int> id_requirement;
  absl::string_view signature_hex;
  absl::string_view message_hex;
};

SignatureTestVector MakeEd25519TestVector(
    const Ed25519TestVectorParams& params) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(params.variant);
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*parameters, Ed25519PublicKeyBytes(),
                               params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key, Ed25519PrivateKeyBytes(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());
  return SignatureTestVector(
      std::make_unique<Ed25519PrivateKey>(*std::move(private_key)),
      HexDecodeOrDie(params.signature_hex), HexDecodeOrDie(params.message_hex));
}

using Ed25519TestVectorMap =
    absl::flat_hash_map<Ed25519Parameters::Variant, SignatureTestVector>;

const Ed25519TestVectorMap& CreateEd25519TestVectorsMap() {
  static const absl::NoDestructor<Ed25519TestVectorMap> test_vectors(
      Ed25519TestVectorMap{
          {Ed25519Parameters::Variant::kNoPrefix,
           MakeEd25519TestVector(Ed25519TestVectorParams{
               /*variant=*/Ed25519Parameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*signature_hex=*/kSignatureHex,
               /*message_hex=*/kMessageHex,
           })},
          {Ed25519Parameters::Variant::kTink,
           MakeEd25519TestVector(Ed25519TestVectorParams{
               /*variant=*/Ed25519Parameters::Variant::kTink,
               /*id_requirement=*/0x99887766,
               /*signature_hex=*/
               "01998877666291d657deec24024827e69c3abe01a30ce548a284743a445e3"
               "680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28d"
               "c027beceea1ec40a",
               /*message_hex=*/kMessageHex,
           })},
          {Ed25519Parameters::Variant::kCrunchy,
           MakeEd25519TestVector(Ed25519TestVectorParams{
               /*variant=*/Ed25519Parameters::Variant::kCrunchy,
               /*id_requirement=*/0x99887766,
               /*signature_hex=*/
               "00998877666291d657deec24024827e69c3abe01a30ce548a284743a445e3"
               "680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28d"
               "c027beceea1ec40a",
               /*message_hex=*/kMessageHex,
           })},
          {Ed25519Parameters::Variant::kLegacy,
           MakeEd25519TestVector(Ed25519TestVectorParams{
               /*variant=*/Ed25519Parameters::Variant::kLegacy,
               /*id_requirement=*/0x99887766,
               /*signature_hex=*/
               "0099887766afeae7a4fcd7d710a03353dfbe11a9906c6918633bb4dfef655"
               "d62d21f7535a1108ea3ef5bef2b0d0acefbf0e051f62ee2582652ae769df9"
               "83ad1b11a95d3a08",
               /*message_hex=*/kMessageHex,
           })},
      });
  return *test_vectors;
}

}  // namespace

const SignatureTestVector& GetEd25519TestVector(
    Ed25519Parameters::Variant variant) {
  const Ed25519TestVectorMap& map = CreateEd25519TestVectorsMap();
  auto it = map.find(variant);
  ABSL_CHECK(it != map.end()) << "No Ed25519 test vector found.";
  return it->second;
}

const std::vector<SignatureTestVector>& CreateEd25519TestVectors() {
  static const absl::NoDestructor<std::vector<SignatureTestVector>>
      test_vectors([] {
        std::vector<SignatureTestVector> result;
        result.reserve(CreateEd25519TestVectorsMap().size());
        for (const auto& [unused_params, test_vector] :
             CreateEd25519TestVectorsMap()) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const SignatureTestVector& CreateEd25519EmptyMessageTestVector() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([] {
    absl::StatusOr<Ed25519Parameters> parameters =
        Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
    ABSL_CHECK_OK(parameters.status());
    absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
        *parameters, Ed25519EmptyMessagePublicKeyBytes(), std::nullopt,
        GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key.status());
    absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
        *public_key, Ed25519EmptyMessagePrivateKeyBytes(),
        GetPartialKeyAccess());
    ABSL_CHECK_OK(private_key.status());
    return SignatureTestVector(
        std::make_unique<Ed25519PrivateKey>(*std::move(private_key)),
        HexDecodeOrDie(kEmptyMessageSignatureHex), "");
  }());
  return *test_vector;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
