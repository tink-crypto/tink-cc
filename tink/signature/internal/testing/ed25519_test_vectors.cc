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

#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/util/statusor.h"
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

SignatureTestVector CreateTestVector0() {
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix).value(),
      Ed25519PublicKeyBytes(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie(kSignatureHex), HexDecodeOrDie(kMessageHex));
}

// TINK
SignatureTestVector CreateTestVector1() {
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink).value(),
      Ed25519PublicKeyBytes(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie(absl::StrCat("0199887766", kSignatureHex)),
      HexDecodeOrDie(kMessageHex));
}

// Crunchy
SignatureTestVector CreateTestVector2() {
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kCrunchy).value(),
      Ed25519PublicKeyBytes(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie(absl::StrCat("0099887766", kSignatureHex)),
      HexDecodeOrDie(kMessageHex));
}

// NOTE: This test vector has been generated adding a `0x00` suffix to the
// message.
SignatureTestVector CreateTestVector3() {
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kLegacy).value(),
      Ed25519PublicKeyBytes(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie(
          "0099887766"
          "afeae7a4fcd7d710a03353dfbe11a9906c6918633bb4dfef655d62d21f7535a1"
          "108ea3ef5bef2b0d0acefbf0e051f62ee2582652ae769df983ad1b11a95d3a08"),
      HexDecodeOrDie(kMessageHex));
}

}  // namespace

std::vector<SignatureTestVector> CreateEd25519TestVectors() {
  return {CreateTestVector0(), CreateTestVector1(), CreateTestVector2(),
          CreateTestVector3()};
}
}  // namespace internal
}  // namespace tink
}  // namespace crypto
