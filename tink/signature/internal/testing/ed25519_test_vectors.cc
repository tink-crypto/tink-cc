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

RestrictedData Ed25519PrivateKeyBytes(){
  return RestrictedData(
      HexDecodeOrDie(
          "9cac7d19aeecc563a3dff7bcae0fbbbc28087b986c49a3463077dd5281437e81"),
      InsecureSecretKeyAccess::Get());
}

std::string Ed25519PublicKeyBytes() {
  return HexDecodeOrDie(
      "ea42941a6dc801484390b2955bc7376d172eeb72640a54e5b50c95efa2fc6ad8");
}

SignatureTestVector CreateTestVector0() {
  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix).value(),
      Ed25519PublicKeyBytes(), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie("3431985050f48157551262d591d0f1f25b9c6808fce4345066cb8216d"
                     "48fcd9feafa4b24949a7f8cabdc16a51030a19d7514c9685c221475bf"
                     "3cfc363472ee0a"),
      HexDecodeOrDie("aa"));
}

// TINK
SignatureTestVector CreateTestVector1() {
  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink).value(),
      Ed25519PublicKeyBytes(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie("0199887766"
                     "3431985050f48157551262d591d0f1f25b9c6808fce4345066cb8216d"
                     "48fcd9feafa4b24949a7f8cabdc16a51030a19d7514c9685c221475bf"
                     "3cfc363472ee0a"),
      HexDecodeOrDie("aa"));
}

// Crunchy
SignatureTestVector CreateTestVector2() {
  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kCrunchy).value(),
      Ed25519PublicKeyBytes(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie("0099887766"
                     "3431985050f48157551262d591d0f1f25b9c6808fce4345066cb8216d"
                     "48fcd9feafa4b24949a7f8cabdc16a51030a19d7514c9685c221475bf"
                     "3cfc363472ee0a"),
      HexDecodeOrDie("aa"));
}

SignatureTestVector CreateTestVector3() {
  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kLegacy).value(),
      Ed25519PublicKeyBytes(), 0x99887766, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  return SignatureTestVector(
      absl::make_unique<Ed25519PrivateKey>(
          Ed25519PrivateKey::Create(*public_key, Ed25519PrivateKeyBytes(),
                                    GetPartialKeyAccess())
              .value()),
      HexDecodeOrDie("0099887766"
                     "e828586415b1226c118617a2b56b923b6717e83c4d265fcb4e2cdf3cb"
                     "902ce7b9b1ecd8405cb4e6a8e248ef5478891b5b6f80f737df16594f8"
                     "8662595d8f140e"),
      HexDecodeOrDie("aa"));
}

}  // namespace

std::vector<SignatureTestVector> CreateEd25519TestVectors() {
  return {CreateTestVector0(), CreateTestVector1(), CreateTestVector2(),
          CreateTestVector3()};
}
}  // namespace internal
}  // namespace tink
}  // namespace crypto
