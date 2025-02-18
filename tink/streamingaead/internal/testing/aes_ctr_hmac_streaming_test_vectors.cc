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

#include "tink/streamingaead/internal/testing/aes_ctr_hmac_streaming_test_vectors.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

std::string Xor(absl::string_view a, absl::string_view b) {
  CHECK_EQ(a.size(), b.size());
  std::string result;
  result.resize(a.size());
  for (int i = 0; i < a.size(); ++i) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// From the cross language tests, test_manually_created_test_vector
StreamingAeadTestVector CreateTestVector0() {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha1)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(64)
          .Build();
  CHECK_OK(parameters);

  RestrictedData initial_key_material =
      RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                     InsecureSecretKeyAccess::Get());
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  CHECK_OK(key);

  absl::string_view plaintext =
      "This is a fairly long plaintext. However, it is not crazy long.";
  absl::string_view associated_data = "aad";

  std::string header_length = HexDecodeOrDie("18");
  std::string salt = HexDecodeOrDie("93b3af5e14ab378d065addfc8484da64");
  std::string nonce_prefix = HexDecodeOrDie("2c0862877baea8");
  std::string header = absl::StrCat(header_length, salt, nonce_prefix);

  std::string msg0 = std::string(plaintext.substr(0, 8));
  std::string msg1 = std::string(plaintext.substr(8, 32));
  std::string msg2 = std::string(plaintext.substr(40));

  std::string c0 = Xor(msg0, HexDecodeOrDie("ea8e18301bd57bfd"));
  std::string c1 = Xor(
      msg1,
      HexDecodeOrDie(
          "2999c8ea5401704243c8cd77929fd52617fec5542a842446251bb2f3a81f6249"));
  std::string c2 = Xor(
      msg2, HexDecodeOrDie("70fe58e44835a6602952749e763637d9d973bca8358086"));
  std::string tag0 = HexDecodeOrDie(
      "8303ca71c04d8e06e1b01cff7c1178af47dac031517b1f6a2d9be84105677a68");
  std::string tag1 = HexDecodeOrDie(
      "834d890839f37f762caddc029cc673300ff107fd51f9a62058fcd00befc362e5");
  std::string tag2 = HexDecodeOrDie(
      "5fb0c893903271af38380c2f355cb85e5ec571648513123321bde0c6042f43c7");

  std::string ciphertext = absl::StrCat(header, c0, tag0, c1, tag1, c2, tag2);

  return StreamingAeadTestVector(std::make_shared<AesCtrHmacStreamingKey>(*key),
                                 plaintext, associated_data, ciphertext);
}

// Created in Java.
StreamingAeadTestVector CreateTestVector1() {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha1)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(64)
          .Build();
  CHECK_OK(parameters);
  RestrictedData initial_key_material =
      RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                     InsecureSecretKeyAccess::Get());
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  CHECK_OK(key);

  std::string plaintext = "";
  std::string associated_data = "";
  std::string ciphertext = HexDecodeOrDie(
      "1874eaeea1260b1cf44d00bfec6d7f58878ce2dd70d5844e2f4410a04703ec4c17ca8c88"
      "31be0f1711da64b5b893ca9f3ba643d6764fd787");
  return StreamingAeadTestVector(std::make_shared<AesCtrHmacStreamingKey>(*key),
                                 plaintext, associated_data, ciphertext);
}

// Created in Java, Use SHA256/SHA512
StreamingAeadTestVector CreateTestVector2() {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(64)
          .Build();
  CHECK_OK(parameters);
  RestrictedData initial_key_material =
      RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                     InsecureSecretKeyAccess::Get());
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  CHECK_OK(key);

  std::string plaintext = "";
  std::string associated_data = HexDecodeOrDie("000102030405");
  std::string ciphertext = HexDecodeOrDie(
      "18ae4fc7af4ed0433d33110793196ead8a77d2ae3f42db8425dc9e0789bdba7d5c23d612"
      "87fbe108224fbf11da38c8eaf5c9feab7deb9c62");
  return StreamingAeadTestVector(std::make_shared<AesCtrHmacStreamingKey>(*key),
                                 plaintext, associated_data, ciphertext);
}

// Created in Java, Use SHA512/SHA1
StreamingAeadTestVector CreateTestVector3() {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha1)
          .SetHmacTagSizeInBytes(20)
          .SetCiphertextSegmentSizeInBytes(64)
          .Build();
  CHECK_OK(parameters);
  RestrictedData initial_key_material =
      RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                     InsecureSecretKeyAccess::Get());
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  CHECK_OK(key);

  std::string plaintext = "";
  std::string associated_data = HexDecodeOrDie("000102030405");
  std::string ciphertext = HexDecodeOrDie(
      "180d87a22c8979d8eb90163aa33aa09a02bab964d5bb2d7a035e62206d62807b3e9bb498"
      "4109ebeb3dfcbf43");
  return StreamingAeadTestVector(std::make_shared<AesCtrHmacStreamingKey>(*key),
                                 plaintext, associated_data, ciphertext);
}

// Created in Java, Use KeySizeBytes=32
StreamingAeadTestVector CreateTestVector4() {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacTagSizeInBytes(20)
          .SetCiphertextSegmentSizeInBytes(64)
          .Build();
  CHECK_OK(parameters);
  RestrictedData initial_key_material = RestrictedData(
      HexDecodeOrDie(
          "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"),
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  CHECK_OK(key);

  std::string plaintext = "";
  std::string associated_data =
      HexDecodeOrDie("012345678901234567890123456789");
  std::string ciphertext = HexDecodeOrDie(
      "18290c66c47a6095d947aa1671bd7b6d9c306e24d51d4b8a4f1b9db123a01226ebd2b6f7"
      "e05298a9f5908072");
  return StreamingAeadTestVector(std::make_shared<AesCtrHmacStreamingKey>(*key),
                                 plaintext, associated_data, ciphertext);
}

// Created in Java, Use DerivedKeySizeBytes=32
StreamingAeadTestVector CreateTestVector5() {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacTagSizeInBytes(20)
          .SetCiphertextSegmentSizeInBytes(64)
          .Build();
  CHECK_OK(parameters);
  RestrictedData initial_key_material = RestrictedData(
      HexDecodeOrDie(
          "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"),
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  CHECK_OK(key);

  std::string plaintext = "";
  std::string associated_data =
      HexDecodeOrDie("012345678901234567890123456789");
  std::string ciphertext = HexDecodeOrDie(
      "28f7bcc58e83e8e24bf833d8586c889ef465f52fdebcad6deb18be062c180e466de959eb"
      "a1a884926692e496d85e1873a1bf9b46e56d76d83772bfc6");
  return StreamingAeadTestVector(std::make_shared<AesCtrHmacStreamingKey>(*key),
                                 plaintext, associated_data, ciphertext);
}

}  // namespace

std::vector<StreamingAeadTestVector> CreateAesCtrHmacStreamingTestVectors() {
  return {CreateTestVector0(), CreateTestVector1(), CreateTestVector2(),
          CreateTestVector3(), CreateTestVector4(), CreateTestVector5()};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
