// Copyright 2025 Google LLC
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

#include "tink/streamingaead/internal/testing/aes_gcm_hkdf_streaming_test_vectors.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

// From the cross language tests, test_manually_created_test_vector
const StreamingAeadTestVector& CreateAes128GcmHkdfSha1StreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(16)
            .SetDerivedKeySizeInBytes(16)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha1)
            .SetCiphertextSegmentSizeInBytes(64)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material =
        RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                       InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    absl::string_view plaintext =
        "This is a fairly long plaintext. It is of the exact length to create "
        "three output blocks. ";
    absl::string_view associated_data = "aad";

    std::string header_length = HexDecodeOrDie("18");
    std::string salt = HexDecodeOrDie("93b3af5e14ab378d065addfc8484da64");
    std::string nonce_prefix = HexDecodeOrDie("2c0862877baea8");
    std::string header = absl::StrCat(header_length, salt, nonce_prefix);

    std::string c0 = HexDecodeOrDie(
        "db92d9c77406a406168478821c4298eab3e6d531277f4c1"
        "a051714faebcaefcbca7b7be05e9445ea");
    std::string c1 = HexDecodeOrDie(
        "a0bb2904153398a25084dd80ae0edcd1c3079fcea2cd3770"
        "630ee36f7539207b8ec9d754956d486b71cdf989f0ed6fba"
        "6779b63558be0a66e668df14e1603cd2");
    std::string c2 = HexDecodeOrDie(
        "af8944844078345286d0b292e772e7190775"
        "c51a0f83e40c0b75821027e7e538e111");

    std::string ciphertext = absl::StrCat(header, c0, c1, c2);

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

// From Java AesGcmHkdfStreamingTestUtil.java, createTestVector1
const StreamingAeadTestVector&
CreateAes128GcmHkdfSha1EmptyPtStreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(16)
            .SetDerivedKeySizeInBytes(16)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha1)
            .SetCiphertextSegmentSizeInBytes(64)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material =
        RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                       InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    std::string plaintext = "";
    std::string associated_data = "";
    std::string ciphertext = HexDecodeOrDie(
        "18ec99b2c3884194023bd41bb9bff309205354c750fa0cb3c0d02609abf71f88eaeaa4"
        "8d7deca27f");

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

// From Java AesGcmHkdfStreamingTestUtil.java, createTestVector2
const StreamingAeadTestVector& CreateAes128GcmHkdfSha256StreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(16)
            .SetDerivedKeySizeInBytes(16)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
            .SetCiphertextSegmentSizeInBytes(64)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material =
        RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                       InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    std::string plaintext = "";
    std::string associated_data = "";
    std::string ciphertext = HexDecodeOrDie(
        "18be78bce0cab6fd38a9041eea8ab0ffc4cf17e3c00b661d3927f5f79069f41a210fed"
        "c40b25648c");

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

// From Java AesGcmHkdfStreamingTestUtil.java, createTestVector3
const StreamingAeadTestVector& CreateAes128GcmHkdfSha512StreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(16)
            .SetDerivedKeySizeInBytes(16)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
            .SetCiphertextSegmentSizeInBytes(64)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material =
        RestrictedData(HexDecodeOrDie("6eb56cdc726dfbe5d57f2fcdc6e9345b"),
                       InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    std::string plaintext = "";
    std::string associated_data = "";
    std::string ciphertext = HexDecodeOrDie(
        "18fec8139ccb406e0f140d7e2bcc41e1b899bc1b121574cc31d1c78ed2ca1cdf324665"
        "b8dce21095");

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

// From Java AesGcmHkdfStreamingTestUtil.java, createTestVector4
const StreamingAeadTestVector& CreateAes256GcmHkdfSha1StreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(32)
            .SetDerivedKeySizeInBytes(16)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha1)
            .SetCiphertextSegmentSizeInBytes(64)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material = RestrictedData(
        HexDecodeOrDie(
            "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
        InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    std::string plaintext = "";
    std::string associated_data = "";
    std::string ciphertext = HexDecodeOrDie(
        "180880e85a24207a7b72cefde26306ed09d7d76e58104b751d005a3ffd72dd6151f0d9"
        "c8ccf163f7");

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

// From Java AesGcmHkdfStreamingTestUtil.java, createTestVector5
const StreamingAeadTestVector&
CreateAes256GcmHkdfSha1Derived32StreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(32)
            .SetDerivedKeySizeInBytes(32)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha1)
            .SetCiphertextSegmentSizeInBytes(64)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material = RestrictedData(
        HexDecodeOrDie(
            "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
        InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    std::string plaintext = "";
    std::string associated_data = "";
    std::string ciphertext = HexDecodeOrDie(
        "28fae780c70a82d1256c8303a1261ac6a98cf557b4e173967a62f3c149517ba5b2431"
        "da93b3c6e90f508b34dc14bfda59bab05681c6ad3fa");

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

// From Java AesGcmHkdfStreamingTestUtil.java, createTestVector6
const StreamingAeadTestVector&
CreateAes256GcmHkdfSha1Segment128StreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(32)
            .SetDerivedKeySizeInBytes(32)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha1)
            .SetCiphertextSegmentSizeInBytes(128)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material = RestrictedData(
        HexDecodeOrDie(
            "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
        InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    std::string plaintext = "";
    std::string associated_data = "";
    std::string ciphertext = HexDecodeOrDie(
        "28fae780c70a82d1256c8303a1261ac6a98cf557b4e173967a62f3c149517ba5b2431"
        "da93b3c6e90f508b34dc14bfda59bab05681c6ad3fa");

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

// From Java AesGcmHkdfStreamingTestUtil.java, createTestVector7
const StreamingAeadTestVector&
CreateAes256GcmHkdfSha1Segment120LongPtStreamingTestVector() {
  static const absl::NoDestructor<StreamingAeadTestVector> test_vector([]() {
    absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
        AesGcmHkdfStreamingParameters::Builder()
            .SetKeySizeInBytes(32)
            .SetDerivedKeySizeInBytes(32)
            .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha1)
            .SetCiphertextSegmentSizeInBytes(120)
            .Build();
    ABSL_CHECK_OK(parameters);

    RestrictedData initial_key_material = RestrictedData(
        HexDecodeOrDie(
            "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b"),
        InsecureSecretKeyAccess::Get());
    absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
        *parameters, initial_key_material, GetPartialKeyAccess());
    ABSL_CHECK_OK(key);

    std::string plaintext =
        "BLOCK 1.BLOCK 2.BLOCK 3.BLOCK 4.BLOCK 5.BLOCK 6.BLOCK 7.BLOCK 8.";
    std::string associated_data = HexDecodeOrDie("00010203");
    std::string ciphertext = HexDecodeOrDie(
        "28782994617714a80fa085e15051a16854522330d6d0f26c049b2192f09cdd98b2eb90"
        "c753bfff277a29e54fa4afb15d648c28477eb07f012535c767f5fdce24ffffae318480"
        "c1d37357d6d3c511159318afa09ef38aa3f5456fd7817c5c02dd6e1a7fef174c8bd24"
        "e38b5982ac105497c0101ac5581fe5b");

    return StreamingAeadTestVector(
        std::make_shared<AesGcmHkdfStreamingKey>(*key), plaintext,
        associated_data, ciphertext);
  }());
  return *test_vector;
}

}  // namespace

// Returns static test vectors for AES-GCM-HKDF Streaming AEAD.
const std::vector<StreamingAeadTestVector>&
CreateAesGcmHkdfStreamingTestVectors() {
  static const absl::NoDestructor<std::vector<StreamingAeadTestVector>>
      test_vectors([]() {
        return std::vector<StreamingAeadTestVector>{
            CreateAes128GcmHkdfSha1StreamingTestVector(),
            CreateAes128GcmHkdfSha1EmptyPtStreamingTestVector(),
            CreateAes128GcmHkdfSha256StreamingTestVector(),
            CreateAes128GcmHkdfSha512StreamingTestVector(),
            CreateAes256GcmHkdfSha1StreamingTestVector(),
            CreateAes256GcmHkdfSha1Derived32StreamingTestVector(),
            CreateAes256GcmHkdfSha1Segment128StreamingTestVector(),
            CreateAes256GcmHkdfSha1Segment120LongPtStreamingTestVector()};
      }());
  return *test_vectors;
}

// Returns a static test vector for AES-GCM-HKDF Streaming AEAD for the given
// key size in bytes.
const StreamingAeadTestVector& GetAesGcmHkdfStreamingTestVector(
    int key_size_in_bytes) {
  if (key_size_in_bytes == 16) {
    return CreateAes128GcmHkdfSha1StreamingTestVector();
  }
  if (key_size_in_bytes == 32) {
    return CreateAes256GcmHkdfSha1StreamingTestVector();
  }
  ABSL_CHECK(false)
      << "No AES-GCM-HKDF streaming test vector found for key size: "
      << key_size_in_bytes;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
