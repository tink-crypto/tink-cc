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

#include <memory>
#include <string>
#include <vector>

#include "absl/log/absl_check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/streamingaead/internal/testing/aes_ctr_hmac_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

// From the cross language tests, test_manually_created_test_vector
StreamingAeadTestVector CreateTestVector0() {
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

  return StreamingAeadTestVector(std::make_shared<AesGcmHkdfStreamingKey>(*key),
                                 plaintext, associated_data, ciphertext);
}

}  // namespace

std::vector<StreamingAeadTestVector> CreateAesGcmHkdfStreamingTestVectors() {
  return {CreateTestVector0()};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
