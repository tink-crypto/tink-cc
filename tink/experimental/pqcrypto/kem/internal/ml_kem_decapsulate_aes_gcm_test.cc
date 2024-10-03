// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_decapsulate_aes_gcm.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/mlkem.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/config/global_registry.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_aes_gcm.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/kem/kem_decapsulate.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

AesGcmParameters CreateAes256GcmParameters() {
  CHECK_OK(AeadConfig::Register());

  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

TEST(MlKemDecapsulateAes256GcmTest, InvalidAesKeySize) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<AesGcmParameters> aes_128_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(aes_128_parameters, IsOk());

  EXPECT_THAT(
      NewMlKemDecapsulateAes256Gcm(*private_key, *aes_128_parameters).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("AES-GCM parameters are not compatible with ML-KEM")));
}

TEST(MlKemEncapsulateAes256GcmTest, InvalidIdRequirementForDerivedKey) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<AesGcmParameters> aes_tink_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(aes_tink_parameters, IsOk());

  EXPECT_THAT(
      NewMlKemDecapsulateAes256Gcm(*private_key, *aes_tink_parameters).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Keys derived from an ML-KEM shared secret "
                         "must not have an ID requirement")));
}

TEST(MlKemDecapsulateAes256GcmTest, EncapsulateDecapsulateAeadWorks) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  // Exchange a key pair.
  util::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   CreateAes256GcmParameters());
  ASSERT_THAT(encapsulate, IsOk());

  util::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters());
  ASSERT_THAT(decapsulate, IsOk());

  // Exchange an encapsulation and derive AEAD primitives.
  util::StatusOr<KemEncapsulation> encapsulation =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulation, IsOk());

  util::StatusOr<KeysetHandle> decapsulation =
      (*decapsulate)->Decapsulate(encapsulation->ciphertext);
  ASSERT_THAT(decapsulation, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> encaps_aead =
      encapsulation->keyset_handle.GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(encaps_aead, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> decaps_aead =
      decapsulation->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(decaps_aead, IsOk());

  // Check that the AEAD primitives are compatible.
  util::StatusOr<std::string> ciphertext =
      (*encaps_aead)->Encrypt("plaintext", "associated data");
  ASSERT_THAT(ciphertext, IsOk());

  util::StatusOr<std::string> decrypted =
      (*decaps_aead)->Decrypt(*ciphertext, "associated data");
  EXPECT_THAT(decrypted, IsOkAndHolds("plaintext"));

  EXPECT_THAT(
      (*decaps_aead)->Decrypt(*ciphertext, "bad associated data").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  // The AEAD primitives are also compatible for messages sent in the other
  // direction.
  util::StatusOr<std::string> ciphertext2 =
      (*decaps_aead)->Encrypt("plaintext 2", "associated data 2");
  ASSERT_THAT(ciphertext2, IsOk());

  util::StatusOr<std::string> decrypted2 =
      (*encaps_aead)->Decrypt(*ciphertext2, "associated data 2");
  EXPECT_THAT(decrypted2, IsOkAndHolds("plaintext 2"));

  EXPECT_THAT(
      (*encaps_aead)->Decrypt(*ciphertext2, "bad associated data").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlKemDecapsulateAes256GcmTest,
     WrongCiphertextDecapsulateAeadIsIncompatible) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  // Exchange a key pair.
  util::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   CreateAes256GcmParameters());
  ASSERT_THAT(encapsulate, IsOk());

  util::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters());
  ASSERT_THAT(decapsulate, IsOk());

  // Exchange an encapsulation and derive AEAD primitives.
  util::StatusOr<KemEncapsulation> encapsulation =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulation, IsOk());

  util::StatusOr<KeysetHandle> decapsulation =
      (*decapsulate)
          ->Decapsulate(
              absl::StrCat(private_key->GetOutputPrefix(),
                           std::string(MLKEM768_CIPHERTEXT_BYTES, 'A')));
  ASSERT_THAT(decapsulation, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> encaps_aead =
      encapsulation->keyset_handle.GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(encaps_aead, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> decaps_aead =
      decapsulation->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(decaps_aead, IsOk());

  // Check that the AEAD primitives are incompatible, in either direction.
  util::StatusOr<std::string> ciphertext =
      (*encaps_aead)->Encrypt("plaintext", "associated data");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_THAT((*decaps_aead)->Decrypt(*ciphertext, "associated data").status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  util::StatusOr<std::string> ciphertext2 =
      (*decaps_aead)->Encrypt("plaintext 2", "associated data 2");
  ASSERT_THAT(ciphertext2, IsOk());

  EXPECT_THAT(
      (*encaps_aead)->Decrypt(*ciphertext2, "associated data 2").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlKemDecapsulateAes256GcmTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters())
          .status(),
      StatusIs(absl::StatusCode::kInternal));
}

// Test vector based on the FIPS 203 standard.
TEST(MlKemRawDecapsulateBoringSslTest, TestVectorEncapsulateDecapsulate) {
  constexpr absl::string_view kHexPublicKey =
      "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913"
      "a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35f"
      "baeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e"
      "535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a517"
      "16aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb74"
      "8ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063"
      "364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b0"
      "2a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a3"
      "03402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253"
      "c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391"
      "f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a"
      "612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9e"
      "a29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151"
      "a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95ac"
      "b732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90a"
      "f65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b"
      "07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c711"
      "3bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720b"
      "e1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c7"
      "68c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c"
      "2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c2882"
      "8beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112b"
      "e10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce"
      "87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baf"
      "f716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b"
      "2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd"
      "11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1"
      "884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c38"
      "9137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd"
      "6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e"
      "663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82"
      "888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736"
      "162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028";
  constexpr absl::string_view kHexPrivateSeed =
      "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D8626ed79"
      "d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f";
  constexpr absl::string_view kHexKemCiphertextWithTinkPrefix =
      "0141424344c8391085b8d3ea9794212541b2914f08964d33521d3f67ad66096ebfb1f706"
      "424b49558f755b5625bae236f2e0079601c766f7d960808f7e2bb0c7a5e066ed346de628"
      "f8c57eebabbb0c22d911548463693ef3ce52a53f7ff415f00e657ae1c5a48fa5ec6e4be5"
      "cf462daffc84d2f6d5ff55dc9bbe8bb0d725ec64fd4cd4bd8dba0a844e8b5ce4b6a28934"
      "d7f7a050991fe185b506b451dabfad52d52cb2114ca7d9a5cf986c8fdc1bc10ec0c1869e"
      "50c03c55a76192a1049aca636ba9020bdaa8d0f58c763b0b89845ca06d4c4ddc21433e16"
      "b9c62e44871fdbc05ba218af871fdd7dcfa464e60faa5265264ce1391bd9a8c5faa7626d"
      "5f159b9805b975710a3503a0b858a11c6a647cc0e19ac88b1be9056c95b4d2087d0951d1"
      "d2f4992491117e6347794ba54571ec49bba71af3413d38a30bf5872248d1f6d07c86baf7"
      "82e73d2637f043d341a00921857d8b21ddf3e1d6310036ed27af49e5de1b900fe4de7980"
      "8ff29f9570859612b15adc01fbb265b305b1e3a12ae419da5b74261fa284c101da3d8dca"
      "8b2e4521aca571ef44a058e844ff32b16d5aaea05f7f3af8e2ab16222e347662eddfb891"
      "d0ecc2a55c5638f9dde92d9a3d544a5f901ac501acd1ea6a010201fcb10ad702c425a94b"
      "df5890d500a2a147eee1d1fcba8c3abe7c2dfe70f346f033d816a0b2791b4f0b2d956d9e"
      "e5971715399a5688302495e2e07c1c8c01527184bcd0c208bc159f2e13318c0bb3dd24a6"
      "a7fc849f83385ed4dba07fe1d7bd5640cc9ed5ccfdd68763cb0d0edf61b292177fc1d2d3"
      "c11dd0495056bcb12558aebcfddef9feb4aebc57afd9023c65cfe65a24e33f1b00111e92"
      "e63e011eaf0b212cf95743cd07f5189ece1f205b7f6fcb2e6b1961b5404cebe47c8cd13b"
      "8599d5b49e6d87eeda36e9b8fc4c00635896aa2b75896e336d1b612ee13db811e1f07e61"
      "748d920f4865f3f11741399dc6162c91ca168a02329dff821d58198712dd558abb099b3a"
      "0baf9da1b730b2aa73bcf58d74f357b06f7211c804b6c8af16ff3509fad1d35b14bfdced"
      "7db8a6a25c48e5956480724daa057cd660b67ee3e472574182679d485838a6476eac0214"
      "1075c812af7967ba7c9185cc2abd2a4545b80f3d3104d58d654a57792dcfabbe9c0715e8"
      "de2ef81ef404c8168fd7a43efab3d448e686a088efd26a26159948926723d7eccc39e3c1"
      "b719cf8becb7be7e964f22cd8cb1b7e25e800ea97d60a64cc0bbd9cb407a3ab9f88f5e29"
      "169eeafd4e0322fde6590ae093ce8feeae98b622caa7556ff426c9e7a404ce69355830a7"
      "a67767a76c7d9a97b84bfcf50a02f75c235d2f9c671138049ffc7c8055926c03eb3fb87f"
      "9695185a42eca9a41655873d30a6b3bf428b246223484a8ff61ee3eeafff10e99c2c13a7"
      "6284d063e56ab711a35a85b5383df81da23490f66e8ea3fcba067f5530c6541c2b8f7471"
      "7c35023e7b9b3956c3ee2ff84ba03ccf4b4b5321b9240895481bc6d63c1693c1847852f8"
      "e97f50a133532ac3ee1e52d464";
  constexpr absl::string_view kHexAeadCiphertextWithoutPrefix =
      "1d0c971b321979b619c96470233163891b16304f76cee5355af738fe832bdad568f39634"
      "9bccb2";
  constexpr absl::string_view kPlaintext = "Hello world";
  constexpr absl::string_view kAssociatedData = "associated data";

  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  std::string public_key_bytes = test::HexDecodeOrDie(kHexPublicKey);
  util::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      *key_parameters, public_key_bytes, 0x41424344, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string private_seed_bytes = test::HexDecodeOrDie(kHexPrivateSeed);
  util::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Create a KEM pair.
  util::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters());
  ASSERT_THAT(decapsulate, IsOk());

  std::string ciphertext_bytes =
      test::HexDecodeOrDie(kHexKemCiphertextWithTinkPrefix);
  util::StatusOr<KeysetHandle> keyset_handle =
      (*decapsulate)->Decapsulate(ciphertext_bytes);
  ASSERT_THAT(keyset_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> decaps_aead =
      keyset_handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(decaps_aead, IsOk());

  std::string aead_ciphertext_bytes =
      test::HexDecodeOrDie(kHexAeadCiphertextWithoutPrefix);
  EXPECT_THAT((*decaps_aead)->Decrypt(aead_ciphertext_bytes, kAssociatedData),
              IsOkAndHolds(kPlaintext));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
