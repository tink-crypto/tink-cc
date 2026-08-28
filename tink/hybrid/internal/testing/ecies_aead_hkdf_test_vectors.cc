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

#include "tink/hybrid/internal/testing/ecies_aead_hkdf_test_vectors.h"

#include <memory>
#include <optional>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/hybrid/hybrid_private_key.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;

HybridTestVector CreateTestVector0() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "04207f1c9bd3bce6864bdbb611bdb9852dea7e12dbe5894c642bd5cc8cde79de9e8a"
          "e3199875eba161d413ce3a29cfa0b27c6717d7d4cfbace5706ae4bbf8f7d1eb76965"
          "7992f5e7f5450091cc61c7b3a7b811fe5578e82e5123cb38855c"));
}

/* Compressed point */
HybridTestVector CreateTestVector1() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kCompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "02f1885dcb9240136f3305a18ac3857dd5de948cb0c4c78dbb087d37815800936340"
          "e2c351380bb615b26fd7d78c9c864f4a0e31863e864140f1f7e1205b"));
}

HybridTestVector CreateTestVector2() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kCompressed)
          .SetDemId(EciesParameters::DemId::kAes256GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "029f1ad546b1b60a0cff3cc356977ab608f5c4c17b693d2778d1e3354ec43500ea65"
          "bb5cce0fdc55e1fd0b9b07ee1ac642f7dcb5abd94b6b42691cd8e206"));
}

// kAes128CtrHmacSha256Raw
HybridTestVector CreateTestVector3() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kCompressed)
          .SetDemId(EciesParameters::DemId::kAes128CtrHmacSha256Raw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "029f86d6f944e163d1b787a261caa65e47f7c59368170b5e8da0e7a14a4ce1bfab8e"
          "6c2e283562a2bc52fb5145ec0a4737ecfe52f725e1c70df17a02dfdda7e6188b"));
}

// kAes256CtrHmacSha256Raw
HybridTestVector CreateTestVector4() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256CtrHmacSha256Raw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "043e59fd951974bfe1b2c7a33d4bf89aa3b461e3aedcf44928eda6744f9880fb893b"
          "66899217736dd6db73"
          "763ba540469ff0d240a95bbd05b7716932082983883db5cba086eebbcc6fe0757644"
          "fb0c612fff2c"
          "a86dc9077e7089ddf107492251413d99a679b86d4d07c0a70d1a6329f6da6f"));
}

// AES256_SIV_RAW
HybridTestVector CreateTestVector5() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("0425975e19677c2110915beb293e3833cd40c9beeff376b83b8cf01aa"
                     "8282a1416b3b8deffd34b7c33044848a3ba8a722d60946757ae29ee31"
                     "7ceefae84890325ca1a246d24696a3f5acd351690763212961"));
}

// TINK
HybridTestVector CreateTestVector6() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ 0x88668866,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "0188668866"
          "04207f1c9bd3bce6864bdbb611bdb9852dea7e12dbe5894c642bd5cc8cde79de9e8a"
          "e3199875eba161d413ce3a29cfa0b27c6717d7d4cfbace5706ae4bbf8f7d1eb76965"
          "7992f5e7f5450091cc61c7b3a7b811fe5578e82e5123cb38855c"));
}

// Crunchy
HybridTestVector CreateTestVector7() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kCrunchy)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ 0x88668866,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "0088668866"
          "04207f1c9bd3bce6864bdbb611bdb9852dea7e12dbe5894c642bd5cc8cde79de9e8a"
          "e3199875eba161d413ce3a29cfa0b27c6717d7d4cfbace5706ae4bbf8f7d1eb76965"
          "7992f5e7f5450091cc61c7b3a7b811fe5578e82e5123cb38855c"));
}

// SHA384
HybridTestVector CreateTestVector8() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha384)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "0484b996da02ef1e0169f220cfec0c1f0bb259d245b0131e2826619ffc19886d9208"
          "76e7444976ca8ec6fa3bd0301680e7d91ecc09196b2b2079db8f00f1775ca2d2f633"
          "41cd6eadffd4332af8f4c2c91acb8872a7f22342a8e6dff119d0"));
}

// SHA512
HybridTestVector CreateTestVector9() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha512)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "044668af1e50e4a24bb30fb763788f2c7151c33aa30542843b8699519ff3b9cf78a8"
          "421466249330ee955220591444f0eb2f910cf530f9cea17e277c393c0796de08184b"
          "6d90cc229efc70f6748c4ff26abc572b08ddffabab04a307e194"));
}

// Empty Message
HybridTestVector CreateTestVector10() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie(""),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "0471855fecd89b62ae67a4d62be5fe31f5368e271b3b1775362161eab5701ab6fb21"
          "048c406a31ffa2dde42bd68b88a20daf9cf3873a2fde4e745d404dd1dcab21ee0e05"
          "a32e919c1bcbecd7fb18c6b8fe7f91ea9c7e0abba5855dd0a2"));
}

// Empty Context info
HybridTestVector CreateTestVector11() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie(""),
      HexDecodeOrDie(
          "045c1ef99f7c3a2c9ea0022bcd8c87e9b90d3dec4687a3e94a006c01136d7b50c0db"
          "443b67ed69d432bc949b7ba76859343577fe702437ebb105e18abdaf6d3f88fb1b12"
          "ed80d0182e1f6ac5da5cb08cec330c861c897e34603a6b83de71"));
}

// NIST_P384
HybridTestVector CreateTestVector12() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP384)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P384Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P384SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "04ff21e8d24773b1deaeb120aba62c2f19d0eb6112c3296d25be9302e0f31788db20"
          "2e87ef1341f9fa05a2ac9b21ced6b0ef19407618ae6e2d86764f6a5ea582aec7cd69"
          "07bebb9261b55eb4ba588dede42ec613992bd143c703b6af20cd927a501536191ec5"
          "2e13326252968c3fcb2af021f25fcfd7d5993c180dfd916d"));
}

// NIST_P521
HybridTestVector CreateTestVector13() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP521)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P521Point(),
                                         /*id_requirement*/ std::nullopt,
                                         GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P521SecretValue(),
                                          GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "0401a1051bd9ceedf066f31edea3465cf5170c72102c325b85e30ae2f80155ca7af0"
          "abb8c8367b63dea022ebdf4d87f923bd02f9dc0d39b6e2facbef079b4737c392ad00"
          "32b7beb0ccb56e160682b722c54b4bd7f288d66b3f25f856304c35cbf2368610d8fb"
          "e3f83890c007c6ca5d2f5f32d1ef4445372751b1bc0e7104879b8c2e1e60f1c8862c"
          "566d2b0718aed41bb763cb29e3e2ca1df63e46f859fa98478ea9"));
}

// X25519
// Test vector created with the implementation here.
HybridTestVector CreateTestVector14() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(
          *params,
          HexDecodeOrDie("90c5b6d9b337cc6c9c2e8ac44f1c0e7c41f23bdf7a04df3b9c808"
                         "1c0c278352a"),
          /*id_requirement*/ std::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  RestrictedData private_key_material = RestrictedData(
      HexDecodeOrDie(
          "97d2e385c9968fbe2dc0b85a182199ed7e0b5b4bb6060f76583c0893241f698d"),
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_material,
                                            GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "fa797599d9031eece63baf6a8da112cc73dd8b977c504ef28c548070292e40094640"
          "6667ba0360d2fe35b5d2adae56d5cccd93c407f8a37926fe0da688"));
}

}  // namespace

const std::vector<HybridTestVector>& CreateEciesTestVectors() {
  static const absl::NoDestructor<std::vector<HybridTestVector>> vectors([]() {
    return std::vector<HybridTestVector>{
        CreateTestVector0(),  CreateTestVector1(),  CreateTestVector2(),
        CreateTestVector3(),  CreateTestVector4(),  CreateTestVector5(),
        CreateTestVector6(),  CreateTestVector7(),  CreateTestVector8(),
        CreateTestVector9(),  CreateTestVector10(), CreateTestVector11(),
        CreateTestVector12(), CreateTestVector13(), CreateTestVector14()};
  }());
  return *vectors;
}

// Returns a valid static ECIES private key for the given curve type from RFC
// 6979.
using EciesPrivateKeyMap =
    absl::flat_hash_map<subtle::EllipticCurveType,
                        std::shared_ptr<HybridPrivateKey>>;

const EciesPrivateKeyMap& CreateEciesPrivateKeyMap() {
  static const absl::NoDestructor<EciesPrivateKeyMap> keys(EciesPrivateKeyMap{
      {subtle::EllipticCurveType::NIST_P256,
       CreateTestVector0().hybrid_private_key},
      {subtle::EllipticCurveType::NIST_P384,
       CreateTestVector12().hybrid_private_key},
      {subtle::EllipticCurveType::NIST_P521,
       CreateTestVector13().hybrid_private_key},
      {subtle::EllipticCurveType::CURVE25519,
       CreateTestVector14().hybrid_private_key},
  });
  return *keys;
}
const EciesPrivateKey* GetEciesPrivateKey(
    subtle::EllipticCurveType curve_type) {
  const EciesPrivateKeyMap& keys = CreateEciesPrivateKeyMap();
  auto it = keys.find(curve_type);
  ABSL_CHECK(it != keys.end()) << "No vector found for curve: " << curve_type;
  return static_cast<const EciesPrivateKey*>(it->second.get());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
