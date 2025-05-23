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
#include <vector>
#include "absl/log/check.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;


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

HybridTestVector CreateTestVector0() {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ 0x88668866,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ 0x88668866,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P256Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P256SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P384Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P384SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, P521Point(),
                                         /*id_requirement*/ absl::nullopt,
                                         GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, P521SecretValue(),
                                          GetPartialKeyAccess());
  CHECK_OK(private_key);
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
  CHECK_OK(params);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(
          *params,
          HexDecodeOrDie("90c5b6d9b337cc6c9c2e8ac44f1c0e7c41f23bdf7a04df3b9c808"
                         "1c0c278352a"),
          /*id_requirement*/ absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key);
  RestrictedData private_key_material = RestrictedData(
      HexDecodeOrDie(
          "97d2e385c9968fbe2dc0b85a182199ed7e0b5b4bb6060f76583c0893241f698d"),
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_material,
                                            GetPartialKeyAccess());
  CHECK_OK(private_key);
  return HybridTestVector(
      std::make_shared<EciesPrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "fa797599d9031eece63baf6a8da112cc73dd8b977c504ef28c548070292e40094640"
          "6667ba0360d2fe35b5d2adae56d5cccd93c407f8a37926fe0da688"));
}

}  // namespace

std::vector<HybridTestVector> CreateEciesTestVectors() {
  return {CreateTestVector0(),  CreateTestVector1(),  CreateTestVector2(),
          CreateTestVector3(),  CreateTestVector4(),  CreateTestVector5(),
          CreateTestVector6(),  CreateTestVector7(),  CreateTestVector8(),
          CreateTestVector9(),  CreateTestVector10(), CreateTestVector11(),
          CreateTestVector12(), CreateTestVector13(), CreateTestVector14()};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

