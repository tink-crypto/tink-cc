// Copyright 2026 Google LLC
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

#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/bn.h"
#include "openssl/mldsa.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_3072_test.json.
constexpr std::string_view kHex3072BitRsaN =
    "00dc8f7880672f0cf9d63617a8a58bdd271a109badda0fa826f94b8a795526b6a49a80564c"
    "caba8a9491a935a53edeae1d9a7b5463d9e2ef3ee0ce7bff5d4b6c8147b5c073c2f220515d"
    "531d55a36687a6de3c34775c2f15191ac0a742d7342228c8d910fe6bbca439539c485debcb"
    "d0ee0e4bae317503b83cee8100ac7bb4587467cbc4373c4bda2eedf7c41631e50922b580f5"
    "bce81d24b208cabcd2d75fcfe99f75b493dffc5c9bd990f7fc3bf2efe392fecae36f3e4ef4"
    "456c1b5de99cc7451733a910b6834b61ec29274d986be3752c350b13a327dabc08dfcf6565"
    "499ad26e853446633eadb2970ca95bcf6bf05ffdbc2a804378d76985a71f06f90979f9fef7"
    "16c36aa625a45b5eedf50825a53e9d9435b23caab9e5c64d38fd3a767e185ad7727d6e15f9"
    "e9bab2f4184d6487695db9a2698c672b2e823410dbef1d93fe40c9d357ee9fc77f849de113"
    "63f583af8ccf5181ca1aeb944c422516cb401e950923e4bd881439fa1093c77582bfe1ac59"
    "93674700b6434339e0245315d86fcb";
constexpr std::string_view kHex3072BitRsaD =
    "0501205bd17b88d0d6626dd0fec898a0fd7f68f8dddcc314f74d167c40495b958a87e4ed63"
    "202e6ac68f4f4f4b88e3ec7a07d85757a7458468b766aad9a40f77337855408b28d140e75c"
    "2e6b3604ea8907bbd7f8e9578c2400ae645d28e2deef8bf718e29cf12fccb92fef9869f43a"
    "ee5bd6adc223848d169cd6c27c2766652766ff81993b3e015a553decee0ffdc1624f39f8d9"
    "6b6ed5d95047c1570b59fa2eb3d688dd5e14acc9407b8094f18b4694244eb1adcd655d873f"
    "57ff9af6e4fec470be236baf3b20c2040ab360d759c8b4e618bf8bd4e0ec6698f1b72c7160"
    "ed0521c82b5176b60fb63503d0ae23f6e2fb7a609305b0af62150b921ac53f4de899666cb0"
    "1db0c9d8b650753015c1b6e682e6bf38204e59f7409c3808c0e53f254935540a381a963c2c"
    "1a77c6f987f06a07a0572686ed22882dbc82e7823cec080a58d72b09d00cc1d245cf158ff4"
    "9cc40599d3af719dc301b4aa7f5b03629ae853e9daabe284db86d5c41d0401143df2b4593e"
    "f4e3747209c523f5a7f80f02d011";
constexpr std::string_view kHex3072BitRsaP =
    "fec6a10bfc49b58a2c850eafebdb997649a95575a0c17631b011cb20d7a320232a815b9af6"
    "040d7bf23d267e5e06304c33e04c85e6d481442f010a9758ba08364a70035ef99e9c98eeb4"
    "31505b2afb6779d1c91d0ea2fb0a65dc391e79ecda7d52fd7dd69923b25dfae448cace829e"
    "baca6b3c8a3cb64a81800614434895778c20d629b125b69f42945f66b644f3840bcfa6fce3"
    "61074256c50863ecca2ce756b4a9fb7e993d0f1fa48b2cc485b7eaa61405fbef150e7563c2"
    "150811767de0f9";
constexpr std::string_view kHex3072BitRsaQ =
    "dd9ec1cee6d8a971b166902c44a4f02ef37a62053b41288a1d873d399cbc9e7bd306ed9064"
    "87da2f49bc1c1809c0d4d88106d6879518ed925feb66aad5ff3c2b83466c554ed97b96abef"
    "55b3b02314f50d0385a0a1d8a46ae03e8fce91b412120f0a10dc681570fa564b6873bacd99"
    "7b616b2bd7733fb723ade23bc1089da32e509583436f1e3448b579fb21b240620d20458d08"
    "f0f995abacc0a398f0ab6a67c9f5bcf7e032fb1d668fe698d80327599ae3fdf3aaaab19baf"
    "17639443194be3";
constexpr std::string_view kHex3072BitRsaDp =
    "f1bfb40cd56573971acb5eb65b0cd2bf4502228f2ceca5a45c37661151cbfdb0a0a28233b6"
    "00fe727fd6ba71e9f1e15e4d53260960907fe01ce1d614ea220bacc8512541b786637d51f3"
    "355fd44222af7b0e2ed11d9454b4f7165234b2e8a62188dff3c9ef21ca1c16f70a83361507"
    "5ca2b9c28641398fd4f58fcf2650f752aa6a760cb584dd969cec80e1cb4dfdeb6bf1abb806"
    "61892bcf7dc28a5ea3309c8acf7f039e8af53f267d517a3737d2de1a9ca158fef171f8bda1"
    "e9a6f03b0912b1";
constexpr std::string_view kHex3072BitRsaDq =
    "3e3c2ae8d362dc9294e2dc71d2050f7ddfd9ea54d5c3028366af67be1a09cde7afe72e2772"
    "53c42dab632bf0842ca698f602d993d186e2904c676ab966c6fa3aadeec4d560032af5b0ea"
    "d10258e0412e5fad31855e6ddc1e3742da57840b3157e8e946bade6fc6fe45e57f3ba0a5c4"
    "0825df56bc761cda6d2693757c4bd318d414c527cb7414e351d7c49d8564ed379bc0084806"
    "cec50806e1c86728b7cd2b606212a43267bf694d6453dcc9e73f5b798a49a4331d263a2222"
    "154b5d834a4349";
constexpr std::string_view kHex3072BitRsaQinv =
    "18cc971e9186f86c144d140ceabbc9ae22c94e8d8575356fb6a4a033991ef210bafa39a4cd"
    "1abfa99b332fde9e56955af179459a7236a700b7fd1d88093906f6130ae7ca9742d9ed0d5c"
    "63e6a9e9b43df4d8b261c12d2c2f9148bc0669f165b8b881879c3ed58d4a6cd5a3f1193e9a"
    "bd2784609c01fb9094c7c822532ad7aec2a08aee9e263095ad0426455cb59258c7fd3731ca"
    "89dee31800d191ed7249721c25266650c46dcbfbae3070604d2e009914a2e269a01bafa5bd"
    "f8bba31c4f3b60";

// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_4096_test.json.
constexpr std::string_view kHex4096BitRsaN =
    "00f601be0dccd04aa40b12f3f191ae17c1f9c8c0b68e7a77e14be25c3c7907cb1d33a6ef41"
    "8ef41852f32c98392bc5c9aed91c1a1501c503eab89b3ee6f4f8eb2e0fcfc41bd03609cf6a"
    "8eb3aa6f0fbe23187b33db4d34b66d128a8aba0a2abf40bb9d13d8e2554569a57ab1d8c61b"
    "8cad2dc88599ae0da5346e15dace1bac7bf69737c22f083be9b46bb8b1eab5957b2da74027"
    "5e96c87195b96fe11452159dafcfd916cee5d749a77bc3905a5ebd387ae445e8fe70f16e9a"
    "086639779ceffbfd41557bd99aea6a371a6b4b160615a1a12bc6958d34bce0c85adcbd8392"
    "fa10ceca52209d56196ba3d273ce228f1f111192aa92de2a039798a17bcecb4dc6100e6f8a"
    "e8c2643f2ae768b2255f082c978e95ca551555f10608231cf8003bbf807969fff1e51914b9"
    "a8c9b8f4564645b9e5d705ffad29663f5dae3d76652b422e43f13e6c1491090805c2d1268a"
    "74a251177427e33a9a91175c3670b91746008bce1fd231e6e4f2ad70cb43aca5f07600a6d3"
    "1dd02915243dfdd943a02165da367a6b7e4dae1dd2e8b836903080795d2585076cc1c15dd9"
    "e8d2e5e047526569b1bfd395d957eb9fde325d342d14426e71efdc1887515e53cdea583492"
    "1f928629e748eed097ac4024e2bf255d70411f87373948cf8e8aa7effa2b0ab47d5166091e"
    "1aedec60568b155bd9c27bc55f3ece35f83d636dbcd5abf4853a051db94d5045";
constexpr std::string_view kHex4096BitRsaD =
    "065028224431ca35e87f82d97302c9384b4d341385ecd8510f4df94e51facf0dbfa0169413"
    "9e3f00e34859db09bd087e74b2e1c1229652e73df7e49c2fb2dd9cda7f5b49d81a32e9403e"
    "4b97b6eeebfdb6e89e7d8fbf27b95282fca9668e649c68297bf367bcdc21a86dfc22132a17"
    "7e4591024b5dd49ad091775271fc9d7cb6e8cd8a5858f93f4cf280bf0c1b69d675e6f760ab"
    "443fa8ee8ddf89a2a85d46a52c367c27db6d1ec6435e52eb86c7e0ab02b05543865423cc4f"
    "25346f55e1db6675e69832e43a04ccc78af3abd68477ed37698ab7f61facbdbcdb32552de5"
    "e89d8342aa9f445b8afac81bfc5bc05981ea20b340e948f710f7b3ee85f18b5c3c5832f233"
    "6706c5e9c9bd8e43d202e73a0f62776df4b715975eddd31aa643b14145057b4995556de614"
    "c57b33297bda0e05a8b8882a29563bf21686ce34c3960f905de73911987eb696e07eac0a63"
    "857e2894c3b4629477ecbf1fc76eafbb2ce4a0f00f8cdb6fbd6169e399151460522cf5b365"
    "d9bbb9587d07dac8c438982adea9ff243a86bbdf128eaa0d3a88871d8cdf081854258a651f"
    "f4226ee9749b4a6add090c159ccea06b9a10804e5fe15120cc63a5972eab0e43980dedaff3"
    "21fadeea3ca60c3ba1c2980bb597ea783b80ab6eba87feb5754fd1d65d7cad6f81cf52c1a6"
    "bfebf9a75e9a316cb364d8cf467d96370871df2ee66ee1c1694a0223958391";
constexpr std::string_view kHex4096BitRsaP =
    "fc21b855c5ad4ca2b6970516406f71c6e79efc4126e6598772db1e082de6b0dddaaa2a2951"
    "f04148e86e0bde28213b7f600f987308301eacea134062bb0c3ddf628da9abf93ef1ce3e75"
    "b0953a484dbd3554bd5c0649933dd77e527563e90f05a8013fddac958c329378e94303b304"
    "be5f9df1fe5b043a7fdd94700a3f0b1cbbd0516b7cd94c57ca96d9fd2a8ca973991218cba3"
    "3a1c23d810f7519d1f7702ab72affdb3f84a1b2a88116e4033bc4d0cfc7989c657e0fe94e9"
    "64476ae58bae6b7876f36c09d32b1a63f8c47c94a74c92eedf75fc27cffe0f8452363e4bc8"
    "f7653f3cb55eaf693cec70d13c875de935a8b20439ab7e93f76981c5957fc5bb44d9";
constexpr std::string_view kHex4096BitRsaQ =
    "f9c7f748a505d23ecef9a85f8097c8cf7d7028ef6c90e22a336511582d2cc3636e34ead372"
    "04dbd22f142a3fb1d5f857b0310c7a433f51ae14d4608b01b43aa8c7ae67835f7fbe0b9d97"
    "948b39e9ba2d3a1687edb8b56ee70ff0536dab4d0551f71ed0daee9e412449f5f099bcc15e"
    "4ef0554dc79f87fec5a0dea717c7054392bf444613937401bbef3c22fbf7e738c58779b981"
    "609a1f9c11dd6f0bbe9996e2773459e4cef247b02a9fc21296ac57a5b10561824310cfbdec"
    "c90e06598370e3698713fdbe2528ec4ef3dccaae701eedc3e54ad6e7af4e68e3b39bd2e97a"
    "c9119936c647a503511cb283df984cfd7c07f0f56aa8ae3166948ef3f41b0859934d";
constexpr std::string_view kHex4096BitRsaDp =
    "815486aab0a0896bf97f13e3eb1f7f5c49195b49cc3b6277412a3688798b18f46422df479c"
    "b941b3b54e25964a3d69b897bcc8355160e58b4af29f1745dd2cabb670f634b9c058e6b351"
    "4947f2c27de5ed424f73b1e1f1be4a188911a0333f3a6688658b3ee8e3265a512e4deacadc"
    "470ee304ebb5224123afb461984fe8524fe0b6b30d32a59f6ed2dc74a96bc7cbfd1bb44e58"
    "a7092235c5d6272e12a2c862cb8c8cf5d109aa4fb1c6472875a14460c1ed5207c4b22bc494"
    "c7947eb7ca63a8cafd31361d000ddf16a2d79f13dd9140d979149b488cbf44945a5b6aaf13"
    "221bf4491ebbb7fca27ca20e221f49c3c37b89fcf2dc0e2cb63f8f8a9b7a14225059";
constexpr std::string_view kHex4096BitRsaDq =
    "b61d84ff934a4e437b16ee1b4b9fdf4ae13370b5385bde7a5464a123c0343df575f9e128ef"
    "9df944230d39cc9cf5dc0edb28b7e740b69ef024c1bfee39fcd5340ffaea0010160c535dc0"
    "920e7cd81be533d00fa554a1fc4d3e02c461569f5e7ca787f1515edf45b196b759884de652"
    "c38d5934cf92524e807b4d3b590bc39bc417ee4885a761d28ddadce6c8fdb3b961d3e7fd48"
    "064df9340a967f8b79997438841f48579a476ddb55088c308f68f2b29d01c6597a5a7c8d06"
    "6284f63e37a68c3879c32aa3836675fd0eb2719883a91944561e9dd7e8aa6bb17157f08c48"
    "f8e6fae5c3e5a2bb6b5d580eec6c97ddcd9be0a49ef283a7031ad7aba8d438df4e95";
constexpr std::string_view kHex4096BitRsaQinv =
    "22fb8e5fcd9b767104e71244db53058c18061e1b0d1f63b73e2d59a95e2a10cd87426a33da"
    "13c287cdef8136e5e47e93fb9b30ad92628a7b543f48eb011a86356ab3cb480f27e391b018"
    "ca187d97af3d82e31861ecafa663db78aa89c3bd468e6aadefb3a43f78bc00b8014c95db54"
    "e9d21a017e8f21f671545edde9a965ea32dfff45cda37fca1aa5132f6c8eed222bd01fed5a"
    "6e7d639580c5955777a86544c2c4c939bdb8b4c486dda53072861a0334359bdb3758475e49"
    "d90d0539944e78cfcfd8fff55bb31a1cebc65b28f51e790701b2f7912188984f034e6e96e1"
    "c5251e33fe38fb221bce7a90a86857c5f56b6ca77307c45d5290b1f088ade082b349";

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

absl::Status NewRsaKeyPairF4(int modulus_size_in_bits,
                             internal::RsaPrivateKey* private_key,
                             internal::RsaPublicKey* public_key) {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  if (BN_set_u64(e.get(), RSA_F4) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Could not set RSA exponent.");
  }
  return internal::NewRsaKeyPair(modulus_size_in_bits, e.get(), private_key,
                                 public_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateEd25519PrivateKeyOrDie() {
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ABSL_CHECK_OK(key_pair);
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *parameters, (*key_pair)->public_key,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key,
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<Ed25519PrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateEcdsaPrivateKeyOrDie(
    subtle::EllipticCurveType subtle_curve_type,
    EcdsaParameters::CurveType ecdsa_curve_type,
    EcdsaParameters::HashType hash_type) {
  absl::StatusOr<internal::EcKey> key_pair =
      internal::NewEcKey(subtle_curve_type);
  ABSL_CHECK_OK(key_pair);
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(ecdsa_curve_type)
          .SetHashType(hash_type)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters,
      EcPoint(BigInteger(key_pair->pub_x), BigInteger(key_pair->pub_y)),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->priv, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<EcdsaPrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsaPss3072PrivateKeyOrDie(
    bool force_random) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(3072, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
        *parameters, BigInteger(rsa_public_key.n),
        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPssPrivateKey> private_key =
        RsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    ABSL_CHECK_OK(private_key);
    return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
  }
  BigInteger modulus(HexDecodeOrDie(kHex3072BitRsaN));
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(HexDecodeOrDie(kHex3072BitRsaP),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(HexDecodeOrDie(kHex3072BitRsaQ),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(HexDecodeOrDie(kHex3072BitRsaDp),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(HexDecodeOrDie(kHex3072BitRsaDq),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(HexDecodeOrDie(kHex3072BitRsaD),
                                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(HexDecodeOrDie(kHex3072BitRsaQinv),
                                            InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsaPss4096PrivateKeyOrDie(
    bool force_random) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
          .SetSaltLengthInBytes(48)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(4096, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
        *parameters, BigInteger(rsa_public_key.n),
        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPssPrivateKey> private_key =
        RsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
  }
  BigInteger modulus(HexDecodeOrDie(kHex4096BitRsaN));
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(HexDecodeOrDie(kHex4096BitRsaP),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(HexDecodeOrDie(kHex4096BitRsaQ),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(HexDecodeOrDie(kHex4096BitRsaDp),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(HexDecodeOrDie(kHex4096BitRsaDq),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(HexDecodeOrDie(kHex4096BitRsaD),
                                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(HexDecodeOrDie(kHex4096BitRsaQinv),
                                            InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsa3072Pkcs1PrivateKeyOrDie(
    bool force_random) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(3072, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
        RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(rsa_public_key.n),
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
        RsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedBigInteger(rsa_private_key.p,
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(rsa_private_key.q,
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedBigInteger(
                rsa_private_key.dp, InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedBigInteger(
                rsa_private_key.dq, InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedBigInteger(
                rsa_private_key.d, InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedBigInteger(
                rsa_private_key.crt, InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
  }
  BigInteger modulus(HexDecodeOrDie(kHex3072BitRsaN));
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(HexDecodeOrDie(kHex3072BitRsaP),
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(HexDecodeOrDie(kHex3072BitRsaQ),
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              HexDecodeOrDie(kHex3072BitRsaDp), InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              HexDecodeOrDie(kHex3072BitRsaDq), InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              HexDecodeOrDie(kHex3072BitRsaD), InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedBigInteger(HexDecodeOrDie(kHex3072BitRsaQinv),
                                   InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsa4096Pkcs1PrivateKeyOrDie(
    bool force_random) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(4096, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
        RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(rsa_public_key.n),
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
        RsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedBigInteger(rsa_private_key.p,
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(rsa_private_key.q,
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedBigInteger(
                rsa_private_key.dp, InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedBigInteger(
                rsa_private_key.dq, InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedBigInteger(
                rsa_private_key.d, InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedBigInteger(
                rsa_private_key.crt, InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
  }
  BigInteger modulus(HexDecodeOrDie(kHex4096BitRsaN));
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(HexDecodeOrDie(kHex4096BitRsaP),
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(HexDecodeOrDie(kHex4096BitRsaQ),
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              HexDecodeOrDie(kHex4096BitRsaDp), InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              HexDecodeOrDie(kHex4096BitRsaDq), InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              HexDecodeOrDie(kHex4096BitRsaD), InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedBigInteger(HexDecodeOrDie(kHex4096BitRsaQinv),
                                   InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
}

}  // namespace

MlDsaPrivateKey GenerateMlDsaPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::MlDsaInstance instance) {
  switch (instance) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65: {
      std::string public_key_bytes;
      public_key_bytes.resize(MLDSA65_PUBLIC_KEY_BYTES);
      internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
      auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();
      ABSL_CHECK_EQ(1, MLDSA65_generate_key(
                           reinterpret_cast<uint8_t*>(public_key_bytes.data()),
                           private_seed_bytes.data(), bssl_private_key.get()));
      absl::StatusOr<MlDsaParameters> parameters =
          MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                                  MlDsaParameters::Variant::kNoPrefix);
      ABSL_CHECK_OK(parameters);
      absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
          *parameters, public_key_bytes, /*id_requirement=*/absl::nullopt,
          GetPartialKeyAccess());
      ABSL_CHECK_OK(public_key);
      absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
          *public_key,
          RestrictedData(
              util::internal::AsSecretData(std::move(private_seed_bytes)),
              InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
      ABSL_CHECK_OK(private_key);
      return *private_key;
    }
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87: {
      std::string public_key_bytes;
      public_key_bytes.resize(MLDSA87_PUBLIC_KEY_BYTES);
      internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
      auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA87_private_key>();
      ABSL_CHECK_EQ(1, MLDSA87_generate_key(
                           reinterpret_cast<uint8_t*>(public_key_bytes.data()),
                           private_seed_bytes.data(), bssl_private_key.get()));
      absl::StatusOr<MlDsaParameters> parameters =
          MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                                  MlDsaParameters::Variant::kNoPrefix);
      ABSL_CHECK_OK(parameters);
      absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
          *parameters, public_key_bytes, /*id_requirement=*/absl::nullopt,
          GetPartialKeyAccess());
      ABSL_CHECK_OK(public_key);
      absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
          *public_key,
          RestrictedData(
              util::internal::AsSecretData(std::move(private_seed_bytes)),
              InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
      ABSL_CHECK_OK(private_key);
      return *private_key;
    }
    default:
      ABSL_LOG(FATAL) << "Unsupported ML-DSA instance";
  }
}

std::unique_ptr<SignaturePrivateKey> GenerateClassicalPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm, bool force_random) {
  switch (algorithm) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519:
      return GenerateEd25519PrivateKeyOrDie();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P256,
                                          EcdsaParameters::CurveType::kNistP256,
                                          EcdsaParameters::HashType::kSha256);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P384,
                                          EcdsaParameters::CurveType::kNistP384,
                                          EcdsaParameters::HashType::kSha384);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P521,
                                          EcdsaParameters::CurveType::kNistP521,
                                          EcdsaParameters::HashType::kSha512);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
      return GenerateRsaPss3072PrivateKeyOrDie(force_random);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss:
      return GenerateRsaPss4096PrivateKeyOrDie(force_random);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
      return GenerateRsa3072Pkcs1PrivateKeyOrDie(force_random);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1:
      return GenerateRsa4096Pkcs1PrivateKeyOrDie(force_random);
    default:
      ABSL_LOG(FATAL) << "Unsupported classical algorithm";
  }
}

CompositeMlDsaPrivateKey GenerateCompositeMlDsaPrivateKeyForTestOrDie(
    const CompositeMlDsaParameters& parameters, bool force_random,
    absl::optional<int> id_requirement) {
  MlDsaPrivateKey ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(parameters.GetMlDsaInstance());
  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          parameters.GetClassicalAlgorithm(), force_random);
  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(parameters, ml_dsa_private_key,
                                       std::move(classical_private_key),
                                       id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return *private_key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
