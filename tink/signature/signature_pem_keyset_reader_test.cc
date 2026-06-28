// Copyright 2018 Google LLC
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
#include "tink/signature/signature_pem_keyset_reader.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/ec_point.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_util.h"
#include "tink/key.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/partial_key_access.h"
#include "tink/proto_keyset_format.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/config_v0.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/subtle/pem_parser_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/ml_dsa.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::test::EqualsKey;
using EcdsaPrivateKeyProto = ::google::crypto::tink::EcdsaPrivateKey;
using EcdsaPublicKeyProto = ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using Ed25519PublicKeyProto = ::google::crypto::tink::Ed25519PublicKey;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using RsaSsaPssPrivateKeyProto = ::google::crypto::tink::RsaSsaPssPrivateKey;
using RsaSsaPssPublicKeyProto = ::google::crypto::tink::RsaSsaPssPublicKey;
using MlDsaPublicKeyProto = ::google::crypto::tink::MlDsaPublicKey;
using ::google::crypto::tink::MlDsaInstance;
using ::testing::Eq;
using ::testing::NotNull;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestWithParam;

// Generated with:
// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem`
constexpr absl::string_view kEcdsaP256PrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgx5oKGNLy+C0ibH2L\n"
    "H35Jr91rDpPtYETna5as8QqOTuyhRANCAATpqcaVqa2D905YgGTK0qvlIUJdvrqz\n"
    "v/UKB4nvbqKXC7qkmhvvEdTR4HJQr0U9d7kvF4IPyHqZDlwGTeCVKefX\n"
    "-----END PRIVATE KEY-----\n";

// Extracted from:
// `openssl asn1parse -in private-key.pem -strparse 29`
constexpr absl::string_view kEcdsaP256PrivateKeyD =
    "c79a0a18d2f2f82d226c7d8b1f7e49afdd6b0e93ed6044e76b96acf10a8e4eec";

// Generated with:
// `openssl pkey -pubout -in private-key.pem -out public-key.pem`
constexpr absl::string_view kEcdsaP256PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6anGlamtg/dOWIBkytKr5SFCXb66\n"
    "s7/1CgeJ726ilwu6pJob7xHU0eByUK9FPXe5LxeCD8h6mQ5cBk3glSnn1w==\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// `openssl asn1parse -in public-key.pem -dump`
//
// The X and Y values are embedded within the dumped 66 byte hex-encoded BIT
// STRING value. Discard the first two bytes, X is the next 32 bytes, Y is the
// remaining 32 bytes.
constexpr absl::string_view kEcdsaP256PublicKeyX =
    "e9a9c695a9ad83f74e588064cad2abe521425dbebab3bff50a0789ef6ea2970b";

constexpr absl::string_view kEcdsaP256PublicKeyY =
    "baa49a1bef11d4d1e07250af453d77b92f17820fc87a990e5c064de09529e7d7";

// Generated with:
// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out key.pem`
constexpr absl::string_view kEcdsaP384PrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAJgNcGVFAYtVGMTm+t\n"
    "M8qx1hhYQbtMVADtc4V2t5QxJcsEbXRwVigUbZAHM4o/Uw6hZANiAASXyFvUJHrY\n"
    "APdllv8nQJETEY/IB8Ps2Bp7xrmTBybU0f0lgeyud7rcT05+BZBgPFxlSUwFQNTy\n"
    "RsbMj+fYOa0wlM6vZnD3UtHesw8uoXhDrenPcyNHOm6eyjwmWIIlM8o=\n"
    "-----END PRIVATE KEY-----\n";

// Extracted from:
// `openssl asn1parse -in private-key.pem -strparse 24`
constexpr absl::string_view kEcdsaP384PrivateKeyD =
    "0980d706545018b5518c4e6fad33cab1d6185841bb4c5400ed738576b7943125cb046d7470"
    "5628146d9007338a3f530e";

// Generated with:
// `openssl pkey -pubout -in private-key.pem -out public-key.pem`
constexpr absl::string_view kEcdsaP384PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEl8hb1CR62AD3ZZb/J0CRExGPyAfD7Nga\n"
    "e8a5kwcm1NH9JYHsrne63E9OfgWQYDxcZUlMBUDU8kbGzI/n2DmtMJTOr2Zw91LR\n"
    "3rMPLqF4Q63pz3MjRzpunso8JliCJTPK\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// `openssl asn1parse -in public-key.pem -dump`
//
// The X and Y values are embedded within the dumped 98 byte hex-encoded BIT
// STRING value. Discard the first two bytes, X is the next 48 bytes, Y is the
// remaining 48 bytes.
constexpr absl::string_view kEcdsaP384PublicKeyX =
    "97c85bd4247ad800f76596ff27409113118fc807c3ecd81a7bc6b9930726d4d1fd2581ecae"
    "77badc4f4e7e0590603c5c";

constexpr absl::string_view kEcdsaP384PublicKeyY =
    "65494c0540d4f246c6cc8fe7d839ad3094ceaf6670f752d1deb30f2ea17843ade9cf732347"
    "3a6e9eca3c2658822533ca";

// Generated with:
// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out key.pem`
constexpr absl::string_view kEcdsaP521PrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBgnVaqLhZZ3FPwdzG\n"
    "y6S3+HQR36UzfkF7xwAmbi8ss+BWwGq4jVylttXBqfLSRshz4rT/DROxHzvrFtj9\n"
    "FdOke/qhgYkDgYYABAANAbxkYZdju2J90n1UfhCuMEtJ/Y3jLC+lr30UHTZOtvqm\n"
    "1l53XtvZ493LlyjnUhPoy0szXy3Lc295NGovPcrYqAAap9ABfAikB+cnM+swOxPC\n"
    "WYvJowXeeAhFnPH9cqzsDAAxVh5AW3Jvn39zBPRZlt2DNWpX3fB9v1GjSy6wqhqh\n"
    "zw==\n"
    "-----END PRIVATE KEY-----\n";

// Extracted from:
// `openssl asn1parse -in private-key.pem -strparse 24`
constexpr absl::string_view kEcdsaP521PrivateKeyD =
    "0182755aa8b85967714fc1dcc6cba4b7f87411dfa5337e417bc700266e2f2cb3e056c06ab8"
    "8d5ca5b6d5c1a9f2d246c873e2b4ff0d13b11f3beb16d8fd15d3a47bfa";

// Generated with:
// `openssl pkey -pubout -in private-key.pem -out public-key.pem`
constexpr absl::string_view kEcdsaP521PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQADQG8ZGGXY7tifdJ9VH4QrjBLSf2N\n"
    "4ywvpa99FB02Trb6ptZed17b2ePdy5co51IT6MtLM18ty3NveTRqLz3K2KgAGqfQ\n"
    "AXwIpAfnJzPrMDsTwlmLyaMF3ngIRZzx/XKs7AwAMVYeQFtyb59/cwT0WZbdgzVq\n"
    "V93wfb9Ro0susKoaoc8=\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// `openssl asn1parse -in public-key.pem -dump`
//
// The X and Y values are embedded within the dumped 134 byte hex-encoded BIT
// STRING value. Discard the first two bytes, X is the next 66 bytes, Y is the
// remaining 66 bytes.
constexpr absl::string_view kEcdsaP521PublicKeyX =
    "000d01bc64619763bb627dd27d547e10ae304b49fd8de32c2fa5af7d141d364eb6faa6d65e"
    "775edbd9e3ddcb9728e75213e8cb4b335f2dcb736f79346a2f3dcad8a8";

constexpr absl::string_view kEcdsaP521PublicKeyY =
    "001aa7d0017c08a407e72733eb303b13c2598bc9a305de7808459cf1fd72acec0c0031561e"
    "405b726f9f7f7304f45996dd83356a57ddf07dbf51a34b2eb0aa1aa1cf";

// Generated with:
// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 | openssl
// pkey -pubout`
constexpr absl::string_view kSecp256k1PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuDj/ROW8F3vyEYnQdmCC/J2EMiaIf8l2\n"
    "A3EQC37iCm/wyddb+6ezGmvKGXRJbutW3jVwcZVdg8Sxutqgshgy6Q==\n"
    "-----END PUBLIC KEY-----";

// Generated with:
// `openssl genpkey -algorithm ed25519 | openssl pkey -pubout`
constexpr absl::string_view kEd25519PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAfU0Of2FTpptiQrUiq77mhf2kQg+INLEIw72uNp71Sfo=\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// `openssl asn1parse -in public-key.pem -dump`
//
// The X is embedded within the dumped 33 byte hex-encoded BIT
// STRING value. Discard the first byte, X is the remaining 32 bytes.
constexpr absl::string_view kEd25519PublicKeyX =
    "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa";

// Generated with:
// `openssl pkey -pubout -in private-key.pem`
constexpr absl::string_view kRsaPublicKey2048 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsll1i7Arx1tosXYSyb9o\n"
    "xfoFlYozTGHhZ7wgvMdXV8Em6JIQud85iQcs9iYOaIPHzUr00x3emRW2mzAfvvli\n"
    "3oxxvS217GJdollxL4ao3D0kHpaIyCORt78evDWDEfVcJr6RC3b2H+pAjtaS8alX\n"
    "imIsgsD89vae82cOOL/JD2PaTzu70IjIrno8WlXmb2R01WLTLM57ft188BScoOls\n"
    "tlJegfu6gVqPEnSONOUTX1crLhe3ukMAgVl+b7kDPABYhNWTURjGDXWwEPb+zn7N\n"
    "zBy31Y0TiWk9Qzd/Tz3pScseQQXnkrltfwSwzSYqwzz/xaiQ0mdCXmHBnpNjVQ8i\n"
    "hQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

// Generated with:
// `openssl genpkey -quiet -algorithm rsa -pkeyopt rsa_keygen_bits:1024 |
// openssl pkey -pubout`
constexpr absl::string_view kRsaPublicKey1024 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+lQMh614+1PINuxuGg8ks1DOD\n"
    "pxDGcbLm47clu/J3KE7htWxPaiLsVeowNURyYTLTscZ/AcD7p3ceVDWNwz5xtETI\n"
    "n2GcHy9Jaaph6HSYak2IOg0p5btxqbd9+UfqKhbmrtMNDNrdRJOq8Z7oLlvbzT0x\n"
    "pj37y294RWqIWhm1rwIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

// Generated with:
// `openssl genpkey -quiet -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out
// private-key.pem`
constexpr absl::string_view kRsaPrivateKey2048 =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAsll1i7Arx1tosXYSyb9oxfoFlYozTGHhZ7wgvMdXV8Em6JIQ\n"
    "ud85iQcs9iYOaIPHzUr00x3emRW2mzAfvvli3oxxvS217GJdollxL4ao3D0kHpaI\n"
    "yCORt78evDWDEfVcJr6RC3b2H+pAjtaS8alXimIsgsD89vae82cOOL/JD2PaTzu7\n"
    "0IjIrno8WlXmb2R01WLTLM57ft188BScoOlstlJegfu6gVqPEnSONOUTX1crLhe3\n"
    "ukMAgVl+b7kDPABYhNWTURjGDXWwEPb+zn7NzBy31Y0TiWk9Qzd/Tz3pScseQQXn\n"
    "krltfwSwzSYqwzz/xaiQ0mdCXmHBnpNjVQ8ihQIDAQABAoIBAHYrXf3bEXa6syh6\n"
    "AkLYZzRdz5tggVLHu9C+zrYmIlILsZsBRMHTDM0lCv5hAsTvI9B7LLJBJT8rKt2y\n"
    "SiaAGKk6RxZAljx0hHPQbXU+9N1QSYFW3nQ1VRR5NoUfs6OPfapSM8pz3OoSjQnX\n"
    "VG94c39GQxWzhyifCXxeuQaS1EY0F8g9HKkSdRbvsNVF/2j+rdmWeur8swtYBDCN\n"
    "nBymiDhEBj/Y1Ft3R6ywC14YM/af4aDWTbhQvZYPtITdoEtOWulGkqcx0j/NlMYU\n"
    "SZcaG3M/6UuKXGzibtO4w9LlI00HPlBDi3fQGbezk6WyLNjcE4xj/MKFg7VosgN7\n"
    "XDy68tUCgYEA6FovqDcya6JxivhyVZks98e22sPARwpowI3Nt+gsF5uPcqQMvbot\n"
    "ACzKHjqxRJyGbioMUI8Ao20/f2PxzeI5wAtH2HPNaN6bCbBXvxlCTMCAokbHSWjW\n"
    "stK2PXl2cqF/51ED7EPbgxABetGyfudsx22QowSR66Sq3I8UtZnQVUMCgYEAxIBC\n"
    "EW2oLh9ZUKxEeMuFlMN1FJCCqIx3zeVjUtAC3Vm/VvodEL0KM7w9Y123BfeoWMnG\n"
    "HaqNUEZRUO/bMvaiIXVykF19NTCxym4s6eKNBwGsdWvxroRm0k37uhflt9A7iVX6\n"
    "HmDVPYgjLJbPmLc8+Ms5ML6Od7qXKajRFOPmSJcCgYEA28JY6s/x9013+InNkdpD\n"
    "ZsNU1gpo9IgK1XwJQ1TrRxTRkwtIJbZN06mJLRg0C4HDv7QzW4o1f1zXvsQnsqOy\n"
    "HUpOFJJKiFJq7roD8/GO/Irh3xn0aSEoV4/l37Te68KF96FvhWoU1xwvWhu1qEN4\n"
    "ZhLhxt2OqgJfvCXz32LwYYMCgYBVEL0JNHJw/Qs6PEksDdcXLoI509FsS9r1XE9i\n"
    "I0CKOHb3nTEF9QA8o0nkAUbhI3RSc477esDQNpCvPBalelV3rJNa4c35P8pHuuhg\n"
    "m723gcb50i/+/7xPYIkP55Z/u3p6mqi7i+nkSFIJ1IOsNe8EOV3ZtzSPqkwUMcvJ\n"
    "gltHowKBgQDkB76QzH3xb4jABKehkCxVxqyGLKxU7SOZpLpCc/5OHbo12u/CwlwG\n"
    "uAeidKZk3SJEmj0F1+Aiir2KRv+RX543VvzCtEXNkVViVrirzvjZUGKPdkMWfbF8\n"
    "OdD7qHPPNu5jSyaroeN6VqfbELpewhYzulMEipckEZlU4+Dxu2k1eQ==\n"
    "-----END RSA PRIVATE KEY-----\n";

// Helper function that creates an EcdsaPublicKey from the given PEM encoded
// key `pem_encoded_key`, Hash type `hash_type` and key version `key_version`.
absl::StatusOr<EcdsaPublicKeyProto> GetExpectedEcdsaPublicKeyProto(
    EllipticCurveType curve, EcdsaSignatureEncoding encoding) {
  EcdsaPublicKeyProto public_key_proto;
  public_key_proto.set_version(0);

  switch (curve) {
    case EllipticCurveType::NIST_P256: {
      public_key_proto.set_x(test::HexDecodeOrDie(kEcdsaP256PublicKeyX));
      public_key_proto.set_y(test::HexDecodeOrDie(kEcdsaP256PublicKeyY));
      public_key_proto.mutable_params()->set_hash_type(HashType::SHA256);
      break;
    }
    case EllipticCurveType::NIST_P384: {
      public_key_proto.set_x(test::HexDecodeOrDie(kEcdsaP384PublicKeyX));
      public_key_proto.set_y(test::HexDecodeOrDie(kEcdsaP384PublicKeyY));
      public_key_proto.mutable_params()->set_hash_type(HashType::SHA384);
      break;
    }
    case EllipticCurveType::NIST_P521: {
      public_key_proto.set_x(test::HexDecodeOrDie(kEcdsaP521PublicKeyX));
      public_key_proto.set_y(test::HexDecodeOrDie(kEcdsaP521PublicKeyY));
      public_key_proto.mutable_params()->set_hash_type(HashType::SHA512);
      break;
    }
    default: {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid curve type.");
    }
  }

  public_key_proto.mutable_params()->set_curve(curve);
  public_key_proto.mutable_params()->set_encoding(encoding);

  return public_key_proto;
}

absl::StatusOr<EcdsaPrivateKeyProto> GetExpectedEcdsaPrivateKeyProto(
    EllipticCurveType curve, EcdsaSignatureEncoding encoding) {
  absl::StatusOr<EcdsaPublicKeyProto> public_key;
  EcdsaPrivateKeyProto private_key_proto;
  private_key_proto.set_version(0);

  switch (curve) {
    case EllipticCurveType::NIST_P256: {
      private_key_proto.set_key_value(
          test::HexDecodeOrDie(kEcdsaP256PrivateKeyD));
      break;
    }
    case EllipticCurveType::NIST_P384: {
      private_key_proto.set_key_value(
          test::HexDecodeOrDie(kEcdsaP384PrivateKeyD));
      break;
    }
    case EllipticCurveType::NIST_P521: {
      private_key_proto.set_key_value(
          test::HexDecodeOrDie(kEcdsaP521PrivateKeyD));
      break;
    }
    default: {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid curve type.");
    }
  }

  public_key = GetExpectedEcdsaPublicKeyProto(curve, encoding);
  if (!public_key.ok()) {
    return public_key.status();
  }
  private_key_proto.mutable_public_key()->Swap(&*public_key);
  return private_key_proto;
}

// Helper function that creates an RsaSsaPssPublicKey from the given PEM encoded
// key `pem_encoded_key`, Hash type `hash_type` and key version `key_version`.
absl::StatusOr<RsaSsaPssPublicKeyProto> GetRsaSsaPssPublicKeyProto(
    absl::string_view pem_encoded_key, HashType hash_type,
    uint32_t key_version) {
  absl::StatusOr<std::unique_ptr<internal::RsaPublicKey>> public_key =
      subtle::PemParser::ParseRsaPublicKey(pem_encoded_key);
  if (!public_key.ok()) {
    return public_key.status();
  }
  std::unique_ptr<internal::RsaPublicKey> key_subtle = *std::move(public_key);

  RsaSsaPssPublicKeyProto public_key_proto;
  public_key_proto.set_version(key_version);
  public_key_proto.set_e(key_subtle->e);
  public_key_proto.set_n(key_subtle->n);
  public_key_proto.mutable_params()->set_mgf1_hash(hash_type);
  public_key_proto.mutable_params()->set_sig_hash(hash_type);
  public_key_proto.mutable_params()->set_salt_length(
      util::Enums::HashLength(hash_type).value());

  return public_key_proto;
}

// Helper function that creates an RsaSsaPssPrivateKey from the given PEM
// encoded key `pem_encoded_key`, Hash type `hash_type` and key version
// `key_version`.
absl::StatusOr<RsaSsaPssPrivateKeyProto> GetRsaSsaPssPrivateKeyProto(
    absl::string_view pem_encoded_key, HashType hash_type,
    uint32_t key_version) {
  // Parse the key with subtle::PemParser to make sure the proto key fields are
  // correct.
  absl::StatusOr<std::unique_ptr<internal::RsaPrivateKey>> private_key =
      subtle::PemParser::ParseRsaPrivateKey(pem_encoded_key);
  if (!private_key.ok()) {
    return private_key.status();
  }
  std::unique_ptr<internal::RsaPrivateKey> key_subtle = *std::move(private_key);

  // Set the inner RSASSA-PSS public key and its parameters.
  RsaSsaPssPrivateKeyProto private_key_proto;

  private_key_proto.set_version(key_version);
  private_key_proto.set_d(
      std::string(util::SecretDataAsStringView(key_subtle->d)));
  private_key_proto.set_p(
      std::string(util::SecretDataAsStringView(key_subtle->p)));
  private_key_proto.set_q(
      std::string(util::SecretDataAsStringView(key_subtle->q)));
  private_key_proto.set_dp(
      std::string(util::SecretDataAsStringView(key_subtle->dp)));
  private_key_proto.set_dq(
      std::string(util::SecretDataAsStringView(key_subtle->dq)));
  private_key_proto.set_crt(
      std::string(util::SecretDataAsStringView(key_subtle->crt)));

  // Set public key parameters.
  RsaSsaPssPublicKeyProto* public_key_proto =
      private_key_proto.mutable_public_key();
  public_key_proto->set_version(key_version);
  public_key_proto->set_e(key_subtle->e);
  public_key_proto->set_n(key_subtle->n);
  // Set algorithm-specific parameters.
  public_key_proto->mutable_params()->set_mgf1_hash(hash_type);
  public_key_proto->mutable_params()->set_sig_hash(hash_type);
  public_key_proto->mutable_params()->set_salt_length(
      util::Enums::HashLength(hash_type).value());

  return private_key_proto;
}

PemKey CreatePemKey(absl::string_view serialized_key,
                    crypto::tink::PemKeyType key_type,
                    crypto::tink::PemAlgorithm algorithm,
                    size_t key_size_in_bits,
                    google::crypto::tink::HashType hash_type) {
  PemKey pem_key = {
      /*serialized_key=*/std::string(serialized_key),
      /*parameters=*/{key_type, algorithm, key_size_in_bits, hash_type},
  };
  return pem_key;
}

TEST(SignaturePemKeysetReaderTest, ReadCorrectPrivateKeyWithMultipleKeyTypes) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);

  builder.Add(CreatePemKey(kEcdsaP256PrivateKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_IEEE, /*key_size_in_bits=*/256,
                           HashType::SHA256));
  builder.Add(CreatePemKey(kRsaPrivateKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA384));

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  EXPECT_THAT((*keyset)->key(), SizeIs(2));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());
  EXPECT_THAT((*keyset)->key(0).key_id(), Not(Eq((*keyset)->key(1).key_id())));

  // Key managers to validate key type and key material type.
  EcdsaSignKeyManager ecdsa_sign_key_manager;
  RsaSsaPssSignKeyManager rsa_sign_key_manager;

  // Build the expected primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id((*keyset)->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(ecdsa_sign_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      ecdsa_sign_key_manager.key_material_type());
  absl::StatusOr<EcdsaPrivateKeyProto> ecdsa_private_key1 =
      GetExpectedEcdsaPrivateKeyProto(EllipticCurveType::NIST_P256,
                                      EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(ecdsa_private_key1, IsOk());
  expected_keydata1->set_value(ecdsa_private_key1->SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key1));

  // Build the expected second key.
  Keyset::Key expected_key2;
  // ID is randomly generated, so we simply copy the one from the second key.
  expected_key2.set_key_id((*keyset)->key(1).key_id());
  expected_key2.set_status(KeyStatusType::ENABLED);
  expected_key2.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected second key KeyData.
  KeyData* expected_keydata2 = expected_key2.mutable_key_data();
  expected_keydata2->set_type_url(rsa_sign_key_manager.get_key_type());
  expected_keydata2->set_key_material_type(
      rsa_sign_key_manager.key_material_type());
  absl::StatusOr<RsaSsaPssPrivateKeyProto> rsa_pss_private_key2 =
      GetRsaSsaPssPrivateKeyProto(kRsaPrivateKey2048, HashType::SHA384,
                                  rsa_sign_key_manager.get_version());
  ASSERT_THAT(rsa_pss_private_key2, IsOk());
  expected_keydata2->set_value(rsa_pss_private_key2->SerializeAsString());
  EXPECT_THAT((*keyset)->key(1), EqualsKey(expected_key2));
}

TEST(SignaturePemKeysetReaderTest, ReadCorrectPublicKeyWithMultipleKeyTypes) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA384));
  builder.Add(CreatePemKey(kEcdsaP256PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_DER, /*key_size_in_bits=*/256,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  EXPECT_THAT((*keyset)->key(), SizeIs(2));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());
  EXPECT_THAT((*keyset)->key(0).key_id(), Not(Eq((*keyset)->key(1).key_id())));

  // Key managers to validate key type and key material type.
  RsaSsaPssVerifyKeyManager verify_key_manager;
  EcdsaVerifyKeyManager key_manager;

  // Build the expected primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id((*keyset)->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(verify_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      verify_key_manager.key_material_type());

  absl::StatusOr<RsaSsaPssPublicKeyProto> rsa_ssa_pss_pub_key =
      GetRsaSsaPssPublicKeyProto(kRsaPublicKey2048, HashType::SHA384,
                                 verify_key_manager.get_version());
  ASSERT_THAT(rsa_ssa_pss_pub_key, IsOk());
  expected_keydata1->set_value(rsa_ssa_pss_pub_key->SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key1));

  // Build the expected secondary key.
  Keyset::Key expected_secondary;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_secondary.set_key_id((*keyset)->key(1).key_id());
  expected_secondary.set_status(KeyStatusType::ENABLED);
  expected_secondary.set_output_prefix_type(OutputPrefixType::RAW);

  // Populate the expected secondary key KeyData.
  KeyData* expected_secondary_data = expected_secondary.mutable_key_data();
  expected_secondary_data->set_type_url(key_manager.get_key_type());
  expected_secondary_data->set_key_material_type(
      key_manager.key_material_type());
  absl::StatusOr<EcdsaPublicKeyProto> pub_key = GetExpectedEcdsaPublicKeyProto(
      EllipticCurveType::NIST_P256, EcdsaSignatureEncoding::DER);
  ASSERT_THAT(pub_key, IsOk());
  expected_secondary_data->set_value(pub_key->SerializeAsString());
  EXPECT_THAT((*keyset)->key(1), EqualsKey(expected_secondary));
}

// Verify check on PEM array size not zero before creating a reader.
TEST(SignaturePemKeysetReaderTest, BuildEmptyPemArray) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  EXPECT_THAT(keyset_reader, StatusIs(absl::StatusCode::kInvalidArgument));
}

// Make sure ReadUnencrypted returns an UNSUPPORTED error as expected.
TEST(SignaturePemKeysetReaderTest, ReadEncryptedUnsupported) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA384));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->ReadEncrypted(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

// Verify parsing works correctly on valid input.
TEST(SignaturePemKeysetReaderTest, ReadRsaCorrectPublicKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA384));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*keyset_reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  // Key manager to validate key type and key material type.
  RsaSsaPssVerifyKeyManager verify_key_manager;
  EXPECT_THAT((*keyset)->key(), SizeIs(1));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());

  // Build the expectedi primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id((*keyset)->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(verify_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      verify_key_manager.key_material_type());

  absl::StatusOr<RsaSsaPssPublicKeyProto> rsa_ssa_pss_pub_key =
      GetRsaSsaPssPublicKeyProto(kRsaPublicKey2048, HashType::SHA384,
                                 verify_key_manager.get_version());
  ASSERT_THAT(rsa_ssa_pss_pub_key, IsOk());
  expected_keydata1->set_value(rsa_ssa_pss_pub_key->SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key1));
}

// RSA public key with OID 1.2.840.113549.1.1.11 "sha256WithRSAEncryption"
// from RFC 4055.
//
// Copied from tink-java's PemKeyConverterTest.java.
constexpr absl::string_view kRsaSha256PublicKey = R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQsFAAOCAY8AMIIBigKCAYEAoHiH83M3gZawt0jN8xwU
c1zPoPEXrK/aoh/eS251WTkLg057kunhzJ1J/A/mz7YEKWUrS/mndo9x/EJxym/v
TkMRkuvcmGML+5TFuvGLTPeIHYRIPkxEwi2xWpYncFoLQqJtbz1gCa7g0qcb7fTU
sO5rb+wvFuEnfsqjve26QGRzpHbRaI3w+tHaeVUmx+ZBmBtIErBbaS1gxgsr+kJM
i2IPQNydulnixxDn7nULPhNMH3H0MhBoiv8XqqQc21ZodT8ABrHPlRvFlR9NiaMR
lphepVwJZsNmK8/k5M008S5K/X5cShMHObEBfWpYOIL9ctsaZ0GHAsiwE1PM91t7
k/rsDgvjYhHV8r2RDhVSMjcRu+tzhY+JnMHsBj72fYjgxpnVponFIQbwbpYPCdKj
z4T1O76ipHPt8ubgF2gB0/ocLTWOHlom9kask3luwfrcaZHA7BnJ3ZCyWi3Tv3PS
zx7qiGf5bKpaLfVJc6yyotoKE2fsdK+7lo9Rd2UjjRdpAgMBAAE=
-----END PUBLIC KEY-----)";

TEST(SignaturePemKeysetReaderTest, ParseRsaSha256PublicKeyFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaSha256PublicKey, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PKCS1,
                           /*key_size_in_bits=*/2048, HashType::SHA256));

  auto reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  EXPECT_THAT((*reader)->Read(), Not(IsOk()));
}

// RSA SSA PSS public key with OID 1.2.840.113549.1.1.10 "id_RSASSA_PSS" from
// RFC 4055. It has parameters sig hash and mgf1 hash set to SHA256.
//
// Copied from tink-java's PemKeyConverterTest.java.
constexpr absl::string_view kRsaSsaPssPublicKey = R"(-----BEGIN PUBLIC KEY-----
MIIBUDA7BgkqhkiG9w0BAQowLjANBglghkgBZQMEAgEFADAaBgkqhkiG9w0BAQgw
DQYJYIZIAWUDBAIBBQACARQDggEPADCCAQoCggEBALE8O9Jpvv6rBFCOeVIXdsA4
6LhO8xfQBMCjt9Bh5H/bc30jJkGMlDaKsgmzOh8IsFVGx2rBJrlXyOhkpNM1jAiY
ZC46/+YXzpepQMoWjQsSK+3/GM0U8RDZcLK2DqZb2Kd3LM/E8qK8gbz7hu+OHnc1
UEst8JT97peDAW5TEk9EmEf2HY19Ok8OQCDzMINVWfBf5HuxgjbQMmOnU+TU3h1e
Z2axdGbbAzdIPEs8UXs/Eht6z+GlkRI9V23PuNajKl1IIJ3YivzJWX/fCzH6fDhE
/AhacWV+3bEqUG7McXbu4Qh5Me95YvGigJgAMqpF3gU3xTtltj1G70Le4QSbZ08C
AwEAAQ==
-----END PUBLIC KEY-----)";

TEST(SignaturePemKeysetReaderTest, ParseRsaPssPublicKeyFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaSsaPssPublicKey, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA256));

  auto reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  EXPECT_THAT((*reader)->Read(), Not(IsOk()));
}

TEST(SignaturePemKeysetReaderTest, ReadRsaCorrectPrivateKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);

  builder.Add(CreatePemKey(kRsaPrivateKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*keyset_reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  EXPECT_THAT((*keyset)->key(), SizeIs(1));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());

  // Key manager to validate key type and key material type.
  RsaSsaPssSignKeyManager sign_key_manager;

  // Build the expected primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id((*keyset)->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(sign_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      sign_key_manager.key_material_type());
  absl::StatusOr<RsaSsaPssPrivateKeyProto> rsa_pss_private_key1 =
      GetRsaSsaPssPrivateKeyProto(kRsaPrivateKey2048, HashType::SHA256,
                                  sign_key_manager.get_version());
  ASSERT_THAT(rsa_pss_private_key1, IsOk());
  expected_keydata1->set_value(rsa_pss_private_key1->SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key1));
}

TEST(SignaturePemKeysetReaderTest, ReadAndUseRsaPemKeys) {
  for (PemAlgorithm pem_algorithm :
       {PemAlgorithm::RSASSA_PSS, PemAlgorithm::RSASSA_PKCS1}) {
    for (HashType hash_type :
         {HashType::SHA256, HashType::SHA384, HashType::SHA512}) {
      auto private_keyset_reader_builder = SignaturePemKeysetReaderBuilder(
          SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
      private_keyset_reader_builder.Add(
          CreatePemKey(kRsaPrivateKey2048, PemKeyType::PEM_RSA, pem_algorithm,
                       /*key_size_in_bits=*/2048, hash_type));
      absl::StatusOr<std::unique_ptr<KeysetReader>> private_keyset_reader =
          private_keyset_reader_builder.Build();
      ASSERT_THAT(private_keyset_reader, IsOk());
      absl::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
          CleartextKeysetHandle::Read(std::move(*private_keyset_reader));

      auto public_keyset_reader_builder = SignaturePemKeysetReaderBuilder(
          SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
      public_keyset_reader_builder.Add(
          CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA, pem_algorithm,
                       /*key_size_in_bits=*/2048, hash_type));
      absl::StatusOr<std::unique_ptr<KeysetReader>> public_keyset_reader =
          public_keyset_reader_builder.Build();
      ASSERT_THAT(public_keyset_reader, IsOk());
      absl::StatusOr<std::unique_ptr<KeysetHandle>> public_keyset_handle =
          CleartextKeysetHandle::Read(std::move(*public_keyset_reader));

      absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
          (*private_keyset_handle)
              ->GetPrimitive<PublicKeySign>(ConfigSignature2026());
      ASSERT_THAT(sign, IsOk());
      absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
          (*public_keyset_handle)
              ->GetPrimitive<PublicKeyVerify>(ConfigSignature2026());
      ASSERT_THAT(verify, IsOk());

      std::string data = "data";
      absl::StatusOr<std::string> signature = (*sign)->Sign(data);
      ASSERT_THAT(signature, IsOk());
      EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
    }
  }
}

// Expects an INVLID_ARGUMENT when passing a public key to a
// PublicKeySignPemKeysetReader.
TEST(SignaturePemKeysetReaderTest, ReadRsaPrivateKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA384));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVLID_ARGUMENT when passing a private key to a
// PublicKeyVerifyPemKeysetReader.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPrivateKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as the key size is too small.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyTooSmall) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey1024, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/1024,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as the key is 2048 bits, but PemKeyParams
// reports 3072.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeySizeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/3072,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as SHA1 is not allowed.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyInvalidHashType) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA1));

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

struct KeysetReaderTestCase {
  std::string test_name;
  PemKey private_pem_key;
  PemKey public_pem_key;
  EllipticCurveType ec_curve;
  EcdsaSignatureEncoding encoding;
};

using EcdsaSignaturePemKeysetReaderTest = TestWithParam<KeysetReaderTestCase>;

INSTANTIATE_TEST_SUITE_P(
    EcdsaSignaturePemKeysetReaderTestSuite, EcdsaSignaturePemKeysetReaderTest,
    testing::ValuesIn<KeysetReaderTestCase>({
        {
            /*test_name=*/"EcdsaP256Der",
            /*private_pem_key=*/
            CreatePemKey(kEcdsaP256PrivateKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_DER,
                         /*key_size_in_bits=*/256, HashType::SHA256),
            /*public_pem_key=*/
            CreatePemKey(kEcdsaP256PublicKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_DER,
                         /*key_size_in_bits=*/256, HashType::SHA256),
            /*ec_curve=*/EllipticCurveType::NIST_P256,
            /*encoding=*/EcdsaSignatureEncoding::DER,
        },
        {
            /*test_name=*/"EcdsaP256Ieee",
            /*private_pem_key=*/
            CreatePemKey(kEcdsaP256PrivateKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_IEEE,
                         /*key_size_in_bits=*/256, HashType::SHA256),
            /*public_pem_key=*/
            CreatePemKey(kEcdsaP256PublicKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_IEEE,
                         /*key_size_in_bits=*/256, HashType::SHA256),
            /*ec_curve=*/EllipticCurveType::NIST_P256,
            /*encoding=*/EcdsaSignatureEncoding::IEEE_P1363,
        },
        {
            /*test_name=*/"EcdsaP384Der",
            /*private_pem_key=*/
            CreatePemKey(kEcdsaP384PrivateKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_DER,
                         /*key_size_in_bits=*/384, HashType::SHA384),
            /*public_pem_key=*/
            CreatePemKey(kEcdsaP384PublicKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_DER,
                         /*key_size_in_bits=*/384, HashType::SHA384),
            /*ec_curve=*/EllipticCurveType::NIST_P384,
            /*encoding=*/EcdsaSignatureEncoding::DER,
        },
        {
            /*test_name=*/"EcdsaP384Ieee",
            /*private_pem_key=*/
            CreatePemKey(kEcdsaP384PrivateKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_IEEE,
                         /*key_size_in_bits=*/384, HashType::SHA384),
            /*public_pem_key=*/
            CreatePemKey(kEcdsaP384PublicKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_IEEE,
                         /*key_size_in_bits=*/384, HashType::SHA384),
            /*ec_curve=*/EllipticCurveType::NIST_P384,
            /*encoding=*/EcdsaSignatureEncoding::IEEE_P1363,
        },
        {
            /*test_name=*/"EcdsaP521Der",
            /*private_pem_key=*/
            CreatePemKey(kEcdsaP521PrivateKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_DER,
                         /*key_size_in_bits=*/521, HashType::SHA512),
            /*public_pem_key=*/
            CreatePemKey(kEcdsaP521PublicKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_DER,
                         /*key_size_in_bits=*/521, HashType::SHA512),
            /*ec_curve=*/EllipticCurveType::NIST_P521,
            /*encoding=*/EcdsaSignatureEncoding::DER,
        },
        {
            /*test_name=*/"EcdsaP521Ieee",
            /*private_pem_key=*/
            CreatePemKey(kEcdsaP521PrivateKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_IEEE,
                         /*key_size_in_bits=*/521, HashType::SHA512),
            /*public_pem_key=*/
            CreatePemKey(kEcdsaP521PublicKey, PemKeyType::PEM_EC,
                         PemAlgorithm::ECDSA_IEEE,
                         /*key_size_in_bits=*/521, HashType::SHA512),
            /*ec_curve=*/EllipticCurveType::NIST_P521,
            /*encoding=*/EcdsaSignatureEncoding::IEEE_P1363,
        },
    }),
    [](const testing::TestParamInfo<
        EcdsaSignaturePemKeysetReaderTest::ParamType>& info) {
      return info.param.test_name;
    });

TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadEcdsaCorrectPublicKey) {
  const KeysetReaderTestCase& test_case = GetParam();
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(test_case.public_pem_key);
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  // Although this keyset only contains public keys, Tink's API requires using
  // CleartextKeysetHandle to read from a KeysetReader.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  ASSERT_THAT(keyset_handle, IsOk());

  // Create a proto Keyset object from keyset_handle
  absl::StatusOr<std::string> serialized_keyset =
      SerializeKeysetWithoutSecretToProtoKeysetFormat(*keyset_handle.value());
  ASSERT_THAT(serialized_keyset, IsOk());
  Keyset keyset;
  keyset.ParseFromString(*serialized_keyset);

  EXPECT_THAT(keyset.key(), SizeIs(1));
  EXPECT_THAT(keyset.primary_key_id(), Eq(keyset.key(0).key_id()));

  // Build the expected primary key.
  Keyset::Key expected_primary;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_primary.set_key_id(keyset.primary_key_id());
  expected_primary.set_status(KeyStatusType::ENABLED);
  expected_primary.set_output_prefix_type(OutputPrefixType::RAW);

  // Populate the expected primary key KeyData.
  KeyData* expected_primary_data = expected_primary.mutable_key_data();
  expected_primary_data->set_type_url(
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey");
  expected_primary_data->set_key_material_type(
      google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC);
  absl::StatusOr<EcdsaPublicKeyProto> pub_key =
      GetExpectedEcdsaPublicKeyProto(test_case.ec_curve, test_case.encoding);
  ASSERT_THAT(pub_key, IsOk());
  expected_primary_data->set_value(pub_key->SerializeAsString());
  EXPECT_THAT(keyset.key(0), EqualsKey(expected_primary));
}

TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadEcdsaCorrectPrivateKey) {
  const KeysetReaderTestCase& test_case = GetParam();
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  builder.Add(test_case.private_pem_key);

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  EXPECT_THAT((*keyset)->key(), SizeIs(1));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());

  // Key manager to validate key type and key material type.
  EcdsaSignKeyManager ecdsa_sign_key_manager;

  // Build the expected primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id((*keyset)->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(ecdsa_sign_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      ecdsa_sign_key_manager.key_material_type());
  absl::StatusOr<EcdsaPrivateKeyProto> ecdsa_private_key1 =
      GetExpectedEcdsaPrivateKeyProto(test_case.ec_curve, test_case.encoding);
  ASSERT_THAT(ecdsa_private_key1, IsOk());
  expected_keydata1->set_value(ecdsa_private_key1->SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key1));
}

TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadAndUseEcdsaPemKeys) {
  const KeysetReaderTestCase& test_case = GetParam();
  auto private_keyset_reader_builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  private_keyset_reader_builder.Add(test_case.private_pem_key);
  absl::StatusOr<std::unique_ptr<KeysetReader>> private_keyset_reader =
      private_keyset_reader_builder.Build();
  ASSERT_THAT(private_keyset_reader, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
      CleartextKeysetHandle::Read(std::move(*private_keyset_reader));

  auto public_keyset_reader_builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  public_keyset_reader_builder.Add(test_case.public_pem_key);
  absl::StatusOr<std::unique_ptr<KeysetReader>> public_keyset_reader =
      public_keyset_reader_builder.Build();
  ASSERT_THAT(public_keyset_reader, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_keyset_handle =
      CleartextKeysetHandle::Read(std::move(*public_keyset_reader));

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*private_keyset_handle)
          ->GetPrimitive<PublicKeySign>(ConfigSignature2026());
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_keyset_handle)
          ->GetPrimitive<PublicKeyVerify>(ConfigSignature2026());
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

// Expects an INVALID_ARGUMENT when passing a public key to a
// PublicKeySignPemKeysetReader.
TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadEcdsaPrivateKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  builder.Add(GetParam().public_pem_key);

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT when passing a private key to a
// PublicKeyVerifyPemKeysetReader.
TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadEcdsaPublicKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(GetParam().private_pem_key);

  absl::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EcdsaSignaturePemKeysetReaderTest,
       ReadEcdsaPrivateKeyMismatchedHashType) {
  const KeysetReaderTestCase& test_case = GetParam();
  for (const HashType hash :
       {HashType::SHA1, HashType::SHA256, HashType::SHA384, HashType::SHA512}) {
    if (hash == test_case.public_pem_key.parameters.hash_type) {
      continue;
    }
    PemKey pub_key = test_case.public_pem_key;
    pub_key.parameters.hash_type = hash;
    auto builder = SignaturePemKeysetReaderBuilder(
        SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);

    builder.Add(pub_key);

    absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
    ASSERT_THAT(reader, IsOk());
    absl::StatusOr<std::unique_ptr<Keyset>> keyset_read = reader->get()->Read();
    ASSERT_THAT(keyset_read, StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(EcdsaSignaturePemKeysetReaderTest,
       ReadECDSAPublicKeyMismatchedHashType) {
  const KeysetReaderTestCase& test_case = GetParam();
  for (const HashType hash :
       {HashType::SHA1, HashType::SHA256, HashType::SHA384, HashType::SHA512}) {
    if (hash == test_case.public_pem_key.parameters.hash_type) {
      continue;
    }
    PemKey pub_key = test_case.public_pem_key;
    pub_key.parameters.hash_type = hash;
    auto builder = SignaturePemKeysetReaderBuilder(
        SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

    builder.Add(pub_key);

    absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
    ASSERT_THAT(reader, IsOk());
    absl::StatusOr<std::unique_ptr<Keyset>> keyset_read = reader->get()->Read();
    ASSERT_THAT(keyset_read, StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(SignaturePemKeysetReaderTest, ReadECDSAWrongKeySize) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kEcdsaP256PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_IEEE, /*key_size_in_bits=*/512,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadECDSAWrongAlgorithm) {
  const KeysetReaderTestCase& test_case = GetParam();
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  PemKey pub_key = test_case.public_pem_key;
  pub_key.parameters.algorithm = PemAlgorithm::RSASSA_PSS;

  builder.Add(pub_key);

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ED25519, /*key_size_in_bits=*/253,
                           HashType::SHA512));
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  Keyset::Key expected_key;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key.set_key_id((*keyset)->primary_key_id());
  expected_key.set_status(KeyStatusType::ENABLED);
  expected_key.set_output_prefix_type(OutputPrefixType::RAW);
  Ed25519PublicKeyProto expected_pub_key;
  expected_pub_key.set_key_value(test::HexDecodeOrDie(kEd25519PublicKeyX));
  expected_key.mutable_key_data()->set_type_url(
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey");
  expected_key.mutable_key_data()->set_key_material_type(
      KeyData::ASYMMETRIC_PUBLIC);
  expected_key.mutable_key_data()->set_value(
      expected_pub_key.SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key));

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::ReadNoSecret((*keyset)->SerializeAsString());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*handle)->GetPrimitive<PublicKeyVerify>(ConfigSignature2026());
  ASSERT_THAT(verify, IsOk());
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519WrongAlgorithmFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  for (const PemAlgorithm algorithm :
       {PemAlgorithm::ECDSA_DER, PemAlgorithm::ECDSA_IEEE,
        PemAlgorithm::RSASSA_PSS, PemAlgorithm::RSASSA_PKCS1}) {
    for (const HashType hash_type :
         {HashType::SHA256, HashType::SHA384, HashType::SHA512}) {
      builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_EC, algorithm,
                               /*key_size_in_bits=*/253, hash_type));

      absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
      ASSERT_THAT(reader, IsOk());
      ASSERT_THAT(reader->get()->Read(),
                  StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519WInvalidHashFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  for (const HashType hash_type :
       {HashType::SHA1, HashType::SHA256, HashType::SHA384}) {
    builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_EC,
                             PemAlgorithm::ED25519,
                             /*key_size_in_bits=*/253, hash_type));

    absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
    ASSERT_THAT(reader, IsOk());
    ASSERT_THAT(reader->get()->Read(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519WInvalidKeyTypeFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_RSA,
                           PemAlgorithm::ED25519,
                           /*key_size_in_bits=*/253, HashType::SHA512));

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  ASSERT_THAT(reader->get()->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519WInvalidKeySizeFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ED25519,
                           /*key_size_in_bits=*/300, HashType::SHA512));

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  ASSERT_THAT(reader->get()->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadSecp256k1ShouldFail) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kSecp256k1PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_IEEE, /*key_size_in_bits=*/256,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset_read = reader->get()->Read();
  // With BoringSSL parsing of the PEM key fails when an unsupported curve is
  // used [1]; Supported curves are defined here [2]. Tink doesn't distinguish
  // between an error caused by a malformed PEM and an unsupported group by
  // BoringSSL. On the other hand, with OpenSSL parsing succeeds, but this
  // curve is unsupported by Tink. As a consequence, this fails with two
  // different errors.
  //
  // [1]https://github.com/google/boringssl/blob/master/crypto/ec_extra/ec_asn1.c#L324
  // [2]https://github.com/google/boringssl/blob/master/crypto/fipsmodule/ec/ec.c#L218
  if (internal::IsBoringSsl()) {
    EXPECT_THAT(keyset_read, StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(keyset_read, StatusIs(absl::StatusCode::kUnimplemented));
  }
}

constexpr absl::string_view kMlDsa44PublicKeyPem =
    R"PEM(-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhANeytHJUquDbReeTDUqY0sl9jxOX0Xidr6Fw
JLMW6b7JT8mUbULxm3mnQTu6oz5xSctC7VEVaTrAQfrLmIretf4OHYYxGEmVtZLD
l9IpTi4U+QqkFLo4JomaxD9MzKy8JumoMrlRGNXLQzy++WYLABOOCBf2HnYsonTD
atVU6yKqwRYuSrAay6HjjE79j4C2WzM9D3LlXf5xzpweu5iJ58VhBsD9c4A6Kuz+
r97XqjyyztpU0SvYzTanjPl1lDtHq9JeiArEUuV0LtHo0agq+oblkMdYwVrk0oQN
kryhpQkPQElll/yn2LlRPxob2m6VCqqY3kZ1B9Sk9aTwWZIWWCw1cvYu2okFqzWB
ZwxKAnd6M+DKcpX9j0/20aCjp2g9ZfX19/xg2gI+gmxfkhRMAvfRuhB1mHVT6pNn
/NdtmQt/qZzUWv24g21D5Fn1GH3wWEeXCaAepoNZNfpwRgmQzT3BukAbqUurHd5B
rGerMxncrKBgSNTE7vJ+4TqcF9BTj0MPLWQtwkFWYN54h32NirxyUjl4wELkKF9D
GYRsRBJiQpdoRMEOVWuiFbWnGeWdDGsqltOYWQcf3MLN51JKe+2uVOhbMY6FTo/i
svPt+slxkSgnCq/R5QRMOk/a/Z/zH5B4S46ORZYUSg2vWGUR09mWK56pWvGXtOX8
YPKx7RXeOlvvX4m9x52RBR2bKBbnT6VFMe/cHL501EiFf0drzVjyHAtlOzt2pOB2
plWaMCcYVVzGP3SFmqurkl8COGHKjND3utsocfZ9VTJtdFETWtRfShumkRj7ssij
DuyTku8/l3Bmya3VxxDMZHsVFNIX2VjHAXw+kP0gwE5nS5BIbpNwoxoAHTL0c5ee
SQZ0nn5Hf6C3RQj4pfI3gxK4PCW9OIygsP/3R4uvQrcWZ+2qyXxGsSlkPlhuWwVa
DCEZRtTzbmdb7Vhg+gQqMV2YJhZNapI3w1pfv0lUkKW9TfJIuVxKrneEtgVnMWas
QkW1tLCCoJ6TI+YvIHjFt2eDRG3v1zatOjcC1JsImESQCmGDM5e8RBmzDXqXoLOH
wZEUdMTUG1PjKpd6y28Op122W7OeWecB52lX3vby1EVZwxp3EitSBOO1whnxaIsU
7QvAuAGz5ugtzUPpwOn0F0TNmBW9G8iCDYuxI/BPrNGxtoXdWisbjbvz7ZM2cPCV
oYC08ZLQixC4+rvfzCskUY4y7qCl4MkEyoRHgAg/OwzS0Li2r2e8NVuUlAJdx7Cn
j6gOOi2/61EyiFHWB4GY6Uk2Ua54fsAlH5Irow6fUd9iptcnhM890gU5MXbfoySl
Er2Ulwo23TSlFKhnkfDrNvAUWwmrZGUbSgMTsplhGiocSIkWJ1mHaKMRQGC6RENI
bfUVIqHOiLMJhcIW+ObtF43VZ7MEoNTK+6iCooNC8XqaomrljbYwCD0sNY/fVmw/
XWKkKFZ7yeqM6VyqDzVHSwv6jzOaJQq0388gg76O77wQVeGP4VNw7ssmBWbYP/Br
IRquxDyim1TM0A+IFaJGXvC0ZRXMfkHzEk8J7/9zkwmrWLKaFFmgC85QOOk4yWeP
cusOTuX9quZtn4Vz/Jf8QrSVn0v4th14Qz6GsDNdbpGRxNi/SHs5BcEIz9asJLDO
t9y3z1H4TQ7Wh7lerrHFM8BvDZcCPZKnCCWDe1m6bLfU5WsKh8IDhiro8xW6WSXo
7e+meTaaIgJ2YVHxapZfn4Hs52zAcLVYaeTbl4TPBcgwsyQsgxI=
-----END PUBLIC KEY-----
)PEM";

constexpr absl::string_view kMlDsa44ExpectedBytesHex =
    "d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42"
    "f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c3"
    "97d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00"
    "138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72"
    "e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a7"
    "8cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5"
    "090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f6"
    "2eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e"
    "826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f518"
    "7df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca0"
    "6048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4"
    "285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7"
    "524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90"
    "784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bd"
    "c79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6"
    "559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad4"
    "5f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e"
    "90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f23783"
    "12b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4"
    "f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784"
    "b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b0898"
    "44900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb3"
    "9e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82d"
    "cd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670"
    "f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8"
    "b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec025"
    "1f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791"
    "f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df5"
    "1522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630"
    "083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083"
    "be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0"
    "b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fd"
    "aae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cf"
    "d6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7"
    "d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc0"
    "70b55869e4db9784cf05c830b3242c8312";

constexpr absl::string_view kMlDsa65PublicKeyPem =
    "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "HgLy6ERP\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kMlDsa65ExpectedBytesHex =
    "48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27d05b38dbb2"
    "edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee67d2c0320954d57212ca"
    "c7229ff1d6eaf03928bd51511f8d88d847736c7de2730d5978e5410713160978867711bf55"
    "39a0bfc4c350c2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff"
    "3cea8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173fce55b67"
    "745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb0"
    "03b8fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d27987bb55d"
    "f69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29afef7031c3a6d857"
    "1610b42c9f421245a88f197e16812b031159b65b9687e5b3e934c5225ae98a79ba73d2b399"
    "d73510effad19e53b8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882"
    "f26378222fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d9"
    "8deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6e"
    "d175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8b3"
    "ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5c74dfc028366"
    "6b40c0793870028204a136bf5da9568eb798d349038bdb0c11e03445e7847cb5069c75cf28"
    "ac601c7799d958210ddbcb226e51afef9f1de47b073873d6d3f97456bede085082e74a298b"
    "2cd48f4b3093155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa67988"
    "2a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96"
    "af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2"
    "b2310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246d7fedb3f"
    "db67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe88014960dce5d94223652"
    "6e12a478d69e5fbe6970310b308c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2"
    "f11068613fbe029bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c5"
    "412863a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f"
    "398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d9617267298"
    "0cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4cb798"
    "bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300750df1d2c58753"
    "389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59c13d57374729fc4e295362e2"
    "a5191204530428bc1522afa28ff5fe1655e304ca5bc8c27ad0e0c6a39dd4df28956c14b38c"
    "c93682cefe402bbd5e82d29c464e44eb5d37b48fc568dfe0cc6e8e16baea05e5135590f192"
    "94e73e8367b0216dbb815030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6"
    "dee639386c46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0"
    "de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b51b1c2cfe6e"
    "2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7b11a9098504fd5975bdf"
    "1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8af4b4c332a103a0cffa5deeb2d062ca"
    "3c215fd360026be7c5164f4a4424ef74948804d66f46487732c8202c795478647b4ea71d62"
    "7c086024cca354a41f0877b38f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed400"
    "80d334f7da52e9f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f4770"
    "3a5aef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0c1268b"
    "4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab620aa2396f56c0686"
    "b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6aa77bc1dcfb6fba59a77dfda9b7"
    "530dc0ca8648c8d973738e01bab8f08b4905e84aa4641bd602410cd97520265f2f231f2b35"
    "e15eb2fa04d2bd94d5a77abaf1e0e161010a990087f5b46ea988b2bc0512fda0fa923dadd6"
    "c45c5301d09483673265b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a318"
    "1954c39c649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be69"
    "a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b58536d109a713"
    "1c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589b80e566ad557ddef736719"
    "6b7227ea9870ef09ddfec79d6b9319a6879b5205d76bf7aba5acf33afb59d17fc54e68383d"
    "6be5a08e9b66da53dcde008bb294b8582bd132cdcc49959fdbc21e52721880c8ad0352c79f"
    "03a43bbd84c4cdfdc6c529005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e"
    "20bf62417198afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a0"
    "6b4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50ad18bd13"
    "fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f";

constexpr absl::string_view kMlDsa87PublicKeyPem =
    "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "5VvgYiIvi6kKl0BzMmsxISrs4KNKYA==\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kMlDsa87ExpectedBytesHex =
    "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124a73b323b9b"
    "a21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e7fc4d115e7e48da1896d"
    "5fe119b10dcddef62cb307954074b42336e52836de61da941f8d37ea68ac8106fabe190706"
    "79af6008537120f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c795"
    "59f21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1"
    "c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85"
    "f9b56b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449e91e23"
    "c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a333aa3ae7ce16b44"
    "0d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa91685de20af32c8b7e268c7f968"
    "77d0c85001135a4f0a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa"
    "1276ba61ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42fd31"
    "67f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e"
    "116cebe49229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b04"
    "39eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d870f1c02e5b2e3"
    "c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129db51f70740f31e63976b50"
    "c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571"
    "cce98b28da51db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb"
    "4c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a"
    "72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc"
    "3280a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4faa45bea"
    "8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df080053e6969b251e875ece"
    "c32cfc592840d69ab69a75e06b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52"
    "104437fed66f8ee3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722"
    "788a3d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f915f6a"
    "e82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf7275"
    "4e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce49731bd6"
    "650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618cc5694a6f0cee1"
    "04511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0c643d1c551b6f3f7a98d29b8"
    "5c2de05a65fa615eee16495bd90737672115b53e91c5d90028cf3f1a93953a153de53b4408"
    "4e9ccff6b736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd1"
    "a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bd"
    "b6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e91470"
    "54ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af3e24078bd0"
    "28b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239023897da0236630a53c0"
    "de7f435a19869792fab36e7b9e635760f09069e6432e700035ac2a02879fff0a1e1bec5220"
    "47193d94eb5df1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea"
    "2c47e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07a80d547"
    "16b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c8"
    "8f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e85095c8105"
    "4994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731ab38344bc1636df16"
    "bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29"
    "ef9bc0e87475ba663be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414"
    "ece7662927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc"
    "732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434"
    "d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b0472"
    "e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0bacb7c638d1b"
    "2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab3d21497528045c63262c8a"
    "42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f"
    "0ad76025bf0dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e"
    "8c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7"
    "b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e"
    "939528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11cfcaf4caa"
    "4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a9d329777a7084e4aad"
    "ae7122ce97005930528eb3c7f7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c"
    "3141fb5550fe3d0dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7ac"
    "ffd95fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f"
    "461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965be"
    "f1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f2e14"
    "9d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d6107faa229d6f6"
    "373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c81dcf1c9c31e5b06568f97544"
    "c17dc15698c5cb38983a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f6958"
    "7695cd6ff172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc697"
    "f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d180"
    "2762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c"
    "5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5fdfe4a8a5c"
    "35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88debc53a595103acce4f1"
    "cff18acff07afe1eb5716aa1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c9366"
    "1e00636b592704d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca"
    "28ffaa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947"
    "c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a3"
    "4a60";

TEST(SignaturePemKeysetReaderTest, ReadMlDsa44PublicKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add({std::string(kMlDsa44PublicKeyPem), kPemParamsMlDsa44});

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  if (!internal::IsBoringSsl()) {
    EXPECT_THAT((*reader)->Read(), StatusIs(absl::StatusCode::kUnimplemented));
    return;
  }

  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  EXPECT_THAT((*keyset)->key(), SizeIs(1));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());

  Keyset::Key expected_key;
  expected_key.set_key_id((*keyset)->primary_key_id());
  expected_key.set_status(KeyStatusType::ENABLED);
  expected_key.set_output_prefix_type(OutputPrefixType::RAW);

  KeyData* expected_keydata = expected_key.mutable_key_data();
  expected_keydata->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, "google.crypto.tink.MlDsaPublicKey"));
  expected_keydata->set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);

  MlDsaPublicKeyProto expected_proto;
  expected_proto.set_version(0);
  expected_proto.mutable_params()->set_ml_dsa_instance(
      MlDsaInstance::ML_DSA_44);
  expected_proto.set_key_value(test::HexDecodeOrDie(kMlDsa44ExpectedBytesHex));

  expected_keydata->set_value(expected_proto.SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key));
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsa44PublicKeyWithoutConstant) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add({std::string(kMlDsa44PublicKeyPem),
               {PemKeyType::PEM_ML_DSA, PemAlgorithm::ML_DSA, 10496,
                google::crypto::tink::HashType::UNKNOWN_HASH}});
  EXPECT_THAT(builder.Build(), IsOk());
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsa65PublicKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add({std::string(kMlDsa65PublicKeyPem), kPemParamsMlDsa65});

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  if (!internal::IsBoringSsl()) {
    EXPECT_THAT((*reader)->Read(), StatusIs(absl::StatusCode::kUnimplemented));
    return;
  }

  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  ASSERT_THAT((*keyset)->key(), SizeIs(1));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());

  Keyset::Key expected_key;
  expected_key.set_key_id((*keyset)->primary_key_id());
  expected_key.set_status(KeyStatusType::ENABLED);
  expected_key.set_output_prefix_type(OutputPrefixType::RAW);

  KeyData* expected_keydata = expected_key.mutable_key_data();
  expected_keydata->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, "google.crypto.tink.MlDsaPublicKey"));
  expected_keydata->set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);

  MlDsaPublicKeyProto expected_proto;
  expected_proto.set_version(0);
  expected_proto.mutable_params()->set_ml_dsa_instance(
      MlDsaInstance::ML_DSA_65);
  expected_proto.set_key_value(test::HexDecodeOrDie(kMlDsa65ExpectedBytesHex));

  expected_keydata->set_value(expected_proto.SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key));
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsa65PublicKeyWithoutConstant) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add({std::string(kMlDsa65PublicKeyPem),
               {PemKeyType::PEM_ML_DSA, PemAlgorithm::ML_DSA, 15616,
                google::crypto::tink::HashType::UNKNOWN_HASH}});
  EXPECT_THAT(builder.Build(), IsOk());
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsa87PublicKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add({std::string(kMlDsa87PublicKeyPem), kPemParamsMlDsa87});

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  if (!internal::IsBoringSsl()) {
    EXPECT_THAT((*reader)->Read(), StatusIs(absl::StatusCode::kUnimplemented));
    return;
  }

  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  EXPECT_THAT((*keyset)->key(), SizeIs(1));
  EXPECT_EQ((*keyset)->primary_key_id(), (*keyset)->key(0).key_id());

  Keyset::Key expected_key;
  expected_key.set_key_id((*keyset)->primary_key_id());
  expected_key.set_status(KeyStatusType::ENABLED);
  expected_key.set_output_prefix_type(OutputPrefixType::RAW);

  KeyData* expected_keydata = expected_key.mutable_key_data();
  expected_keydata->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, "google.crypto.tink.MlDsaPublicKey"));
  expected_keydata->set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);

  MlDsaPublicKeyProto expected_proto;
  expected_proto.set_version(0);
  expected_proto.mutable_params()->set_ml_dsa_instance(
      MlDsaInstance::ML_DSA_87);
  expected_proto.set_key_value(test::HexDecodeOrDie(kMlDsa87ExpectedBytesHex));

  expected_keydata->set_value(expected_proto.SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key));
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsaInvalidAlgorithmFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(CreatePemKey(kMlDsa65PublicKeyPem, PemKeyType::PEM_ML_DSA,
                           PemAlgorithm::ED25519, /*key_size_in_bits=*/0,
                           HashType::UNKNOWN_HASH));

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  EXPECT_THAT(reader->get()->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsaTruncatedKeyFails) {
  std::string truncated_pem = std::string(kMlDsa65PublicKeyPem);
  size_t footer_pos = truncated_pem.find("-----END PUBLIC KEY-----");
  ASSERT_NE(footer_pos, std::string::npos);
  truncated_pem.erase(footer_pos - 60, 60);

  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add({truncated_pem, kPemParamsMlDsa65});

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  EXPECT_THAT(reader->get()->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsaInvalidKeySizeFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  // Use a key size that is neither 10496, 15616 nor 20736.
  PemKeyParams invalid_params = {PemKeyType::PEM_ML_DSA, PemAlgorithm::ML_DSA,
                                 1024,
                                 google::crypto::tink::HashType::UNKNOWN_HASH};
  builder.Add({std::string(kMlDsa65PublicKeyPem), invalid_params});

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  EXPECT_THAT(reader->get()->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsaInvalidHashTypeFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  // Use a hash type that is not UNKNOWN_HASH.
  PemKeyParams invalid_params = {PemKeyType::PEM_ML_DSA, PemAlgorithm::ML_DSA,
                                 15616, google::crypto::tink::HashType::SHA256};
  builder.Add({std::string(kMlDsa65PublicKeyPem), invalid_params});

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  EXPECT_THAT(reader->get()->Read(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadMlDsaPrivateKeyUnsupported) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  builder.Add({std::string(kMlDsa65PublicKeyPem), kPemParamsMlDsa65});

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  EXPECT_THAT(reader->get()->Read(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(SignaturePemKeysetReaderTest, BuildKeysetHandleFromPrivateKeysetFails) {
  SignaturePemKeysetReaderBuilder builder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);

  builder.Add(CreatePemKey(kEcdsaP256PrivateKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_IEEE, /*key_size_in_bits=*/256,
                           HashType::SHA256));

  EXPECT_THAT(builder.BuildPublicKeysetHandle(), Not(IsOk()));
}

TEST(SignaturePemKeysetReaderTest, BuildKeysetHandleSuccess) {
  SignaturePemKeysetReaderBuilder builder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kEcdsaP256PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_IEEE, /*key_size_in_bits=*/256,
                           HashType::SHA256));

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      builder.BuildPublicKeysetHandle();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<EcdsaParameters> expected_parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  EcPoint expected_public_point(
      BigInteger(test::HexDecodeOrDie(kEcdsaP256PublicKeyX)),
      BigInteger(test::HexDecodeOrDie(kEcdsaP256PublicKeyY)));

  absl::StatusOr<EcdsaPublicKey> expected_public_key = EcdsaPublicKey::Create(
      *expected_parameters, expected_public_point,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  // Check that the handle has the expected key.
  ASSERT_EQ((*handle)->size(), 1);
  ASSERT_THAT((*handle)->Validate(), IsOk());
  std::shared_ptr<const Key> primary_key = (*handle)->GetPrimary().GetKey();
  ASSERT_THAT(primary_key, NotNull());
  EXPECT_THAT(*primary_key, Eq(*expected_public_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
