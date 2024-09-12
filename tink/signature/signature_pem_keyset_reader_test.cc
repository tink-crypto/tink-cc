// Copyright 2018 Google Inc.
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
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_util.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/config_v0.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/subtle/pem_parser_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::EqualsKey;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::EcdsaPrivateKey;
using ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::Ed25519PublicKey;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::RsaSsaPssPrivateKey;
using ::google::crypto::tink::RsaSsaPssPublicKey;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestWithParam;

// Generated with:
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
//   -out private-key.pem
constexpr absl::string_view kEcdsaP256PrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgx5oKGNLy+C0ibH2L\n"
    "H35Jr91rDpPtYETna5as8QqOTuyhRANCAATpqcaVqa2D905YgGTK0qvlIUJdvrqz\n"
    "v/UKB4nvbqKXC7qkmhvvEdTR4HJQr0U9d7kvF4IPyHqZDlwGTeCVKefX\n"
    "-----END PRIVATE KEY-----\n";

// Extracted from:
// openssl asn1parse -in private-key.pem -strparse 29
constexpr absl::string_view kEcdsaP256PrivateKeyD =
    "c79a0a18d2f2f82d226c7d8b1f7e49afdd6b0e93ed6044e76b96acf10a8e4eec";

// Generated with:
// openssl pkey -pubout -in private-key.pem -out public-key.pem
constexpr absl::string_view kEcdsaP256PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6anGlamtg/dOWIBkytKr5SFCXb66\n"
    "s7/1CgeJ726ilwu6pJob7xHU0eByUK9FPXe5LxeCD8h6mQ5cBk3glSnn1w==\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// openssl asn1parse -in public-key.pem -dump
//
// The X and Y values are embedded within the dumped 66 byte hex-encoded BIT
// STRING value. Discard the first two bytes, X is the next 32 bytes, Y is the
// remaining 32 bytes.
constexpr absl::string_view kEcdsaP256PublicKeyX =
    "e9a9c695a9ad83f74e588064cad2abe521425dbebab3bff50a0789ef6ea2970b";

constexpr absl::string_view kEcdsaP256PublicKeyY =
    "baa49a1bef11d4d1e07250af453d77b92f17820fc87a990e5c064de09529e7d7";

// Generated with:
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
//   -out private-key.pem
constexpr absl::string_view kEcdsaP384PrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAJgNcGVFAYtVGMTm+t\n"
    "M8qx1hhYQbtMVADtc4V2t5QxJcsEbXRwVigUbZAHM4o/Uw6hZANiAASXyFvUJHrY\n"
    "APdllv8nQJETEY/IB8Ps2Bp7xrmTBybU0f0lgeyud7rcT05+BZBgPFxlSUwFQNTy\n"
    "RsbMj+fYOa0wlM6vZnD3UtHesw8uoXhDrenPcyNHOm6eyjwmWIIlM8o=\n"
    "-----END PRIVATE KEY-----\n";

// Extracted from:
// openssl asn1parse -in private-key.pem -strparse 24
constexpr absl::string_view kEcdsaP384PrivateKeyD =
    "0980d706545018b5518c4e6fad33cab1d6185841bb4c5400ed738576b7943125cb046d7470"
    "5628146d9007338a3f530e";

// Generated with:
// openssl pkey -pubout -in private-key.pem -out public-key.pem
constexpr absl::string_view kEcdsaP384PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEl8hb1CR62AD3ZZb/J0CRExGPyAfD7Nga\n"
    "e8a5kwcm1NH9JYHsrne63E9OfgWQYDxcZUlMBUDU8kbGzI/n2DmtMJTOr2Zw91LR\n"
    "3rMPLqF4Q63pz3MjRzpunso8JliCJTPK\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// openssl asn1parse -in public-key.pem -dump
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
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 \
//   -out private-key.pem
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
// openssl asn1parse -in private-key.pem -strparse 24
constexpr absl::string_view kEcdsaP521PrivateKeyD =
    "0182755aa8b85967714fc1dcc6cba4b7f87411dfa5337e417bc700266e2f2cb3e056c06ab8"
    "8d5ca5b6d5c1a9f2d246c873e2b4ff0d13b11f3beb16d8fd15d3a47bfa";

// Generated with:
// openssl pkey -pubout -in private-key.pem -out public-key.pem
constexpr absl::string_view kEcdsaP521PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQADQG8ZGGXY7tifdJ9VH4QrjBLSf2N\n"
    "4ywvpa99FB02Trb6ptZed17b2ePdy5co51IT6MtLM18ty3NveTRqLz3K2KgAGqfQ\n"
    "AXwIpAfnJzPrMDsTwlmLyaMF3ngIRZzx/XKs7AwAMVYeQFtyb59/cwT0WZbdgzVq\n"
    "V93wfb9Ro0susKoaoc8=\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// openssl asn1parse -in public-key.pem -dump
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
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 \
//   | openssl pkey -pubout
constexpr absl::string_view kSecp256k1PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuDj/ROW8F3vyEYnQdmCC/J2EMiaIf8l2\n"
    "A3EQC37iCm/wyddb+6ezGmvKGXRJbutW3jVwcZVdg8Sxutqgshgy6Q==\n"
    "-----END PUBLIC KEY-----";

// Generated with:
// openssl genpkey -algorithm ed25519 | openssl pkey -pubout
constexpr absl::string_view kEd25519PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAfU0Of2FTpptiQrUiq77mhf2kQg+INLEIw72uNp71Sfo=\n"
    "-----END PUBLIC KEY-----\n";

// Extracted from:
// openssl asn1parse -in public-key.pem -dump
//
// The X is embedded within the dumped 33 byte hex-encoded BIT
// STRING value. Discard the first byte, X is the remaining 32 bytes.
constexpr absl::string_view kEd25519PublicKeyX =
    "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa";

// Generated with:
// openssl pkey -pubout -in private-key.pem
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
// openssl genpkey -quiet -algorithm rsa -pkeyopt rsa_keygen_bits:1024 \
//   | openssl pkey -pubout
constexpr absl::string_view kRsaPublicKey1024 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+lQMh614+1PINuxuGg8ks1DOD\n"
    "pxDGcbLm47clu/J3KE7htWxPaiLsVeowNURyYTLTscZ/AcD7p3ceVDWNwz5xtETI\n"
    "n2GcHy9Jaaph6HSYak2IOg0p5btxqbd9+UfqKhbmrtMNDNrdRJOq8Z7oLlvbzT0x\n"
    "pj37y294RWqIWhm1rwIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

// Generated with:
// openssl genpkey -quiet -algorithm rsa -pkeyopt rsa_keygen_bits:2048 \
//   -out private-key.pem
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
util::StatusOr<EcdsaPublicKey> GetExpectedEcdsaPublicKeyProto(
    EllipticCurveType curve, EcdsaSignatureEncoding encoding) {
  EcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);

  switch (curve) {
    case EllipticCurveType::NIST_P256: {
      public_key_proto.set_x(absl::HexStringToBytes(kEcdsaP256PublicKeyX));
      public_key_proto.set_y(absl::HexStringToBytes(kEcdsaP256PublicKeyY));
      public_key_proto.mutable_params()->set_hash_type(HashType::SHA256);
      break;
    }
    case EllipticCurveType::NIST_P384: {
      public_key_proto.set_x(absl::HexStringToBytes(kEcdsaP384PublicKeyX));
      public_key_proto.set_y(absl::HexStringToBytes(kEcdsaP384PublicKeyY));
      public_key_proto.mutable_params()->set_hash_type(HashType::SHA384);
      break;
    }
    case EllipticCurveType::NIST_P521: {
      public_key_proto.set_x(absl::HexStringToBytes(kEcdsaP521PublicKeyX));
      public_key_proto.set_y(absl::HexStringToBytes(kEcdsaP521PublicKeyY));
      public_key_proto.mutable_params()->set_hash_type(HashType::SHA512);
      break;
    }
    default: {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid curve type.");
    }
  }

  public_key_proto.mutable_params()->set_curve(curve);
  public_key_proto.mutable_params()->set_encoding(encoding);

  return public_key_proto;
}

util::StatusOr<EcdsaPrivateKey> GetExpectedEcdsaPrivateKeyProto(
    EllipticCurveType curve, EcdsaSignatureEncoding encoding) {
  util::StatusOr<EcdsaPublicKey> public_key;
  EcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);

  switch (curve) {
    case EllipticCurveType::NIST_P256: {
      private_key_proto.set_key_value(
          absl::HexStringToBytes(kEcdsaP256PrivateKeyD));
      break;
    }
    case EllipticCurveType::NIST_P384: {
      private_key_proto.set_key_value(
          absl::HexStringToBytes(kEcdsaP384PrivateKeyD));
      break;
    }
    case EllipticCurveType::NIST_P521: {
      private_key_proto.set_key_value(
          absl::HexStringToBytes(kEcdsaP521PrivateKeyD));
      break;
    }
    default: {
      return util::Status(absl::StatusCode::kInvalidArgument,
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
util::StatusOr<RsaSsaPssPublicKey> GetRsaSsaPssPublicKeyProto(
    absl::string_view pem_encoded_key, HashType hash_type,
    uint32_t key_version) {
  util::StatusOr<std::unique_ptr<internal::RsaPublicKey>> public_key =
      subtle::PemParser::ParseRsaPublicKey(pem_encoded_key);
  if (!public_key.ok()) {
    return public_key.status();
  }
  std::unique_ptr<internal::RsaPublicKey> key_subtle = *std::move(public_key);

  RsaSsaPssPublicKey public_key_proto;
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
util::StatusOr<RsaSsaPssPrivateKey> GetRsaSsaPssPrivateKeyProto(
    absl::string_view pem_encoded_key, HashType hash_type,
    uint32_t key_version) {
  // Parse the key with subtle::PemParser to make sure the proto key fields are
  // correct.
  util::StatusOr<std::unique_ptr<internal::RsaPrivateKey>> private_key =
      subtle::PemParser::ParseRsaPrivateKey(pem_encoded_key);
  if (!private_key.ok()) {
    return private_key.status();
  }
  std::unique_ptr<internal::RsaPrivateKey> key_subtle = *std::move(private_key);

  // Set the inner RSASSA-PSS public key and its parameters.
  RsaSsaPssPrivateKey private_key_proto;

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
  RsaSsaPssPublicKey* public_key_proto = private_key_proto.mutable_public_key();
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

  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  util::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
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
  util::StatusOr<EcdsaPrivateKey> ecdsa_private_key1 =
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
  util::StatusOr<RsaSsaPssPrivateKey> rsa_pss_private_key2 =
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

  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  util::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
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

  util::StatusOr<RsaSsaPssPublicKey> rsa_ssa_pss_pub_key =
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
  util::StatusOr<EcdsaPublicKey> pub_key = GetExpectedEcdsaPublicKeyProto(
      EllipticCurveType::NIST_P256, EcdsaSignatureEncoding::DER);
  ASSERT_THAT(pub_key, IsOk());
  expected_secondary_data->set_value(pub_key->SerializeAsString());
  EXPECT_THAT((*keyset)->key(1), EqualsKey(expected_secondary));
}

// Verify check on PEM array size not zero before creating a reader.
TEST(SignaturePemKeysetReaderTest, BuildEmptyPemArray) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  auto keyset_reader_or = builder.Build();
  EXPECT_THAT(keyset_reader_or.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Make sure ReadUnencrypted returns an UNSUPPORTED error as expected.
TEST(SignaturePemKeysetReaderTest, ReadEncryptedUnsupported) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA384));

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->ReadEncrypted().status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

// Verify parsing works correctly on valid input.
TEST(SignaturePemKeysetReaderTest, ReadRsaCorrectPublicKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA384));

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  auto keyset_or = keyset_reader->Read();
  ASSERT_THAT(keyset_or, IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_or).value();

  // Key manager to validate key type and key material type.
  RsaSsaPssVerifyKeyManager verify_key_manager;
  EXPECT_THAT(keyset->key(), SizeIs(1));
  EXPECT_EQ(keyset->primary_key_id(), keyset->key(0).key_id());

  // Build the expectedi primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id(keyset->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(verify_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      verify_key_manager.key_material_type());

  util::StatusOr<RsaSsaPssPublicKey> rsa_ssa_pss_pub_key =
      GetRsaSsaPssPublicKeyProto(kRsaPublicKey2048, HashType::SHA384,
                                 verify_key_manager.get_version());
  ASSERT_THAT(rsa_ssa_pss_pub_key, IsOk());
  expected_keydata1->set_value(rsa_ssa_pss_pub_key->SerializeAsString());
  EXPECT_THAT(keyset->key(0), EqualsKey(expected_key1));
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

  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
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

  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  EXPECT_THAT((*reader)->Read(), Not(IsOk()));
}

TEST(SignaturePemKeysetReaderTest, ReadRsaCorrectPrivateKey) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);

  builder.Add(CreatePemKey(kRsaPrivateKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA256));

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  auto keyset_or = keyset_reader->Read();
  ASSERT_THAT(keyset_or, IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_or).value();

  EXPECT_THAT(keyset->key(), SizeIs(1));
  EXPECT_EQ(keyset->primary_key_id(), keyset->key(0).key_id());

  // Key manager to validate key type and key material type.
  RsaSsaPssSignKeyManager sign_key_manager;

  // Build the expected primary key.
  Keyset::Key expected_key1;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key1.set_key_id(keyset->primary_key_id());
  expected_key1.set_status(KeyStatusType::ENABLED);
  expected_key1.set_output_prefix_type(OutputPrefixType::RAW);
  // Populate the expected primary key KeyData.
  KeyData* expected_keydata1 = expected_key1.mutable_key_data();
  expected_keydata1->set_type_url(sign_key_manager.get_key_type());
  expected_keydata1->set_key_material_type(
      sign_key_manager.key_material_type());
  util::StatusOr<RsaSsaPssPrivateKey> rsa_pss_private_key1 =
      GetRsaSsaPssPrivateKeyProto(kRsaPrivateKey2048, HashType::SHA256,
                                  sign_key_manager.get_version());
  ASSERT_THAT(rsa_pss_private_key1, IsOk());
  expected_keydata1->set_value(rsa_pss_private_key1->SerializeAsString());
  EXPECT_THAT(keyset->key(0), EqualsKey(expected_key1));
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
      util::StatusOr<std::unique_ptr<KeysetReader>> private_keyset_reader =
          private_keyset_reader_builder.Build();
      ASSERT_THAT(private_keyset_reader, IsOk());
      util::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
          CleartextKeysetHandle::Read(std::move(*private_keyset_reader));

      auto public_keyset_reader_builder = SignaturePemKeysetReaderBuilder(
          SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
      public_keyset_reader_builder.Add(
          CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA, pem_algorithm,
                       /*key_size_in_bits=*/2048, hash_type));
      util::StatusOr<std::unique_ptr<KeysetReader>> public_keyset_reader =
          public_keyset_reader_builder.Build();
      ASSERT_THAT(public_keyset_reader, IsOk());
      util::StatusOr<std::unique_ptr<KeysetHandle>> public_keyset_handle =
          CleartextKeysetHandle::Read(std::move(*public_keyset_reader));

      util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
          (*private_keyset_handle)
              ->GetPrimitive<PublicKeySign>(ConfigSignatureV0());
      ASSERT_THAT(sign, IsOk());
      util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
          (*public_keyset_handle)
              ->GetPrimitive<PublicKeyVerify>(ConfigSignatureV0());
      ASSERT_THAT(verify, IsOk());

      std::string data = "data";
      util::StatusOr<std::string> signature = (*sign)->Sign(data);
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

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
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

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as the key size is too small.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyTooSmall) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey1024, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/1024,
                           HashType::SHA256));

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
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

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT error as SHA1 is not allowed.
TEST(SignaturePemKeysetReaderTest, ReadRsaPublicKeyInvalidHashType) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kRsaPublicKey2048, PemKeyType::PEM_RSA,
                           PemAlgorithm::RSASSA_PSS, /*key_size_in_bits=*/2048,
                           HashType::SHA1));

  auto keyset_reader_or = builder.Build();
  ASSERT_THAT(keyset_reader_or, IsOk());
  std::unique_ptr<KeysetReader> keyset_reader =
      std::move(keyset_reader_or).value();

  EXPECT_THAT(keyset_reader->Read().status(),
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
  auto reader = builder.Build();
  ASSERT_THAT(reader, IsOk());

  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read, IsOk());
  std::unique_ptr<Keyset> keyset = std::move(keyset_read).value();

  EXPECT_THAT(keyset->key(), SizeIs(1));
  EXPECT_THAT(keyset->primary_key_id(), keyset->key(0).key_id());

  // Key manager to validate key type and key material type.
  EcdsaVerifyKeyManager key_manager;

  // Build the expected primary key.
  Keyset::Key expected_primary;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_primary.set_key_id(keyset->primary_key_id());
  expected_primary.set_status(KeyStatusType::ENABLED);
  expected_primary.set_output_prefix_type(OutputPrefixType::RAW);

  // Populate the expected primary key KeyData.
  KeyData* expected_primary_data = expected_primary.mutable_key_data();
  expected_primary_data->set_type_url(key_manager.get_key_type());
  expected_primary_data->set_key_material_type(key_manager.key_material_type());
  util::StatusOr<EcdsaPublicKey> pub_key =
      GetExpectedEcdsaPublicKeyProto(test_case.ec_curve, test_case.encoding);
  ASSERT_THAT(pub_key, IsOk());
  expected_primary_data->set_value(pub_key->SerializeAsString());
  EXPECT_THAT(keyset->key(0), EqualsKey(expected_primary));
}

TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadEcdsaCorrectPrivateKey) {
  const KeysetReaderTestCase& test_case = GetParam();
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  builder.Add(test_case.private_pem_key);

  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  util::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
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
  util::StatusOr<EcdsaPrivateKey> ecdsa_private_key1 =
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
  util::StatusOr<std::unique_ptr<KeysetReader>> private_keyset_reader =
      private_keyset_reader_builder.Build();
  ASSERT_THAT(private_keyset_reader, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
      CleartextKeysetHandle::Read(std::move(*private_keyset_reader));

  auto public_keyset_reader_builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  public_keyset_reader_builder.Add(test_case.public_pem_key);
  util::StatusOr<std::unique_ptr<KeysetReader>> public_keyset_reader =
      public_keyset_reader_builder.Build();
  ASSERT_THAT(public_keyset_reader, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_keyset_handle =
      CleartextKeysetHandle::Read(std::move(*public_keyset_reader));

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*private_keyset_handle)
          ->GetPrimitive<PublicKeySign>(ConfigSignatureV0());
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_keyset_handle)
          ->GetPrimitive<PublicKeyVerify>(ConfigSignatureV0());
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

// Expects an INVALID_ARGUMENT when passing a public key to a
// PublicKeySignPemKeysetReader.
TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadEcdsaPrivateKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_SIGN);
  builder.Add(GetParam().public_pem_key);

  util::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Expects an INVALID_ARGUMENT when passing a private key to a
// PublicKeyVerifyPemKeysetReader.
TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadEcdsaPublicKeyKeyTypeMismatch) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(GetParam().private_pem_key);

  util::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader = builder.Build();
  ASSERT_THAT(keyset_reader, IsOk());

  EXPECT_THAT((*keyset_reader)->Read().status(),
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

    auto reader = builder.Build();
    ASSERT_THAT(reader, IsOk());
    auto keyset_read = reader->get()->Read();
    ASSERT_THAT(keyset_read.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
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

    auto reader = builder.Build();
    ASSERT_THAT(reader, IsOk());
    auto keyset_read = reader->get()->Read();
    ASSERT_THAT(keyset_read.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(SignaturePemKeysetReaderTest, ReadECDSAWrongKeySize) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kEcdsaP256PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_IEEE, /*key_size_in_bits=*/512,
                           HashType::SHA256));

  auto reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EcdsaSignaturePemKeysetReaderTest, ReadECDSAWrongAlgorithm) {
  const KeysetReaderTestCase& test_case = GetParam();
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  PemKey pub_key = test_case.public_pem_key;
  pub_key.parameters.algorithm = PemAlgorithm::RSASSA_PSS;

  builder.Add(pub_key);

  auto reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  auto keyset_read = reader->get()->Read();
  ASSERT_THAT(keyset_read.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ED25519, /*key_size_in_bits=*/253,
                           HashType::SHA512));
  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  util::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  ASSERT_THAT(keyset, IsOk());

  Keyset::Key expected_key;
  // ID is randomly generated, so we simply copy the primary key ID.
  expected_key.set_key_id((*keyset)->primary_key_id());
  expected_key.set_status(KeyStatusType::ENABLED);
  expected_key.set_output_prefix_type(OutputPrefixType::RAW);
  Ed25519PublicKey expected_pub_key;
  expected_pub_key.set_key_value(absl::HexStringToBytes(kEd25519PublicKeyX));
  expected_key.mutable_key_data()->set_type_url(
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey");
  expected_key.mutable_key_data()->set_key_material_type(
      KeyData::ASYMMETRIC_PUBLIC);
  expected_key.mutable_key_data()->set_value(
      expected_pub_key.SerializeAsString());
  EXPECT_THAT((*keyset)->key(0), EqualsKey(expected_key));

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::ReadNoSecret((*keyset)->SerializeAsString());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*handle)->GetPrimitive<PublicKeyVerify>(ConfigSignatureV0());
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

      util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
      ASSERT_THAT(reader, IsOk());
      ASSERT_THAT(reader->get()->Read().status(),
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

    util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
    ASSERT_THAT(reader, IsOk());
    ASSERT_THAT(reader->get()->Read().status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519WInvalidKeyTypeFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_RSA,
                           PemAlgorithm::ED25519,
                           /*key_size_in_bits=*/253, HashType::SHA512));

  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  ASSERT_THAT(reader->get()->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadEd25519WInvalidKeySizeFails) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kEd25519PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ED25519,
                           /*key_size_in_bits=*/300, HashType::SHA512));

  util::StatusOr<std::unique_ptr<KeysetReader>> reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  ASSERT_THAT(reader->get()->Read().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignaturePemKeysetReaderTest, ReadSecp256k1ShouldFail) {
  auto builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);

  builder.Add(CreatePemKey(kSecp256k1PublicKey, PemKeyType::PEM_EC,
                           PemAlgorithm::ECDSA_IEEE, /*key_size_in_bits=*/256,
                           HashType::SHA256));

  auto reader = builder.Build();
  ASSERT_THAT(reader, IsOk());
  auto keyset_read = reader->get()->Read();
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
    EXPECT_THAT(keyset_read.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(keyset_read.status(),
                StatusIs(absl::StatusCode::kUnimplemented));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
