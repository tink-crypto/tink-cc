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
#include <new>
#include <random>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/keyset_reader.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/subtle/pem_parser_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/keyset_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::EcdsaParams;
using EcdsaPrivateKeyProto = ::google::crypto::tink::EcdsaPrivateKey;
using EcdsaPublicKeyProto = ::google::crypto::tink::EcdsaPublicKey;
using Ed25519PublicKeyProto = ::google::crypto::tink::Ed25519PublicKey;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::EncryptedKeyset;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using RsaSsaPkcs1PrivateKeyProto =
    ::google::crypto::tink::RsaSsaPkcs1PrivateKey;
using RsaSsaPkcs1PublicKeyProto = ::google::crypto::tink::RsaSsaPkcs1PublicKey;
using ::google::crypto::tink::RsaSsaPssParams;
using RsaSsaPssPrivateKeyProto = ::google::crypto::tink::RsaSsaPssPrivateKey;
using RsaSsaPssPublicKeyProto = ::google::crypto::tink::RsaSsaPssPublicKey;

namespace {

// Sets the parameters for an RSASSA-PSS key `parameters` given the PEM
// parameters `pem_parameters`.
absl::Status SetRsaSsaPssParameters(const PemKeyParams& pem_parameters,
                                    RsaSsaPssParams* parameters) {
  if (parameters == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Null parameters provided");
  }
  parameters->set_mgf1_hash(pem_parameters.hash_type);
  parameters->set_sig_hash(pem_parameters.hash_type);
  auto salt_len_or = util::Enums::HashLength(pem_parameters.hash_type);
  if (!salt_len_or.ok()) return salt_len_or.status();
  parameters->set_salt_length(salt_len_or.value());

  return absl::OkStatus();
}

// Sets the parameters for an ECDSA key `parameters` given the PEM
// parameters `pem_parameters`.
absl::Status SetEcdsaParameters(const PemKeyParams& pem_parameters,
                                EcdsaParams* parameters) {
  if (parameters == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Null parameters provided");
  }

  switch (pem_parameters.hash_type) {
    case HashType::SHA256: {
      if (pem_parameters.key_size_in_bits != 256) {
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            "For NIST_P256 ECDSA, the key should be 256 bits long.");
      }
      parameters->set_curve(EllipticCurveType::NIST_P256);
      break;
    }
    case HashType::SHA384: {
      if (pem_parameters.key_size_in_bits != 384) {
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            "For NIST_P384 ECDSA, the key should be 384 bits long.");
      }
      parameters->set_curve(EllipticCurveType::NIST_P384);
      break;
    }
    case HashType::SHA512: {
      if (pem_parameters.key_size_in_bits != 521) {
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            "For NIST_P521 ECDSA, the key should be 521 bits long.");
      }
      parameters->set_curve(EllipticCurveType::NIST_P521);
      break;
    }
    default: {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Only NIST_P256, NIST_P384, and NIST_P521 ECDSA are "
                          "supported. The hash type "
                          "should be SHA256, SHA384, or SHA512 respectively.");
    }
  }

  parameters->set_hash_type(pem_parameters.hash_type);

  switch (pem_parameters.algorithm) {
    case PemAlgorithm::ECDSA_IEEE: {
      parameters->set_encoding(
          google::crypto::tink::EcdsaSignatureEncoding::IEEE_P1363);
      break;
    }
    case PemAlgorithm::ECDSA_DER: {
      parameters->set_encoding(
          google::crypto::tink::EcdsaSignatureEncoding::DER);
      break;
    }
    default: {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Only ECDSA supported. The algorithm parameter should be "
          "ECDSA_IEEE or ECDSA_DER.");
    }
  }

  return absl::OkStatus();
}

// Creates a new Keyset::Key with ID `key_id`. The key has key data
// `key_data`, key type `key_type`, and key material type
// `key_material_type`.
Keyset::Key NewKeysetKey(uint32_t key_id, absl::string_view key_type,
                         const KeyData::KeyMaterialType& key_material_type,
                         const std::string& key_data) {
  Keyset::Key key;
  // Populate KeyData for the new key.
  key.set_key_id(key_id);
  key.set_status(KeyStatusType::ENABLED);
  // PEM keys don't add any prefix to signatures
  key.set_output_prefix_type(OutputPrefixType::RAW);
  KeyData* key_data_proto = key.mutable_key_data();
  key_data_proto->set_type_url(key_type.data(), key_type.size());
  key_data_proto->set_value(key_data);
  key_data_proto->set_key_material_type(key_material_type);
  return key;
}

// Construct a new ECDSA key proto from a subtle ECDSA private key
// `private_key_subtle`. The key is assigned version `key_version` and
// key parameters `parameters`.
absl::StatusOr<EcdsaPrivateKeyProto> NewEcdsaPrivateKey(
    const internal::EcKey& private_key_subtle, uint32_t key_version,
    const PemKeyParams& parameters) {
  EcdsaPrivateKeyProto private_key_proto;

  // ECDSA private key parameters.
  private_key_proto.set_version(key_version);
  private_key_proto.set_key_value(
      util::SecretDataAsStringView(private_key_subtle.priv));

  // Inner ECDSA public key.
  EcdsaPublicKeyProto* public_key_proto =
      private_key_proto.mutable_public_key();
  public_key_proto->set_x(private_key_subtle.pub_x);
  public_key_proto->set_y(private_key_subtle.pub_y);

  // ECDSA public key parameters.
  absl::Status set_parameter_status =
      SetEcdsaParameters(parameters, public_key_proto->mutable_params());
  if (!set_parameter_status.ok()) {
    return set_parameter_status;
  }

  return private_key_proto;
}

// Construct a new RSASSA-PSS key proto from a subtle RSA private key
// `private_key_subtle`; the key is assigned version `key_version` and
// key paramters `parameters`.
absl::StatusOr<RsaSsaPssPrivateKeyProto> NewRsaSsaPrivateKey(
    const internal::RsaPrivateKey& private_key_subtle, uint32_t key_version,
    const PemKeyParams& parameters) {
  RsaSsaPssPrivateKeyProto private_key_proto;

  // RSA Private key parameters.
  private_key_proto.set_version(key_version);
  private_key_proto.set_d(
      std::string(util::SecretDataAsStringView(private_key_subtle.d)));
  private_key_proto.set_p(
      std::string(util::SecretDataAsStringView(private_key_subtle.p)));
  private_key_proto.set_q(
      std::string(util::SecretDataAsStringView(private_key_subtle.q)));
  private_key_proto.set_dp(
      std::string(util::SecretDataAsStringView(private_key_subtle.dp)));
  private_key_proto.set_dq(
      std::string(util::SecretDataAsStringView(private_key_subtle.dq)));
  private_key_proto.set_crt(
      std::string(util::SecretDataAsStringView(private_key_subtle.crt)));

  // Inner RSA public key.
  RsaSsaPssPublicKeyProto* public_key_proto =
      private_key_proto.mutable_public_key();
  public_key_proto->set_version(key_version);
  public_key_proto->set_n(private_key_subtle.n);
  public_key_proto->set_e(private_key_subtle.e);

  // RSASSA-PSS public key parameters.
  auto set_parameter_status =
      SetRsaSsaPssParameters(parameters, public_key_proto->mutable_params());
  if (!set_parameter_status.ok()) {
    return set_parameter_status;
  }

  return private_key_proto;
}

// Construct a new RSASSA-PKCS1 key proto from a subtle RSA private key
// `private_key_subtle`; the key is assigned version `key_version` and
// key paramters `parameters`.
RsaSsaPkcs1PrivateKeyProto NewRsaSsaPkcs1PrivateKey(
    const internal::RsaPrivateKey& private_key_subtle, uint32_t key_version,
    const PemKeyParams& parameters) {
  RsaSsaPkcs1PrivateKeyProto private_key_proto;

  // RSA Private key parameters.
  private_key_proto.set_version(key_version);
  private_key_proto.set_d(
      std::string(util::SecretDataAsStringView(private_key_subtle.d)));
  private_key_proto.set_p(
      std::string(util::SecretDataAsStringView(private_key_subtle.p)));
  private_key_proto.set_q(
      std::string(util::SecretDataAsStringView(private_key_subtle.q)));
  private_key_proto.set_dp(
      std::string(util::SecretDataAsStringView(private_key_subtle.dp)));
  private_key_proto.set_dq(
      std::string(util::SecretDataAsStringView(private_key_subtle.dq)));
  private_key_proto.set_crt(
      std::string(util::SecretDataAsStringView(private_key_subtle.crt)));

  // Inner RSA Public key parameters.
  RsaSsaPkcs1PublicKeyProto* public_key_proto =
      private_key_proto.mutable_public_key();
  public_key_proto->set_version(key_version);
  public_key_proto->set_n(private_key_subtle.n);
  public_key_proto->set_e(private_key_subtle.e);

  // RSASSA-PKCS1 Public key parameters.
  public_key_proto->mutable_params()->set_hash_type(parameters.hash_type);

  return private_key_proto;
}

// Adds the PEM-encoded ECDSA private key `pem_key` to `keyset`.
absl::Status AddEcdsaPrivateKey(const PemKey& pem_key, Keyset& keyset) {
  absl::StatusOr<std::unique_ptr<internal::EcKey>> private_key_subtle =
      subtle::PemParser::ParseEcPrivateKey(pem_key.serialized_key);
  if (!private_key_subtle.ok()) return private_key_subtle.status();

  EcdsaSignKeyManager key_manager;
  absl::StatusOr<EcdsaPrivateKeyProto> private_key_proto = NewEcdsaPrivateKey(
      **private_key_subtle, key_manager.get_version(), pem_key.parameters);
  if (!private_key_proto.ok()) return private_key_proto.status();

  absl::Status key_validation_status =
      key_manager.ValidateKey(*private_key_proto);
  if (!key_validation_status.ok()) return key_validation_status;

  *keyset.add_key() = NewKeysetKey(
      GenerateUnusedKeyId(keyset), key_manager.get_key_type(),
      key_manager.key_material_type(), private_key_proto->SerializeAsString());

  return absl::OkStatus();
}

// Adds the PEM-encoded private key `pem_key` to `keyset`.
absl::Status AddRsaSsaPrivateKey(const PemKey& pem_key, Keyset& keyset) {
  // Try to parse the PEM RSA private key.
  auto private_key_subtle_or =
      subtle::PemParser::ParseRsaPrivateKey(pem_key.serialized_key);
  if (!private_key_subtle_or.ok()) return private_key_subtle_or.status();

  std::unique_ptr<internal::RsaPrivateKey> private_key_subtle =
      std::move(private_key_subtle_or).value();

  size_t modulus_size = private_key_subtle->n.length() * 8;
  if (pem_key.parameters.key_size_in_bits != modulus_size) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid RSA Key modulus size; found: ", modulus_size,
                     ", expected: ", pem_key.parameters.key_size_in_bits));
  }

  switch (pem_key.parameters.algorithm) {
    case PemAlgorithm::RSASSA_PSS: {
      RsaSsaPssSignKeyManager key_manager;
      auto private_key_proto_or = NewRsaSsaPrivateKey(
          *private_key_subtle, key_manager.get_version(), pem_key.parameters);
      if (!private_key_proto_or.ok()) return private_key_proto_or.status();
      const RsaSsaPssPrivateKeyProto& private_key_proto =
          private_key_proto_or.value();

      // Validate the key.
      auto key_validation_status = key_manager.ValidateKey(private_key_proto);
      if (!key_validation_status.ok()) return key_validation_status;

      *keyset.add_key() =
          NewKeysetKey(GenerateUnusedKeyId(keyset), key_manager.get_key_type(),
                       key_manager.key_material_type(),
                       private_key_proto.SerializeAsString());
      break;
    }
    case PemAlgorithm::RSASSA_PKCS1: {
      RsaSsaPkcs1SignKeyManager key_manager;
      RsaSsaPkcs1PrivateKeyProto private_key_proto = NewRsaSsaPkcs1PrivateKey(
          *private_key_subtle, key_manager.get_version(), pem_key.parameters);

      // Validate the key.
      auto key_validation_status = key_manager.ValidateKey(private_key_proto);
      if (!key_validation_status.ok()) return key_validation_status;

      *keyset.add_key() =
          NewKeysetKey(GenerateUnusedKeyId(keyset), key_manager.get_key_type(),
                       key_manager.key_material_type(),
                       private_key_proto.SerializeAsString());

      break;
    }
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid RSA algorithm ", pem_key.parameters.algorithm));
  }

  return absl::OkStatus();
}
// Parses a given PEM-encoded ECDSA public key `pem_key`, and adds it to the
// keyset `keyset`.
absl::Status AddEcdsaPublicKey(const PemKey& pem_key, Keyset& keyset) {
  // Parse the PEM string into a ECDSA public key.
  auto public_key_subtle_or =
      subtle::PemParser::ParseEcPublicKey(pem_key.serialized_key);
  if (!public_key_subtle_or.ok()) return public_key_subtle_or.status();

  std::unique_ptr<internal::EcKey> public_key_subtle =
      std::move(public_key_subtle_or).value();

  EcdsaPublicKeyProto ecdsa_key;
  EcdsaVerifyKeyManager key_manager;

  // ECDSA Public Key Parameters
  ecdsa_key.set_x(public_key_subtle->pub_x);
  ecdsa_key.set_y(public_key_subtle->pub_y);
  auto set_parameter_status =
      SetEcdsaParameters(pem_key.parameters, ecdsa_key.mutable_params());
  if (!set_parameter_status.ok()) return set_parameter_status;

  ecdsa_key.set_version(key_manager.get_version());

  // Validate the key.
  auto key_validation_status = key_manager.ValidateKey(ecdsa_key);
  if (!key_validation_status.ok()) return key_validation_status;

  *keyset.add_key() = NewKeysetKey(
      GenerateUnusedKeyId(keyset), key_manager.get_key_type(),
      key_manager.key_material_type(), ecdsa_key.SerializeAsString());

  return absl::OkStatus();
}

absl::Status AddEd25519PublicKey(const PemKey& pem_key, Keyset& keyset) {
  if (pem_key.parameters.hash_type != HashType::SHA512) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Invalid ed25519 hash type: ",
                                     pem_key.parameters.hash_type));
  }
  if (pem_key.parameters.key_size_in_bits != 253) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Invalid ed25519 key size: ",
                                     pem_key.parameters.key_size_in_bits));
  }
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> ecc_public_key =
      subtle::PemParser::ParseEd25519PublicKey(pem_key.serialized_key);
  if (!ecc_public_key.ok()) {
    return ecc_public_key.status();
  }

  Ed25519PublicKeyProto ed25519_key;
  Ed25519VerifyKeyManager key_manager;

  ed25519_key.set_key_value((*ecc_public_key)->public_key);
  ed25519_key.set_version(key_manager.get_version());

  *keyset.add_key() = NewKeysetKey(
      GenerateUnusedKeyId(keyset), key_manager.get_key_type(),
      key_manager.key_material_type(), ed25519_key.SerializeAsString());

  return absl::OkStatus();
}

// Parses a given PEM-encoded RSA public key `pem_key`, and adds it to the
// keyset `keyset`.
absl::Status AddRsaSsaPublicKey(const PemKey& pem_key, Keyset& keyset) {
  // Parse the PEM string into a RSA public key.
  auto public_key_subtle_or =
      subtle::PemParser::ParseRsaPublicKey(pem_key.serialized_key);
  if (!public_key_subtle_or.ok()) return public_key_subtle_or.status();

  std::unique_ptr<internal::RsaPublicKey> public_key_subtle =
      std::move(public_key_subtle_or).value();

  // Check key length is as expected.
  size_t modulus_size = public_key_subtle->n.length() * 8;
  if (pem_key.parameters.key_size_in_bits != modulus_size) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid RSA Key modulus size; found ", modulus_size,
                     ", expected ", pem_key.parameters.key_size_in_bits));
  }

  switch (pem_key.parameters.algorithm) {
    case PemAlgorithm::RSASSA_PSS: {
      RsaSsaPssPublicKeyProto public_key_proto;
      RsaSsaPssVerifyKeyManager key_manager;

      // RSA Public key paramters.
      public_key_proto.set_e(public_key_subtle->e);
      public_key_proto.set_n(public_key_subtle->n);

      // RSASSA-PSS Public key parameters.
      auto set_parameter_status = SetRsaSsaPssParameters(
          pem_key.parameters, public_key_proto.mutable_params());
      if (!set_parameter_status.ok()) return set_parameter_status;
      public_key_proto.set_version(key_manager.get_version());

      // Validate the key.
      auto key_validation_status = key_manager.ValidateKey(public_key_proto);
      if (!key_validation_status.ok()) return key_validation_status;

      *keyset.add_key() =
          NewKeysetKey(GenerateUnusedKeyId(keyset), key_manager.get_key_type(),
                       key_manager.key_material_type(),
                       public_key_proto.SerializeAsString());

      break;
    }
    case PemAlgorithm::RSASSA_PKCS1: {
      RsaSsaPkcs1PublicKeyProto public_key_proto;
      RsaSsaPkcs1VerifyKeyManager key_manager;

      // RSA Public key paramters.
      public_key_proto.set_e(public_key_subtle->e);
      public_key_proto.set_n(public_key_subtle->n);

      // RSASSA-PKCS1 Public key parameters.
      public_key_proto.mutable_params()->set_hash_type(
          pem_key.parameters.hash_type);
      public_key_proto.set_version(key_manager.get_version());

      // Validate the key.
      auto key_validation_status = key_manager.ValidateKey(public_key_proto);
      if (!key_validation_status.ok()) return key_validation_status;

      *keyset.add_key() =
          NewKeysetKey(GenerateUnusedKeyId(keyset), key_manager.get_key_type(),
                       key_manager.key_material_type(),
                       public_key_proto.SerializeAsString());
      break;
    }
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid RSA algorithm ", pem_key.parameters.algorithm));
  }
  return absl::OkStatus();
}

}  // namespace

void SignaturePemKeysetReaderBuilder::Add(const PemKey& pem_serialized_key) {
  pem_serialized_keys_.push_back(pem_serialized_key);
}

absl::StatusOr<std::unique_ptr<KeysetReader>>
SignaturePemKeysetReaderBuilder::Build() {
  if (pem_serialized_keys_.empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Empty array of PEM-encoded keys");
  }

  switch (pem_reader_type_) {
    case PUBLIC_KEY_SIGN: {
      return absl::WrapUnique<KeysetReader>(
          new PublicKeySignPemKeysetReader(pem_serialized_keys_));
    }
    case PUBLIC_KEY_VERIFY: {
      return absl::WrapUnique<KeysetReader>(
          new PublicKeyVerifyPemKeysetReader(pem_serialized_keys_));
    }
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "Unknown pem_reader_type_");
}

absl::StatusOr<std::unique_ptr<Keyset>> PublicKeySignPemKeysetReader::Read() {
  if (pem_serialized_keys_.empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Empty array of PEM-encoded keys");
  }

  auto keyset = absl::make_unique<Keyset>();
  for (const PemKey& pem_key : pem_serialized_keys_) {
    // Parse and add the new key to the keyset.
    switch (pem_key.parameters.key_type) {
      case PemKeyType::PEM_RSA: {
        auto add_rsassa_pss_status = AddRsaSsaPrivateKey(pem_key, *keyset);
        if (!add_rsassa_pss_status.ok()) return add_rsassa_pss_status;
        break;
      }
      case PemKeyType::PEM_EC: {
        auto add_ecdsa_status = AddEcdsaPrivateKey(pem_key, *keyset);
        if (!add_ecdsa_status.ok()) return add_ecdsa_status;
        break;
      }
    }
  }

  // Set the 1st key as primary.
  keyset->set_primary_key_id(keyset->key(0).key_id());

  return std::move(keyset);
}

absl::StatusOr<std::unique_ptr<Keyset>> PublicKeyVerifyPemKeysetReader::Read() {
  if (pem_serialized_keys_.empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Empty array of PEM-encoded keys");
  }

  auto keyset = absl::make_unique<Keyset>();
  for (const PemKey& pem_key : pem_serialized_keys_) {
    // Parse and add the new key to the keyset.
    switch (pem_key.parameters.key_type) {
      case PemKeyType::PEM_RSA: {
        auto add_rsassa_pss_status = AddRsaSsaPublicKey(pem_key, *keyset);
        if (!add_rsassa_pss_status.ok()) return add_rsassa_pss_status;
        break;
      }
      case PemKeyType::PEM_EC:
        switch (pem_key.parameters.algorithm) {
          case PemAlgorithm::ECDSA_IEEE:
          case PemAlgorithm::ECDSA_DER: {
            auto add_ecdsa_status = AddEcdsaPublicKey(pem_key, *keyset);
            if (!add_ecdsa_status.ok()) return add_ecdsa_status;
            break;
          }
          case PemAlgorithm::ED25519: {
            auto add_ed25519_status = AddEd25519PublicKey(pem_key, *keyset);
            if (!add_ed25519_status.ok()) return add_ed25519_status;
            break;
          }
          default:
            return absl::Status(absl::StatusCode::kInvalidArgument,
                                absl::StrCat("Invalid ECC algorithm ",
                                             pem_key.parameters.algorithm));
        }
    }
  }

  // Set the 1st key as primary.
  keyset->set_primary_key_id(keyset->key(0).key_id());

  return std::move(keyset);
}

absl::StatusOr<std::unique_ptr<EncryptedKeyset>>
SignaturePemKeysetReader::ReadEncrypted() {
  return absl::Status(absl::StatusCode::kUnimplemented,
                      "Reading Encrypted PEM is not supported");
}

}  // namespace tink
}  // namespace crypto
