// Copyright 2021 Google LLC
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

#include "tink/jwt/jwk_set_converter.h"

#include <cstdint>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "google/protobuf/struct.pb.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/ec.h"
#include "tink/binary_keyset_writer.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/keyset_handle.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/keyset_util.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaPublicKey;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1PublicKey;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPssPublicKey;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::Keyset_Key;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::google::protobuf::ListValue;
using ::google::protobuf::Struct;
using ::google::protobuf::Value;

namespace {

bool HasItem(const Struct& key_struct, absl::string_view name) {
  return key_struct.fields().find(std::string(name)) !=
         key_struct.fields().end();
}

absl::StatusOr<std::string> GetStringItem(const Struct& key_struct,
                                          absl::string_view name) {
  auto it = key_struct.fields().find(std::string(name));
  if (it == key_struct.fields().end()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "not found");
  }
  if (it->second.kind_case() != Value::kStringValue) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "is not a string");
  }
  return it->second.string_value();
}

absl::Status ExpectStringItem(const Struct& key_struct, absl::string_view name,
                              absl::string_view value) {
  absl::StatusOr<std::string> item = GetStringItem(key_struct, name);
  if (!item.ok()) {
    return item.status();
  }
  if (*item != value) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "unexpected value");
  }
  return absl::OkStatus();
}

absl::Status ValidateUseIsSig(const Struct& key_struct) {
  if (!HasItem(key_struct, "use")) {
    return absl::OkStatus();
  }
  return ExpectStringItem(key_struct, "use", "sig");
}

absl::Status ValidateKeyOpsIsVerify(const Struct& key_struct) {
  if (!HasItem(key_struct, "key_ops")) {
    return absl::OkStatus();
  }
  auto it = key_struct.fields().find("key_ops");
  if (it == key_struct.fields().end()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_ops not found");
  }
  if (it->second.kind_case() != Value::kListValue) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_ops is not a list");
  }
  const ListValue& key_ops_list = it->second.list_value();
  if (key_ops_list.values_size() != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_ops size is not 1");
  }
  const Value & value = key_ops_list.values().Get(0);
  if (value.kind_case() != Value::kStringValue) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_ops item is not a string");
  }
  if (value.string_value() != "verify") {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_ops is not equal to [\"verify\"]");
  }
  return absl::OkStatus();
}

absl::StatusOr<KeyData> RsPublicKeyDataFromKeyStruct(const Struct& key_struct) {
  JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);

  absl::StatusOr<std::string> alg = GetStringItem(key_struct, "alg");
  if (!alg.ok()) {
    return alg.status();
  }
  if (*alg == "RS256") {
    public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  } else if (*alg == "RS384") {
    public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS384);
  } else if (*alg == "RS512") {
    public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS512);
  } else {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid alg");
  }

  if (HasItem(key_struct, "p") || HasItem(key_struct, "q") ||
      HasItem(key_struct, "dq") || HasItem(key_struct, "dp") ||
      HasItem(key_struct, "d") || HasItem(key_struct, "qi")) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "private keys cannot be converted");
  }
  absl::Status status_kty = ExpectStringItem(key_struct, "kty", "RSA");
  if (!status_kty.ok()) {
    return status_kty;
  }
  absl::Status status_use = ValidateUseIsSig(key_struct);
  if (!status_use.ok()) {
    return status_use;
  }
  absl::Status status_key_ops = ValidateKeyOpsIsVerify(key_struct);
  if (!status_key_ops.ok()) {
    return status_key_ops;
  }

  absl::StatusOr<std::string> e = GetStringItem(key_struct, "e");
  if (!e.ok()) {
    return e.status();
  }
  std::string decoded_e;
  if (!absl::WebSafeBase64Unescape(*e, &decoded_e)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "failed to decode e");
  }
  public_key_proto.set_e(decoded_e);

  absl::StatusOr<std::string> n = GetStringItem(key_struct, "n");
  if (!n.ok()) {
    return n.status();
  }
  std::string decoded_n;
  if (!absl::WebSafeBase64Unescape(*n, &decoded_n)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "failed to decode n");
  }
  public_key_proto.set_n(decoded_n);

  if (HasItem(key_struct, "kid")) {
    absl::StatusOr<std::string> kid = GetStringItem(key_struct, "kid");
    if (!kid.ok()) {
      return kid.status();
    }
    public_key_proto.mutable_custom_kid()->set_value(*kid);
  }
  KeyData key_data_proto;
  key_data_proto.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey");
  key_data_proto.set_value(public_key_proto.SerializeAsString());
  key_data_proto.set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);
  return key_data_proto;
}

absl::StatusOr<KeyData> PsPublicKeyDataFromKeyStruct(const Struct& key_struct) {
  JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);

  absl::StatusOr<std::string> alg = GetStringItem(key_struct, "alg");
  if (!alg.ok()) {
    return alg.status();
  }
  if (*alg == "PS256") {
    public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  } else if (*alg == "PS384") {
    public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS384);
  } else if (*alg == "PS512") {
    public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS512);
  } else {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid alg");
  }

  if (HasItem(key_struct, "p") || HasItem(key_struct, "q") ||
      HasItem(key_struct, "dq") || HasItem(key_struct, "dp") ||
      HasItem(key_struct, "d") || HasItem(key_struct, "qi")) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "private keys cannot be converted");
  }
  absl::Status status_kty = ExpectStringItem(key_struct, "kty", "RSA");
  if (!status_kty.ok()) {
    return status_kty;
  }
  absl::Status status_use = ValidateUseIsSig(key_struct);
  if (!status_use.ok()) {
    return status_use;
  }
  absl::Status status_key_ops = ValidateKeyOpsIsVerify(key_struct);
  if (!status_key_ops.ok()) {
    return status_key_ops;
  }

  absl::StatusOr<std::string> e = GetStringItem(key_struct, "e");
  if (!e.ok()) {
    return e.status();
  }
  std::string decoded_e;
  if (!absl::WebSafeBase64Unescape(*e, &decoded_e)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "failed to decode e");
  }
  public_key_proto.set_e(decoded_e);

  absl::StatusOr<std::string> n = GetStringItem(key_struct, "n");
  if (!n.ok()) {
    return n.status();
  }
  std::string decoded_n;
  if (!absl::WebSafeBase64Unescape(*n, &decoded_n)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "failed to decode n");
  }
  public_key_proto.set_n(decoded_n);

  if (HasItem(key_struct, "kid")) {
    absl::StatusOr<std::string> kid = GetStringItem(key_struct, "kid");
    if (!kid.ok()) {
      return kid.status();
    }
    public_key_proto.mutable_custom_kid()->set_value(*kid);
  }
  KeyData key_data_proto;
  key_data_proto.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey");
  key_data_proto.set_value(public_key_proto.SerializeAsString());
  key_data_proto.set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);
  return key_data_proto;
}

absl::StatusOr<KeyData> EsPublicKeyDataFromKeyStruct(const Struct& key_struct) {
  JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);

  absl::StatusOr<std::string> alg = GetStringItem(key_struct, "alg");
  if (!alg.ok()) {
    return alg.status();
  }
  absl::StatusOr<std::string> curve = GetStringItem(key_struct, "crv");
  if (!curve.ok()) {
    return curve.status();
  }
  if (*alg == "ES256") {
    if (*curve != "P-256") {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "crv is not equal to P-256");
    }
    public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  } else if (*alg == "ES384") {
    if (*curve != "P-384") {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "crv is not equal to P-384");
    }
    public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES384);
  } else if (*alg == "ES512") {
    if (*curve != "P-521") {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "crv is not equal to P-521");
    }
    public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES512);
  } else {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid alg");
  }

  if (HasItem(key_struct, "d")) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "private keys cannot be converted");
  }
  absl::Status status_kty = ExpectStringItem(key_struct, "kty", "EC");
  if (!status_kty.ok()) {
    return status_kty;
  }
  absl::Status status_use = ValidateUseIsSig(key_struct);
  if (!status_use.ok()) {
    return status_use;
  }
  absl::Status status_key_ops = ValidateKeyOpsIsVerify(key_struct);
  if (!status_key_ops.ok()) {
    return status_key_ops;
  }

  absl::StatusOr<std::string> x = GetStringItem(key_struct, "x");
  if (!x.ok()) {
    return x.status();
  }
  std::string decoded_x;
  if (!absl::WebSafeBase64Unescape(*x, &decoded_x)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "failed to decode x");
  }
  public_key_proto.set_x(decoded_x);

  absl::StatusOr<std::string> y = GetStringItem(key_struct, "y");
  if (!y.ok()) {
    return y.status();
  }
  std::string decoded_y;
  if (!absl::WebSafeBase64Unescape(*y, &decoded_y)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "failed to decode y");
  }
  public_key_proto.set_y(decoded_y);

  if (HasItem(key_struct, "kid")) {
    absl::StatusOr<std::string> kid = GetStringItem(key_struct, "kid");
    if (!kid.ok()) {
      return kid.status();
    }
    public_key_proto.mutable_custom_kid()->set_value(*kid);
  }
  KeyData key_data_proto;
  key_data_proto.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey");
  key_data_proto.set_value(public_key_proto.SerializeAsString());
  key_data_proto.set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);
  return key_data_proto;
}

// RFC 7518 specifies a fixed sized encoding for the x and y coordinates from
// SEC 1 https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2
absl::StatusOr<std::pair<std::string, std::string>> Sec1EncodeCoordinates(
    absl::string_view x, absl::string_view y,
    subtle::EllipticCurveType curve_type) {
  absl::StatusOr<int32_t> encoded_size =
      internal::EcFieldSizeInBytes(curve_type);
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> point =
      internal::GetEcPoint(curve_type, x, y);
  if (!point.ok()) {
    return point.status();
  }
  // The uncompressed point is encoded as 0x04 || x || y.
  absl::StatusOr<std::string> uncompressed_point = internal::EcPointEncode(
      curve_type, subtle::EcPointFormat::UNCOMPRESSED, (*point).get());
  if (!uncompressed_point.ok()) {
    return uncompressed_point.status();
  }
  if ((*uncompressed_point).size() != *encoded_size * 2 + 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "invalid encoded size");
  }
  return std::make_pair(
      uncompressed_point.value().substr(1, *encoded_size),
      uncompressed_point.value().substr(*encoded_size + 1, *encoded_size));
}

}  // namespace

absl::StatusOr<std::unique_ptr<KeysetHandle>> JwkSetToPublicKeysetHandle(
    absl::string_view jwk_set) {
  absl::StatusOr<Struct> jwk_set_struct =
      jwt_internal::JsonStringToProtoStruct(jwk_set);
  if (!jwk_set_struct.ok()) {
    return jwk_set_struct.status();
  }
  auto it = jwk_set_struct->fields().find("keys");
  if (it == jwk_set_struct->fields().end()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "keys not found");
  }
  if (it->second.kind_case() != Value::kListValue) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "keys is not a list");
  }
  if (it->second.list_value().values_size() <= 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "keys list is empty");
  }
  uint32_t last_key_id = 0;
  Keyset keyset;
  for (const Value& value : it->second.list_value().values()) {
    if (value.kind_case() != Value::kStructValue) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "key is not a JSON object");
    }
    const Struct& key_struct = value.struct_value();

    absl::StatusOr<std::string> alg = GetStringItem(key_struct, "alg");
    if (!alg.ok()) {
      return alg.status();
    }
    absl::string_view alg_prefix = absl::string_view(*alg).substr(0, 2);

    // Add to keyset
    Keyset_Key* key = keyset.add_key();
    uint32_t key_id = GenerateUnusedKeyId(keyset);
    key->set_key_id(key_id);
    key->set_status(KeyStatusType::ENABLED);
    key->set_output_prefix_type(OutputPrefixType::RAW);

    if (alg_prefix == "RS") {
      absl::StatusOr<KeyData> key_data =
          RsPublicKeyDataFromKeyStruct(key_struct);
      if (!key_data.ok()) {
        return key_data.status();
      }
      *key->mutable_key_data() = *key_data;
    } else if (alg_prefix == "PS") {
      absl::StatusOr<KeyData> key_data =
          PsPublicKeyDataFromKeyStruct(key_struct);
      if (!key_data.ok()) {
        return key_data.status();
      }
      *key->mutable_key_data() = *key_data;
    } else if (alg_prefix == "ES") {
      absl::StatusOr<KeyData> key_data =
          EsPublicKeyDataFromKeyStruct(key_struct);
      if (!key_data.ok()) {
        return key_data.status();
      }
      *key->mutable_key_data() = *key_data;
    } else {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "invalid alg prefix");
    }
    last_key_id = key_id;
  }
  keyset.set_primary_key_id(last_key_id);
  return KeysetHandle::ReadNoSecret(keyset.SerializeAsString());
}

void AddStringEntry(Struct* key, absl::string_view name,
                    absl::string_view value) {
  auto val = key->mutable_fields()->insert({std::string(name), Value()});
  val.first->second.set_string_value(value);
}

void AddKeyOpsVerifyEntry(Struct* key) {
  auto key_ops = key->mutable_fields()->insert({"key_ops", Value()});
  key_ops.first->second.mutable_list_value()->add_values()->set_string_value(
      "verify");
}

absl::StatusOr<Struct> EsPublicKeyToKeyStruct(const Keyset_Key& key) {
  JwtEcdsaPublicKey public_key;
  if (!public_key.ParseFromString(key.key_data().value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "parse JwtEcdsaPublicKey failed");
  }

  Struct output_key;
  subtle::EllipticCurveType curve_type;
  switch (public_key.algorithm()) {
    case JwtEcdsaAlgorithm::ES256:
      AddStringEntry(&output_key, "crv", "P-256");
      AddStringEntry(&output_key, "alg", "ES256");
      curve_type = subtle::EllipticCurveType::NIST_P256;
      break;
    case JwtEcdsaAlgorithm::ES384:
      AddStringEntry(&output_key, "crv", "P-384");
      AddStringEntry(&output_key, "alg", "ES384");
      curve_type = subtle::EllipticCurveType::NIST_P384;
      break;
    case JwtEcdsaAlgorithm::ES512:
      AddStringEntry(&output_key, "crv", "P-521");
      AddStringEntry(&output_key, "alg", "ES512");
      curve_type = subtle::EllipticCurveType::NIST_P521;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "unknown JwtEcdsaAlgorithm");
  }

  absl::StatusOr<std::pair<std::string, std::string>> encoded_point =
      Sec1EncodeCoordinates(public_key.x(), public_key.y(), curve_type);
  if (!encoded_point.ok()) {
    return encoded_point.status();
  }

  AddStringEntry(&output_key, "kty", "EC");
  AddStringEntry(&output_key, "x",
                 absl::WebSafeBase64Escape((*encoded_point).first));
  AddStringEntry(&output_key, "y",
                 absl::WebSafeBase64Escape((*encoded_point).second));
  AddStringEntry(&output_key, "use", "sig");
  AddKeyOpsVerifyEntry(&output_key);

  absl::optional<std::string> kid =
      jwt_internal::GetKid(key.key_id(), key.output_prefix_type());
  if (kid.has_value()) {
    AddStringEntry(&output_key, "kid", kid.value());
  } else if (public_key.has_custom_kid()) {
    AddStringEntry(&output_key, "kid", public_key.custom_kid().value());
  }
  return output_key;
}

absl::StatusOr<Struct> RsPublicKeyToKeyStruct(const Keyset_Key& key) {
  JwtRsaSsaPkcs1PublicKey public_key;
  if (!public_key.ParseFromString(key.key_data().value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "parse JwtRsaSsaPkcs1PublicKey failed");
  }

  Struct output_key;

  switch (public_key.algorithm()) {
    case JwtRsaSsaPkcs1Algorithm::RS256:
      AddStringEntry(&output_key, "alg", "RS256");
      break;
    case JwtRsaSsaPkcs1Algorithm::RS384:
      AddStringEntry(&output_key, "alg", "RS384");
      break;
    case JwtRsaSsaPkcs1Algorithm::RS512:
      AddStringEntry(&output_key, "alg", "RS512");
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "unknown JwtRsaSsaPkcs1Algorithm");
  }

  AddStringEntry(&output_key, "kty", "RSA");
  AddStringEntry(&output_key, "e", absl::WebSafeBase64Escape(public_key.e()));
  AddStringEntry(&output_key, "n", absl::WebSafeBase64Escape(public_key.n()));
  AddStringEntry(&output_key, "use", "sig");
  AddKeyOpsVerifyEntry(&output_key);

  absl::optional<std::string> kid =
      jwt_internal::GetKid(key.key_id(), key.output_prefix_type());
  if (kid.has_value()) {
    AddStringEntry(&output_key, "kid", kid.value());
  } else if (public_key.has_custom_kid()) {
    AddStringEntry(&output_key, "kid", public_key.custom_kid().value());
  }
  return output_key;
}

absl::StatusOr<Struct> PsPublicKeyToKeyStruct(const Keyset_Key& key) {
  JwtRsaSsaPssPublicKey public_key;
  if (!public_key.ParseFromString(key.key_data().value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "parse JwtRsaSsaPkcs1PublicKey failed");
  }

  Struct output_key;

  switch (public_key.algorithm()) {
    case JwtRsaSsaPssAlgorithm::PS256:
      AddStringEntry(&output_key, "alg", "PS256");
      break;
    case JwtRsaSsaPssAlgorithm::PS384:
      AddStringEntry(&output_key, "alg", "PS384");
      break;
    case JwtRsaSsaPssAlgorithm::PS512:
      AddStringEntry(&output_key, "alg", "PS512");
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "unknown JwtRsaSsaPkcs1Algorithm");
  }

  AddStringEntry(&output_key, "kty", "RSA");
  AddStringEntry(&output_key, "e", absl::WebSafeBase64Escape(public_key.e()));
  AddStringEntry(&output_key, "n", absl::WebSafeBase64Escape(public_key.n()));
  AddStringEntry(&output_key, "use", "sig");
  AddKeyOpsVerifyEntry(&output_key);

  absl::optional<std::string> kid =
      jwt_internal::GetKid(key.key_id(), key.output_prefix_type());
  if (kid.has_value()) {
    AddStringEntry(&output_key, "kid", kid.value());
  } else if (public_key.has_custom_kid()) {
    AddStringEntry(&output_key, "kid", public_key.custom_kid().value());
  }
  return output_key;
}

absl::StatusOr<std::string> JwkSetFromPublicKeysetHandle(
    const KeysetHandle& keyset_handle) {
  std::stringbuf keyset_buf;
  absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset_buf));
  if (!writer.ok()) {
    return writer.status();
  }
  absl::Status status = keyset_handle.WriteNoSecret((*writer).get());
  if (!status.ok()) {
    return status;
  }
  Keyset keyset;
  if (!keyset.ParseFromString(keyset_buf.str())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "parse Keyset failed");
  }

  Struct output;
  auto insertion_result = output.mutable_fields()->insert({"keys", Value()});
  ListValue* keys_list = insertion_result.first->second.mutable_list_value();

  for (const Keyset::Key& key : keyset.key()) {
    if (key.status() != KeyStatusType::ENABLED) {
      continue;
    }
    if ((key.output_prefix_type() != OutputPrefixType::RAW) &&
        (key.output_prefix_type() != OutputPrefixType::TINK)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unknown output prefix type");
    }

    if (key.key_data().key_material_type() != KeyData::ASYMMETRIC_PUBLIC) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Only asymmetric public keys are supported");
    }
    if (key.key_data().type_url() ==
        "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey") {
      absl::StatusOr<Struct> output_key = EsPublicKeyToKeyStruct(key);
      if (!output_key.ok()) {
        return output_key.status();
      }
      *keys_list->add_values()->mutable_struct_value() = *output_key;
    } else if (key.key_data().type_url() ==
               "type.googleapis.com/"
               "google.crypto.tink.JwtRsaSsaPkcs1PublicKey") {
      absl::StatusOr<Struct> output_key = RsPublicKeyToKeyStruct(key);
      if (!output_key.ok()) {
        return output_key.status();
      }
      *keys_list->add_values()->mutable_struct_value() = *output_key;
    } else if (key.key_data().type_url() ==
               "type.googleapis.com/"
               "google.crypto.tink.JwtRsaSsaPssPublicKey") {
      absl::StatusOr<Struct> output_key = PsPublicKeyToKeyStruct(key);
      if (!output_key.ok()) {
        return output_key.status();
      }
      *keys_list->add_values()->mutable_struct_value() = *output_key;
    } else {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unknown key type url");
    }
  }
  return jwt_internal::ProtoStructToJsonString(output);
}

}  // namespace tink
}  // namespace crypto
