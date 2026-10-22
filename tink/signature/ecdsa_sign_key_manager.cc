// Copyright 2017 Google LLC
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

#include "tink/signature/ecdsa_sign_key_manager.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/config/tink_fips.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_key_from_seed.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key.h"
#include "tink/public_key_sign.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::EcdsaKeyFormat;
using EcdsaPrivateKeyProto = ::google::crypto::tink::EcdsaPrivateKey;
using EcdsaPublicKeyProto = ::google::crypto::tink::EcdsaPublicKey;

absl::StatusOr<EcdsaPrivateKey> ParseEcdsaPrivateKeyWithNoPrefix(
    const EcdsaPrivateKeyProto& ecdsa_private_key) {
  static const internal::SerializationRegistry* registry = []() {
    internal::SerializationRegistry::Builder builder;
    ABSL_CHECK_OK(
        internal::RegisterEcdsaProtoSerializationWithRegistryBuilder(builder));
    return new internal::SerializationRegistry(std::move(builder).Build());
  }();
  // KeyTypeManager primitives only receive the raw key proto (without
  // OutputPrefixType or key ID) and must produce raw (kNoPrefix) primitives;
  // the output prefix is handled by PublicKeySignWrapper.
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          EcdsaSignKeyManager().get_key_type(),
          RestrictedData(ecdsa_private_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt);
  ABSL_RETURN_IF_ERROR(serialization.status());
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(*serialization, InsecureSecretKeyAccess::Get()));
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(key.get());
  if (private_key == nullptr) {
    return absl::InternalError("Failed to cast to EcdsaPrivateKey");
  }
  return *private_key;
}

}  // namespace

absl::StatusOr<EcdsaPrivateKeyProto> EcdsaSignKeyManager::CreateKey(
    const EcdsaKeyFormat& ecdsa_key_format) const {
  // Generate new EC key.
  ABSL_ASSIGN_OR_RETURN(internal::EcKey ec_key,
                        internal::NewEcKey(util::Enums::ProtoToSubtle(
                            ecdsa_key_format.params().curve())));

  // Build EcdsaPrivateKeyProto.
  EcdsaPrivateKeyProto ecdsa_private_key;
  ecdsa_private_key.set_version(get_version());
  ecdsa_private_key.set_key_value(ec_key.priv.AsStringView());
  EcdsaPublicKeyProto* ecdsa_public_key =
      ecdsa_private_key.mutable_public_key();
  ecdsa_public_key->set_version(get_version());
  ecdsa_public_key->set_x(ec_key.pub_x);
  ecdsa_public_key->set_y(ec_key.pub_y);
  *(ecdsa_public_key->mutable_params()) = ecdsa_key_format.params();
  return ecdsa_private_key;
}

absl::StatusOr<EcdsaPrivateKeyProto> EcdsaSignKeyManager::DeriveKey(
    const EcdsaKeyFormat& ecdsa_key_format, InputStream* input_stream) const {
  if (IsFipsModeEnabled()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Deriving EC keys is not allowed in FIPS mode.");
  }

  absl::Status status =
      ValidateVersion(ecdsa_key_format.version(), get_version());
  if (!status.ok()) {
    return status;
  }

  // Extract enough random bytes from the input_stream to match the security
  // level of the EC. Note that the input_stream here must come from a PRF
  // and will not use more bytes than required by the security level of the EC.
  // Providing an input_stream which has more bytes available than required,
  // will result in the same keys being generated.
  int random_bytes_used = 0;
  switch (ecdsa_key_format.params().curve()) {
    case ::google::crypto::tink::EllipticCurveType::NIST_P256:
      random_bytes_used = 16;
      break;
    case ::google::crypto::tink::EllipticCurveType::NIST_P384:
      random_bytes_used = 24;
      break;
    case ::google::crypto::tink::EllipticCurveType::NIST_P521:
      random_bytes_used = 32;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Curve does not support key derivation.");
  }

  absl::StatusOr<SecretData> randomness =
      ReadSecretBytesFromStream(random_bytes_used, input_stream);
  if (!randomness.ok()) {
    if (randomness.status().code() == absl::StatusCode::kOutOfRange) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not get enough pseudorandomness from input stream");
    }
    return randomness.status();
  }

  // Generate new EC key from the seed.
  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKeyFromSeed(
      util::Enums::ProtoToSubtle(ecdsa_key_format.params().curve()),
      *randomness);

  if (!ec_key.ok()) {
    return ec_key.status();
  }

  // Build EcdsaPrivateKey.
  EcdsaPrivateKeyProto ecdsa_private_key;
  ecdsa_private_key.set_version(get_version());
  ecdsa_private_key.set_key_value(ec_key->priv.AsStringView());
  EcdsaPublicKeyProto* ecdsa_public_key =
      ecdsa_private_key.mutable_public_key();
  ecdsa_public_key->set_version(get_version());
  ecdsa_public_key->set_x(ec_key->pub_x);
  ecdsa_public_key->set_y(ec_key->pub_y);
  *(ecdsa_public_key->mutable_params()) = ecdsa_key_format.params();
  return ecdsa_private_key;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
EcdsaSignKeyManager::PublicKeySignFactory::Create(
    const EcdsaPrivateKeyProto& ecdsa_private_key) const {
  ABSL_ASSIGN_OR_RETURN(EcdsaPrivateKey private_key,
                        ParseEcdsaPrivateKeyWithNoPrefix(ecdsa_private_key));
  return subtle::EcdsaSignBoringSsl::New(private_key);
}

absl::Status EcdsaSignKeyManager::ValidateKey(
    const EcdsaPrivateKeyProto& key) const {
  ABSL_RETURN_IF_ERROR(ValidateVersion(key.version(), get_version()));
  return EcdsaVerifyKeyManager().ValidateKey(key.public_key());
}

absl::Status EcdsaSignKeyManager::ValidateKeyFormat(
    const EcdsaKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }
  return EcdsaVerifyKeyManager().ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
