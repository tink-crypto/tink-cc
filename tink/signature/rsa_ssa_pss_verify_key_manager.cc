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

#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"

#include <memory>
#include <optional>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/md_util.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/rtti.h"
#include "tink/signature/internal/rsa_ssa_pss_proto_serialization_impl.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/validation.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::Enums;
using ::google::crypto::tink::RsaSsaPssParams;
using RsaSsaPssPublicKeyProto = ::google::crypto::tink::RsaSsaPssPublicKey;

absl::StatusOr<RsaSsaPssPublicKey> ParseRsaSsaPssPublicKeyWithNoPrefix(
    const RsaSsaPssPublicKeyProto& rsa_ssa_pss_public_key) {
  static const internal::SerializationRegistry* registry = []() {
    auto* registry = new internal::SerializationRegistry();
    ABSL_CHECK_OK(
        internal::RegisterRsaSsaPssProtoSerializationWithRegistry(*registry));
    return registry;
  }();
  // KeyTypeManager primitives only receive the raw key proto (without
  // OutputPrefixType or key ID) and must produce raw (kNoPrefix) primitives;
  // the output prefix is handled by PublicKeyVerifyWrapper.
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          RsaSsaPssVerifyKeyManager().get_key_type(),
          RestrictedData(rsa_ssa_pss_public_key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPublic,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt);
  ABSL_RETURN_IF_ERROR(serialization.status());
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<Key> key,
      registry->ParseKey(*serialization, InsecureSecretKeyAccess::Get()));
  const auto* public_key = DynamicCast<const RsaSsaPssPublicKey*>(key.get());
  if (public_key == nullptr) {
    return absl::InternalError("Failed to cast to RsaSsaPssPublicKey");
  }
  return *public_key;
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPssVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const RsaSsaPssPublicKeyProto& rsa_ssa_pss_public_key) const {
  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPssPublicKey public_key,
      ParseRsaSsaPssPublicKeyWithNoPrefix(rsa_ssa_pss_public_key));
  return subtle::RsaSsaPssVerifyBoringSsl::New(public_key);
}

absl::Status RsaSsaPssVerifyKeyManager::ValidateKey(
    const RsaSsaPssPublicKeyProto& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(key.n());
  if (!n.ok()) {
    return n.status();
  }
  absl::Status modulus_status =
      internal::ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }
  absl::Status exponent_status = internal::ValidateRsaPublicExponent(key.e());
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  return ValidateParams(key.params());
}

absl::Status RsaSsaPssVerifyKeyManager::ValidateParams(
    const RsaSsaPssParams& params) const {
  absl::Status hash_result = internal::IsHashTypeSafeForSignature(
      Enums::ProtoToSubtle(params.sig_hash()));
  if (!hash_result.ok()) {
    return hash_result;
  }
  // The most common use case is that MGF1 hash is the same as signature hash.
  // This is recommended by RFC https://tools.ietf.org/html/rfc8017#section-8.1.
  // While using different hashes doesn't cause security vulnerabilities, there
  // is also no good reason to support different hashes. Furthermore:
  //
  //  - Golang does not support different hashes.
  //
  //  - BoringSSL supports different hashes just because of historical reason.
  // There is no real use case.
  //
  //  - Conscrypt/BouncyCastle do not support different hashes.
  if (params.mgf1_hash() != params.sig_hash()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("MGF1 hash '", params.mgf1_hash(),
                                     "' is different from signature hash '",
                                     params.sig_hash(), "'"));
  }
  if (params.salt_length() < 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "salt length is negative");
  }
  return absl::OkStatus();
}

}  // namespace tink
}  // namespace crypto
