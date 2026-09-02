// Copyright 2026 Google LLC
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

#include "tink/signature/internal/testing/ecdsa_test_utils.h"

#include "tink/internal/ec_util.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::EcdsaPrivateKey;

EcdsaPrivateKey GetEcdsaTestPrivateKey(
    subtle::EllipticCurveType curve_type, subtle::HashType hash_type,
    subtle::EcdsaSignatureEncoding encoding) {
  return GetEcdsaTestPrivateKey(util::Enums::SubtleToProto(curve_type),
                                util::Enums::SubtleToProto(hash_type),
                                util::Enums::SubtleToProto(encoding));
}

EcdsaPrivateKey GetEcdsaTestPrivateKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::HashType hash_type,
    google::crypto::tink::EcdsaSignatureEncoding encoding) {
  const internal::EcKey& test_key =
      internal::GetEcKey(util::Enums::ProtoToSubtle(curve_type));
  EcdsaPrivateKey ecdsa_key;
  ecdsa_key.set_version(0);
  ecdsa_key.set_key_value(util::SecretDataAsStringView(test_key.priv));

  google::crypto::tink::EcdsaPublicKey* public_key =
      ecdsa_key.mutable_public_key();
  public_key->set_version(0);
  public_key->set_x(test_key.pub_x);
  public_key->set_y(test_key.pub_y);

  google::crypto::tink::EcdsaParams* params = public_key->mutable_params();
  params->set_curve(curve_type);
  params->set_hash_type(hash_type);
  params->set_encoding(encoding);

  return ecdsa_key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
