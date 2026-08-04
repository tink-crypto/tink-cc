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

#include "tink/prf/hkdf_prf_key_manager.h"

#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "tink/prf/prf_set.h"
#include "tink/subtle/prf/hkdf_streaming_prf.h"
#include "tink/subtle/prf/prf_set_util.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "proto/hkdf_prf.pb.h"

namespace crypto {
namespace tink {

absl::StatusOr<std::unique_ptr<StreamingPrf>>
HkdfPrfKeyManager::StreamingPrfFactory::Create(
    const google::crypto::tink::HkdfPrfKey& key) const {
  return subtle::HkdfStreamingPrf::New(
      crypto::tink::util::Enums::ProtoToSubtle(key.params().hash()),
      util::SecretDataFromStringView(key.key_value()), key.params().salt());
}

absl::StatusOr<std::unique_ptr<Prf>> HkdfPrfKeyManager::PrfSetFactory::Create(
    const google::crypto::tink::HkdfPrfKey& key) const {
  auto hkdf_result = subtle::HkdfStreamingPrf::New(
      crypto::tink::util::Enums::ProtoToSubtle(key.params().hash()),
      util::SecretDataFromStringView(key.key_value()), key.params().salt());
  if (!hkdf_result.ok()) {
    return hkdf_result.status();
  }
  return subtle::CreatePrfFromStreamingPrf(std::move(hkdf_result.value()));
}

}  // namespace tink
}  // namespace crypto
