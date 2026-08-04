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

#include "tink/prf/aes_cmac_prf_key_manager.h"

#include <memory>

#include "absl/status/statusor.h"
#include "tink/mac/internal/stateful_cmac_boringssl.h"
#include "tink/prf/prf_set.h"
#include "tink/subtle/prf/prf_set_util.h"
#include "tink/util/secret_data.h"
#include "proto/aes_cmac_prf.pb.h"

namespace crypto {
namespace tink {

absl::StatusOr<std::unique_ptr<Prf>>
AesCmacPrfKeyManager::PrfSetFactory::Create(
    const google::crypto::tink::AesCmacPrfKey& key) const {
  return subtle::CreatePrfFromStatefulMacFactory(
      std::make_unique<internal::StatefulCmacBoringSslFactory>(
          AesCmacPrfKeyManager::MaxOutputLength(),
          util::SecretDataFromStringView(key.key_value())));
}

}  // namespace tink
}  // namespace crypto
