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

#ifndef TINK_DAEAD_DETERMINISTIC_AEAD_CONFIG_H_
#define TINK_DAEAD_DETERMINISTIC_AEAD_CONFIG_H_

#include "absl/base/macros.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Static methods and constants for registering with the Registry
// all instances of DeterministicAead key types supported in a release of Tink.
//
// To register all DeterministicAead key types from the current Tink release
// one can do:
//
//   auto status = DeterministicAeadConfig::Register();
//
class DeterministicAeadConfig {
 public:
  // Registers DeterministicAead primitive wrapper and key managers for all
  // DeterministicAead key types from the current Tink release.
  static absl::Status Register();

 private:
  DeterministicAeadConfig() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_DETERMINISTIC_AEAD_CONFIG_H_
