// Copyright 2017 Google Inc.
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

#ifndef TINK_MAC_MAC_CONFIG_H_
#define TINK_MAC_MAC_CONFIG_H_

#include "absl/base/macros.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Static methods and constants for registering with the Registry
// all instances of Mac key types supported in a particular release of Tink.
//
// To register all Mac key types from the current Tink release one can do:
//
//   auto status = MacConfig::Register();
//
class MacConfig {
 public:
  // Registers Mac primitive wrapper and key managers for all Mac key types
  // from the current Tink release.
  static absl::Status Register();

 private:
  MacConfig() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_MAC_CONFIG_H_
