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

#include "tink/subtle/random.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "openssl/rand.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

template <typename UintType>
UintType GetRandomUint() {
  UintType result;
  ABSL_CHECK_OK(Random::GetRandomBytes(
      absl::MakeSpan(reinterpret_cast<char*>(&result), sizeof(result))));
  return result;
}

}  // namespace

absl::Status Random::GetRandomBytes(absl::Span<char> buffer) {
  auto buffer_ptr = reinterpret_cast<uint8_t*>(buffer.data());
  if (RAND_bytes(buffer_ptr, buffer.size()) <= 0) {
    return absl::Status(absl::StatusCode::kInternal,
                        absl::StrCat("RAND_bytes failed to generate ",
                                     buffer.size(), " bytes"));
  }
  return absl::OkStatus();
}

std::string Random::GetRandomBytes(size_t length) {
  std::string buffer;
  ResizeStringUninitialized(&buffer, length);
  ABSL_CHECK_OK(GetRandomBytes(absl::MakeSpan(buffer)));
  return buffer;
}

uint32_t Random::GetRandomUInt32() { return GetRandomUint<uint32_t>(); }
uint16_t Random::GetRandomUInt16() { return GetRandomUint<uint16_t>(); }
uint8_t Random::GetRandomUInt8() { return GetRandomUint<uint8_t>(); }

SecretData Random::GetRandomKeyBytes(size_t length) {
  internal::SecretBuffer buf(length, 0);
  ABSL_CHECK_OK(GetRandomBytes(
      absl::MakeSpan(reinterpret_cast<char*>(buf.data()), buf.size())));
  return util::internal::AsSecretData(std::move(buf));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
