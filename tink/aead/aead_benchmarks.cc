// Copyright 2025 Google LLC
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

#include <memory>
#include <string>

#include "benchmark/benchmark.h"
#include "gmock/gmock.h"
#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/config/global_registry.h"
#include "tink/keyset_handle.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::KeyTemplate;

constexpr int kMinSize = 128;
constexpr int kMaxSize = 1 << 25;
constexpr absl::string_view kAssociatedData = "associated_data";
constexpr int kMultipler = 16;

absl::StatusOr<std::unique_ptr<Aead>> GetAead(const KeyTemplate& key_template) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  if (!keyset_handle.ok()) {
    return keyset_handle.status();
  }
  return (*keyset_handle)->GetPrimitive<Aead>(ConfigGlobalRegistry());
}


void Encrypt(benchmark::State& state, const KeyTemplate& key_template) {
  CHECK_OK(AeadConfig::Register());
  absl::StatusOr<std::unique_ptr<Aead>> aead = GetAead(key_template);
  CHECK_OK(aead);

  std::string plaintext(state.range(0), 'a');
  for (auto s : state) {
    absl::StatusOr<std::string> ciphertext =
        (*aead)->Encrypt(plaintext, kAssociatedData);
    CHECK_OK(ciphertext);
    benchmark::DoNotOptimize(ciphertext);
  }
  state.SetBytesProcessed(state.iterations() * plaintext.size());
}

void BM_Aes256CtrHmacSha256Encrypt(benchmark::State& state) {
  Encrypt(state, AeadKeyTemplates::Aes256CtrHmacSha256());
}

void BM_Aes256GcmEncrypt(benchmark::State& state) {
  Encrypt(state, AeadKeyTemplates::Aes256Gcm());
}


BENCHMARK(BM_Aes256CtrHmacSha256Encrypt)
    ->RangeMultiplier(kMultipler)
    ->Range(kMinSize, kMaxSize);
BENCHMARK(BM_Aes256GcmEncrypt)
    ->RangeMultiplier(kMultipler)
    ->Range(kMinSize, kMaxSize);

void Decrypt(benchmark::State& state, const KeyTemplate& key_template) {
  CHECK_OK(AeadConfig::Register());
  absl::StatusOr<std::unique_ptr<Aead>> aead = GetAead(key_template);
  CHECK_OK(aead);

  std::string plaintext(state.range(0), 'a');
  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(plaintext, kAssociatedData);
  CHECK_OK(ciphertext);

  for (auto s : state) {
    absl::StatusOr<std::string> decrypted =
        (*aead)->Decrypt(*ciphertext, kAssociatedData);
    CHECK_OK(decrypted);
    benchmark::DoNotOptimize(decrypted);
  }
  state.SetBytesProcessed(state.iterations() * plaintext.size());
}

void BM_Aes256CtrHmacSha256Decrypt(benchmark::State& state) {
  Decrypt(state, AeadKeyTemplates::Aes256CtrHmacSha256());
}

void BM_Aes256GcmDecrypt(benchmark::State& state) {
  Decrypt(state, AeadKeyTemplates::Aes256Gcm());
}

BENCHMARK(BM_Aes256CtrHmacSha256Decrypt)
    ->RangeMultiplier(kMultipler)
    ->Range(kMinSize, kMaxSize);
BENCHMARK(BM_Aes256GcmDecrypt)
    ->RangeMultiplier(kMultipler)
    ->Range(kMinSize, kMaxSize);

}  // namespace
}  // namespace tink
}  // namespace crypto
