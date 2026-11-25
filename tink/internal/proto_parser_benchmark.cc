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

// Microbenchmarks for the core-dump-safe proto parser in
// `third_party/tink/cc/internal/proto_parser_*.h`, using the generated
// `KeysetTP` struct with a varying number of keys.

#include <cstddef>
#include <cstdint>
#include <string>

#include "benchmark/benchmark.h"
#include "absl/crc/crc32c.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::internal::KeyDataTP;
using ::google::crypto::tink::internal::KeysetTP;
using ::google::crypto::tink::internal::KeyStatusTypeTP;
using ::google::crypto::tink::internal::OutputPrefixTypeTP;

constexpr absl::string_view kKeyValue32 = "0123456789abcdef0123456789abcdef";
constexpr absl::string_view kAesGcmTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmKey";

// Returns a keyset with `num_keys` AES-GCM keys. Key IDs have the top bit set,
// so they are encoded as 5-byte varints.
KeysetTP MakeKeyset(int num_keys) {
  KeyDataTP key_data;
  key_data.set_type_url(kAesGcmTypeUrl);
  // Serialized `google.crypto.tink.AesGcmKey` with version 0 and a 32-byte
  // key_value (field 3, length 32).
  key_data.set_value(SecretData(absl::StrCat("\x1a\x20", kKeyValue32)));
  key_data.set_key_material_type(KeyDataTP::KeyMaterialTypeTP::kSymmetric);

  KeysetTP keyset;
  for (int i = 0; i < num_keys; ++i) {
    KeysetTP::KeyTP* key = keyset.add_key();
    *key->mutable_key_data() = key_data;
    key->set_status(KeyStatusTypeTP::kEnabled);
    key->set_key_id(0x80000000u + 7919u * i);
    key->set_output_prefix_type(OutputPrefixTypeTP::kTink);
  }
  keyset.set_primary_key_id(keyset.key(0).key_id());
  return keyset;
}

void BM_Keyset_ParseFromString(benchmark::State& state) {
  const SecretData serialized =
      MakeKeyset(state.range(0)).SerializeAsSecretData();
  KeysetTP parsed;
  ABSL_CHECK(parsed.ParseFromString(serialized.AsStringView()));
  for (auto s : state) {
    bool ok = parsed.ParseFromString(serialized.AsStringView());
    benchmark::DoNotOptimize(ok);
    benchmark::DoNotOptimize(parsed);
  }
  state.SetBytesProcessed(state.iterations() * serialized.size());
}
BENCHMARK(BM_Keyset_ParseFromString)->Arg(1)->Arg(4)->Arg(16);

void BM_Keyset_ParseFromStringWithCrc(benchmark::State& state) {
  const SecretData serialized =
      MakeKeyset(state.range(0)).SerializeAsSecretData();
  KeysetTP parsed;
  ABSL_CHECK_OK(parsed.ParseFromStringWithCrc(serialized.AsStringView()));
  for (auto s : state) {
    absl::StatusOr<util::SecretValue<absl::crc32c_t>> crc =
        parsed.ParseFromStringWithCrc(serialized.AsStringView());
    benchmark::DoNotOptimize(crc);
    benchmark::DoNotOptimize(parsed);
  }
  state.SetBytesProcessed(state.iterations() * serialized.size());
}
BENCHMARK(BM_Keyset_ParseFromStringWithCrc)->Arg(1)->Arg(4)->Arg(16);

void BM_Keyset_SerializeAsSecretData(benchmark::State& state) {
  const KeysetTP keyset = MakeKeyset(state.range(0));
  for (auto s : state) {
    SecretData serialized = keyset.SerializeAsSecretData();
    benchmark::DoNotOptimize(serialized);
  }
  state.SetBytesProcessed(state.iterations() * keyset.ByteSizeLong());
}
BENCHMARK(BM_Keyset_SerializeAsSecretData)->Arg(1)->Arg(4)->Arg(16);

void BM_Keyset_ByteSizeLong(benchmark::State& state) {
  const KeysetTP keyset = MakeKeyset(state.range(0));
  for (auto s : state) {
    size_t size = keyset.ByteSizeLong();
    benchmark::DoNotOptimize(size);
  }
}
BENCHMARK(BM_Keyset_ByteSizeLong)->Arg(1)->Arg(4)->Arg(16);

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
