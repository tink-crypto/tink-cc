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

#include <memory>

#include "benchmark/benchmark.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/config/config_2026.h"
#include "tink/config/global_registry.h"
#include "tink/configuration.h"
#include "tink/internal/ssl_util.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/signature_config.h"
#include "tink/signature/signature_key_templates.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::KeyTemplate;

// Every benchmark is run with two configurations, because they take different
// code paths in `KeysetHandle::GetPrimitive`:
//   - `ConfigGlobalRegistry()` (suffix "Global") only creates primitives from
//     the legacy proto key data via the registry; its key-object based
//     primitive getter always returns `kNotFound`.
//   - A `Configuration` such as `Config2026()` (suffix "Config") creates
//     primitives from the `Key` objects via the primitive getters added to the
//     configuration.

void RegisterConfigs() {
  ABSL_CHECK_OK(SignatureConfig::Register());
  ABSL_CHECK_OK(AeadConfig::Register());
}

std::unique_ptr<KeysetHandle> GenerateKeysetHandleOrDie(
    const KeyTemplate& key_template) {
  RegisterConfigs();
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ABSL_CHECK_OK(handle);
  return *std::move(handle);
}

std::unique_ptr<KeysetHandle> GetPublicKeysetHandleOrDie(
    const KeysetHandle& private_handle) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      private_handle.GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ABSL_CHECK_OK(public_handle);
  return *std::move(public_handle);
}

// Times only `KeysetHandle::GetPrimitive<P>`; `handle` is created once
// outside of the timed loop.
template <typename P>
void BenchmarkGetPrimitive(benchmark::State& state, const KeysetHandle& handle,
                           const Configuration& config) {
  for (auto s : state) {
    absl::StatusOr<std::unique_ptr<P>> primitive =
        handle.GetPrimitive<P>(config);
    ABSL_CHECK_OK(primitive);
    benchmark::DoNotOptimize(primitive);
  }
}

void BenchmarkGetPublicKeySign(benchmark::State& state,
                               const KeyTemplate& key_template,
                               const Configuration& config) {
  std::unique_ptr<KeysetHandle> handle =
      GenerateKeysetHandleOrDie(key_template);
  BenchmarkGetPrimitive<PublicKeySign>(state, *handle, config);
}

void BenchmarkGetPublicKeyVerify(benchmark::State& state,
                                 const KeyTemplate& key_template,
                                 const Configuration& config) {
  std::unique_ptr<KeysetHandle> private_handle =
      GenerateKeysetHandleOrDie(key_template);
  std::unique_ptr<KeysetHandle> public_handle =
      GetPublicKeysetHandleOrDie(*private_handle);
  BenchmarkGetPrimitive<PublicKeyVerify>(state, *public_handle, config);
}

// RSA-SSA-PKCS1 3072-bit, SHA256, F4.
void RsaSsaPkcs1Sign(benchmark::State& state, const Configuration& config) {
  BenchmarkGetPublicKeySign(
      state, SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4(), config);
}

void BM_RsaSsaPkcs1SignGlobal(benchmark::State& state) {
  RsaSsaPkcs1Sign(state, ConfigGlobalRegistry());
}

void BM_RsaSsaPkcs1SignConfig(benchmark::State& state) {
  RsaSsaPkcs1Sign(state, Config2026());
}

void RsaSsaPkcs1Verify(benchmark::State& state, const Configuration& config) {
  BenchmarkGetPublicKeyVerify(
      state, SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4(), config);
}

void BM_RsaSsaPkcs1VerifyGlobal(benchmark::State& state) {
  RsaSsaPkcs1Verify(state, ConfigGlobalRegistry());
}

void BM_RsaSsaPkcs1VerifyConfig(benchmark::State& state) {
  RsaSsaPkcs1Verify(state, Config2026());
}

// RSA-SSA-PKCS1 3072-bit, SHA256, F4 with a public keyset of `state.range(0)`
// keys.
void RsaSsaPkcs1VerifyMultipleKeys(benchmark::State& state,
                                   const Configuration& config) {
  RegisterConfigs();
  const KeyTemplate& key_template =
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4();
  absl::StatusOr<std::unique_ptr<KeysetManager>> manager =
      KeysetManager::New(key_template);
  ABSL_CHECK_OK(manager);
  for (int i = 1; i < state.range(0); ++i) {
    ABSL_CHECK_OK((*manager)->Add(key_template).status());
  }
  std::unique_ptr<KeysetHandle> private_handle = (*manager)->GetKeysetHandle();
  std::unique_ptr<KeysetHandle> public_handle =
      GetPublicKeysetHandleOrDie(*private_handle);
  BenchmarkGetPrimitive<PublicKeyVerify>(state, *public_handle, config);
}

void BM_RsaSsaPkcs1VerifyMultipleKeysGlobal(benchmark::State& state) {
  RsaSsaPkcs1VerifyMultipleKeys(state, ConfigGlobalRegistry());
}

void BM_RsaSsaPkcs1VerifyMultipleKeysConfig(benchmark::State& state) {
  RsaSsaPkcs1VerifyMultipleKeys(state, Config2026());
}

// ECDSA P-256.
void EcdsaP256Sign(benchmark::State& state, const Configuration& config) {
  BenchmarkGetPublicKeySign(state, SignatureKeyTemplates::EcdsaP256(), config);
}

void BM_EcdsaP256SignGlobal(benchmark::State& state) {
  EcdsaP256Sign(state, ConfigGlobalRegistry());
}

void BM_EcdsaP256SignConfig(benchmark::State& state) {
  EcdsaP256Sign(state, Config2026());
}

void EcdsaP256Verify(benchmark::State& state, const Configuration& config) {
  BenchmarkGetPublicKeyVerify(state, SignatureKeyTemplates::EcdsaP256(),
                              config);
}

void BM_EcdsaP256VerifyGlobal(benchmark::State& state) {
  EcdsaP256Verify(state, ConfigGlobalRegistry());
}

void BM_EcdsaP256VerifyConfig(benchmark::State& state) {
  EcdsaP256Verify(state, Config2026());
}

// Ed25519.
void Ed25519Sign(benchmark::State& state, const Configuration& config) {
  BenchmarkGetPublicKeySign(state, SignatureKeyTemplates::Ed25519(), config);
}

void BM_Ed25519SignGlobal(benchmark::State& state) {
  Ed25519Sign(state, ConfigGlobalRegistry());
}

void BM_Ed25519SignConfig(benchmark::State& state) {
  Ed25519Sign(state, Config2026());
}

void Ed25519Verify(benchmark::State& state, const Configuration& config) {
  BenchmarkGetPublicKeyVerify(state, SignatureKeyTemplates::Ed25519(), config);
}

void BM_Ed25519VerifyGlobal(benchmark::State& state) {
  Ed25519Verify(state, ConfigGlobalRegistry());
}

void BM_Ed25519VerifyConfig(benchmark::State& state) {
  Ed25519Verify(state, Config2026());
}

// ML-DSA-65.
std::unique_ptr<KeysetHandle> GenerateMlDsa65KeysetHandleOrDie() {
  RegisterConfigs();
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters,
                                              KeyGenConfigGlobalRegistry());
  ABSL_CHECK_OK(handle);
  return *std::move(handle);
}

void MlDsa65Sign(benchmark::State& state, const Configuration& config) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL";
  }
  std::unique_ptr<KeysetHandle> handle = GenerateMlDsa65KeysetHandleOrDie();
  BenchmarkGetPrimitive<PublicKeySign>(state, *handle, config);
}

void BM_MlDsa65SignGlobal(benchmark::State& state) {
  MlDsa65Sign(state, ConfigGlobalRegistry());
}

void BM_MlDsa65SignConfig(benchmark::State& state) {
  MlDsa65Sign(state, Config2026());
}

void MlDsa65Verify(benchmark::State& state, const Configuration& config) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL";
  }
  std::unique_ptr<KeysetHandle> private_handle =
      GenerateMlDsa65KeysetHandleOrDie();
  std::unique_ptr<KeysetHandle> public_handle =
      GetPublicKeysetHandleOrDie(*private_handle);
  BenchmarkGetPrimitive<PublicKeyVerify>(state, *public_handle, config);
}

void BM_MlDsa65VerifyGlobal(benchmark::State& state) {
  MlDsa65Verify(state, ConfigGlobalRegistry());
}

void BM_MlDsa65VerifyConfig(benchmark::State& state) {
  MlDsa65Verify(state, Config2026());
}

// AES-256-GCM.
void Aes256Gcm(benchmark::State& state, const Configuration& config) {
  std::unique_ptr<KeysetHandle> handle =
      GenerateKeysetHandleOrDie(AeadKeyTemplates::Aes256Gcm());
  BenchmarkGetPrimitive<Aead>(state, *handle, config);
}

void BM_Aes256GcmGlobal(benchmark::State& state) {
  Aes256Gcm(state, ConfigGlobalRegistry());
}

void BM_Aes256GcmConfig(benchmark::State& state) {
  Aes256Gcm(state, Config2026());
}

BENCHMARK(BM_RsaSsaPkcs1SignGlobal);
BENCHMARK(BM_RsaSsaPkcs1SignConfig);
BENCHMARK(BM_RsaSsaPkcs1VerifyGlobal);
BENCHMARK(BM_RsaSsaPkcs1VerifyConfig);
BENCHMARK(BM_RsaSsaPkcs1VerifyMultipleKeysGlobal)->Arg(1)->Arg(10);
BENCHMARK(BM_RsaSsaPkcs1VerifyMultipleKeysConfig)->Arg(1)->Arg(10);
BENCHMARK(BM_EcdsaP256SignGlobal);
BENCHMARK(BM_EcdsaP256SignConfig);
BENCHMARK(BM_EcdsaP256VerifyGlobal);
BENCHMARK(BM_EcdsaP256VerifyConfig);
BENCHMARK(BM_Ed25519SignGlobal);
BENCHMARK(BM_Ed25519SignConfig);
BENCHMARK(BM_Ed25519VerifyGlobal);
BENCHMARK(BM_Ed25519VerifyConfig);
BENCHMARK(BM_MlDsa65SignGlobal);
BENCHMARK(BM_MlDsa65SignConfig);
BENCHMARK(BM_MlDsa65VerifyGlobal);
BENCHMARK(BM_MlDsa65VerifyConfig);
BENCHMARK(BM_Aes256GcmGlobal);
BENCHMARK(BM_Aes256GcmConfig);

}  // namespace
}  // namespace tink
}  // namespace crypto
