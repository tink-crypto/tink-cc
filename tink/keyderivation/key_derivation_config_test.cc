// Copyright 2020 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/key_derivation_config.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/config/global_registry.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/key_status.h"
#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/keyderivation/key_derivation_key_templates.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/prf_config.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/proto_parameters_format.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCmacPrfKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;
using ::google::crypto::tink::PrfBasedDeriverParams;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Test;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";
constexpr absl::string_view kPrfKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";
constexpr absl::string_view kDerivedKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
constexpr absl::string_view kPrfKeyValue = "0123456789abcdef0123456789abcdef";

class KeyDerivationConfigTest : public Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(KeyDerivationConfigTest, Register) {
  EXPECT_THAT(KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
                  PrfKeyTemplates::HkdfSha256(), AeadKeyTemplates::Aes256Gcm()),
              Not(IsOk()));

  ASSERT_THAT(KeyDerivationConfig::Register(), IsOk());
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  util::StatusOr<::google::crypto::tink::KeyTemplate> templ =
      KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
          PrfKeyTemplates::HkdfSha256(), AeadKeyTemplates::Aes256Gcm());
  ASSERT_THAT(templ, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(*templ, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*handle)->GetPrimitive<crypto::tink::KeysetDeriver>(
          ConfigGlobalRegistry());
  ASSERT_THAT(deriver, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> derived_handle =
      (*deriver)->DeriveKeyset("salty");
  ASSERT_THAT(derived_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*derived_handle)
          ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());
  std::string plaintext = "plaintext";
  std::string ad = "ad";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  ASSERT_THAT(ciphertext, IsOk());
  util::StatusOr<std::string> got = (*aead)->Decrypt(*ciphertext, ad);
  ASSERT_THAT(got, IsOk());
  EXPECT_EQ(plaintext, *got);
}

KeyTemplate GetAesCmacPrfKeyTemplate() {
  AesCmacPrfKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(kPrfKeyValue.size());
  KeyTemplate key_template;
  key_template.set_type_url(kPrfKeyTypeUrl);
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

AesCmacPrfParameters GetAesCmacPrfParameters() {
  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(kPrfKeyValue.size());
  CHECK_OK(parameters);
  return *parameters;
}

AesCmacPrfKey GetAesCmacPrfKey() {
  util::StatusOr<AesCmacPrfKey> key = AesCmacPrfKey::Create(
      RestrictedData(kPrfKeyValue,
                     internal::GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  CHECK_OK(key);
  return *key;
}

KeyTemplate GetXChaCha20Poly1305KeyTemplate() {
  XChaCha20Poly1305KeyFormat key_format;
  key_format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(kDerivedKeyTypeUrl);
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  return key_template;
}

XChaCha20Poly1305Parameters GetXChaCha20Poly1305Parameters() {
  util::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  CHECK_OK(parameters);
  return *parameters;
}

TEST_F(KeyDerivationConfigTest,
       PrfBasedKeyDerivationProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = GetAesCmacPrfKeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      derived_key_template;
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  KeyTemplate key_template;
  key_template.set_type_url(kTypeUrl);
  key_template.set_output_prefix_type(
      derived_key_template.output_prefix_type());
  key_format_proto.SerializeToString(key_template.mutable_value());

  util::StatusOr<std::unique_ptr<Parameters>> proto_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(proto_parameters, IsOk());
  EXPECT_THAT(
      dynamic_cast<internal::LegacyProtoParameters*>(proto_parameters->get()),
      NotNull());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetAesCmacPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(SerializeParametersToProtoFormat(*parameters),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(KeyDerivationConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT(
      dynamic_cast<PrfBasedKeyDerivationParameters*>(parsed_parameters->get()),
      NotNull());

  EXPECT_THAT(SerializeParametersToProtoFormat(*parameters), IsOk());
}

TEST_F(KeyDerivationConfigTest,
       PrfBasedKeyDerivationProtoKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_THAT(AeadConfig::Register(), IsOk());  // For XChaCha20Poly1305Key
  ASSERT_THAT(PrfConfig::Register(), IsOk());  // For AesCmacPrfKey

  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = GetAesCmacPrfKeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      derived_key_template;
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  KeyTemplate key_template;
  key_template.set_type_url(kTypeUrl);
  key_template.set_output_prefix_type(
      derived_key_template.output_prefix_type());
  key_format_proto.SerializeToString(key_template.mutable_value());

  // NOTE: No key generation config available yet for PrfBasedDeriver keys.
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<internal::PrfBasedDeriverKeyManager>(), true),
      IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());

  // Fails to parse this key type, so falls back to legacy proto key.
  EXPECT_THAT(dynamic_cast<const internal::LegacyProtoKey*>(
                  (*handle)->GetPrimary().GetKey().get()),
              NotNull());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetAesCmacPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, GetAesCmacPrfKey(),
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Fails to serialize this key type.
  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  ASSERT_THAT(KeyDerivationConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle2 =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle2, IsOk());

  EXPECT_THAT(dynamic_cast<const PrfBasedKeyDerivationKey*>(
                  (*handle2)->GetPrimary().GetKey().get()),
              NotNull());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
