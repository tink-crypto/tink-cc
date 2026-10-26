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

#include "tink/signature/predefined_signature_parameters.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "openssl/opensslv.h"  // To get OPENSSL_IS_BORINGSSL if needed
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/proto_parameters_format.h"
#include "tink/signature/key_gen_config_2026.h"
#include "tink/signature/signature_config.h"
#include "tink/signature/signature_key_templates.h"

namespace tink_parameters {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::KeyGenConfigSignature2026;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::Parameters;
using ::crypto::tink::ParseParametersFromProtoFormat;
using ::crypto::tink::SignatureConfig;
using ::crypto::tink::SignatureKeyTemplates;
using ::google::crypto::tink::KeyTemplate;

struct TemplateEquivalence {
  std::string test_name;
  const Parameters& (*predefined)();
  const KeyTemplate& (*key_template)();
};

class PredefinedMatchesKeyTemplateTest
    : public testing::TestWithParam<TemplateEquivalence> {
 protected:
  // Registers the proto serializations used by ParseParametersFromProtoFormat.
  void SetUp() override { ASSERT_THAT(SignatureConfig::Register(), IsOk()); }
};

TEST_P(PredefinedMatchesKeyTemplateTest, ParsedTemplateEqualsPredefined) {
  const TemplateEquivalence& p = GetParam();
  absl::StatusOr<std::unique_ptr<Parameters>> parsed =
      ParseParametersFromProtoFormat(p.key_template().SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_EQ(**parsed, p.predefined());
}

INSTANTIATE_TEST_SUITE_P(
    PredefinedMatchesKeyTemplateTests, PredefinedMatchesKeyTemplateTest,
    testing::Values(
        TemplateEquivalence{"EcdsaP256",
                            +[]() -> const Parameters& { return EcdsaP256(); },
                            &SignatureKeyTemplates::EcdsaP256},
        TemplateEquivalence{
            "EcdsaP256RawDer",
            +[]() -> const Parameters& { return EcdsaP256RawDer(); },
            &SignatureKeyTemplates::EcdsaP256RawDer},
        TemplateEquivalence{
            "EcdsaP384Sha512",
            +[]() -> const Parameters& { return EcdsaP384Sha512(); },
            &SignatureKeyTemplates::EcdsaP384Sha512},
        TemplateEquivalence{"EcdsaP521",
                            +[]() -> const Parameters& { return EcdsaP521(); },
                            &SignatureKeyTemplates::EcdsaP521},
        TemplateEquivalence{
            "EcdsaP256Ieee",
            +[]() -> const Parameters& { return EcdsaP256Ieee(); },
            &SignatureKeyTemplates::EcdsaP256Ieee},
        TemplateEquivalence{
            "EcdsaP384Ieee",
            +[]() -> const Parameters& { return EcdsaP384Ieee(); },
            &SignatureKeyTemplates::EcdsaP384Ieee},
        TemplateEquivalence{
            "EcdsaP256Raw",
            +[]() -> const Parameters& { return EcdsaP256Raw(); },
            &SignatureKeyTemplates::EcdsaP256Raw},
        TemplateEquivalence{
            "EcdsaP521Ieee",
            +[]() -> const Parameters& { return EcdsaP521Ieee(); },
            &SignatureKeyTemplates::EcdsaP521Ieee},
        TemplateEquivalence{"Ed25519",
                            +[]() -> const Parameters& { return Ed25519(); },
                            &SignatureKeyTemplates::Ed25519},
        TemplateEquivalence{
            "Ed25519WithRawOutput",
            +[]() -> const Parameters& { return Ed25519WithRawOutput(); },
            &SignatureKeyTemplates::Ed25519WithRawOutput},
        TemplateEquivalence{
            "RsaSsaPkcs13072Sha256F4",
            +[]() -> const Parameters& { return RsaSsaPkcs13072Sha256F4(); },
            &SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4},
        TemplateEquivalence{
            "RsaSsaPkcs14096Sha512F4",
            +[]() -> const Parameters& { return RsaSsaPkcs14096Sha512F4(); },
            &SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4},
        TemplateEquivalence{
            "RsaSsaPss3072Sha256Sha256F4",
            +[]() -> const Parameters& {
              return RsaSsaPss3072Sha256Sha256F4();
            },
            &SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4},
        TemplateEquivalence{
            "RsaSsaPss4096Sha512Sha512F4",
            +[]() -> const Parameters& {
              return RsaSsaPss4096Sha512Sha512F4();
            },
            &SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4}),
    [](const testing::TestParamInfo<TemplateEquivalence>& info) {
      return info.param.test_name;
    });

// Checks that a key can be generated from `parameters` using
// `KeyGenConfigSignature2026()`, and that the generated key has `parameters`.
template <typename P>
void ExpectKeyGenerationWorks(const P& parameters) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(parameters,
                                              KeyGenConfigSignature2026());
  ASSERT_THAT(handle, IsOk());
  EXPECT_TRUE((*handle)->GetPrimary().GetKey()->GetParameters() == parameters);
}

TEST(PredefinedSignatureParametersTest, EcdsaKeyGen) {
  ExpectKeyGenerationWorks(EcdsaP256());
  ExpectKeyGenerationWorks(EcdsaP256RawDer());
  ExpectKeyGenerationWorks(EcdsaP384Sha512());
  ExpectKeyGenerationWorks(EcdsaP521());
  ExpectKeyGenerationWorks(EcdsaP256Ieee());
  ExpectKeyGenerationWorks(EcdsaP384Ieee());
  ExpectKeyGenerationWorks(EcdsaP256Raw());
  ExpectKeyGenerationWorks(EcdsaP521Ieee());
}

TEST(PredefinedSignatureParametersTest, Ed25519KeyGen) {
  ExpectKeyGenerationWorks(Ed25519());
  ExpectKeyGenerationWorks(Ed25519WithRawOutput());
}

TEST(PredefinedSignatureParametersTest, RsaSsaPkcs1Modulus3072Sha256F4KeyGen) {
  ExpectKeyGenerationWorks(RsaSsaPkcs13072Sha256F4());
  ExpectKeyGenerationWorks(RsaSsaPkcs13072Sha256F4NoPrefix());
}

TEST(PredefinedSignatureParametersTest, RsaSsaPss3072Sha256Sha256F4KeyGen) {
  ExpectKeyGenerationWorks(RsaSsaPss3072Sha256Sha256F4());
  ExpectKeyGenerationWorks(RsaSsaPss4096Sha512Sha512F4());
}

// ML-DSA is only supported with BoringSSL or OpenSSL >= 3.5.
#if defined(OPENSSL_IS_BORINGSSL) || \
    (defined(OPENSSL_API_LEVEL) && OPENSSL_API_LEVEL >= 30500)
TEST(PredefinedSignatureParametersTest, MlDsa44KeyGen) {
  ExpectKeyGenerationWorks(MlDsa44());
  ExpectKeyGenerationWorks(MlDsa44NoPrefix());
}
#endif

// SLH-DSA is only supported with BoringSSL.
#ifdef OPENSSL_IS_BORINGSSL
TEST(PredefinedSignatureParametersTest, SlhDsaSha2_128sKeyGen) {
  ExpectKeyGenerationWorks(SlhDsaSha2_128s());
  ExpectKeyGenerationWorks(SlhDsaSha2_128sNoPrefix());
}
#endif

}  // namespace
}  // namespace tink_parameters
