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

#include "tink/hybrid/internal/hpke_proto_structs.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_parameters.h"
#include "proto/hpke.tinkpb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::internal::HpkeAeadTP;
using ::google::crypto::tink::internal::HpkeKdfTP;
using ::google::crypto::tink::internal::HpkeKemTP;
using ::google::crypto::tink::internal::HpkeParamsTP;
using ::google::crypto::tink::internal::OutputPrefixTypeTP;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

HpkeParamsTP Params(HpkeKemTP kem, HpkeKdfTP kdf, HpkeAeadTP aead) {
  HpkeParamsTP params;
  params.set_kem(kem);
  params.set_kdf(kdf);
  params.set_aead(aead);
  return params;
}

struct RoundTripCase {
  OutputPrefixTypeTP output_prefix_type;
  HpkeKemTP kem;
  HpkeKdfTP kdf;
  HpkeAeadTP aead;
  HpkeParameters::Variant variant;
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
};

using HpkeProtoStructsRoundTripTest = TestWithParam<RoundTripCase>;

TEST_P(HpkeProtoStructsRoundTripTest, FromProtoAndBack) {
  const RoundTripCase& tc = GetParam();
  absl::StatusOr<HpkeParameters> parameters = HpkeParametersFromProto(
      tc.output_prefix_type, Params(tc.kem, tc.kdf, tc.aead));
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetVariant(), Eq(tc.variant));
  EXPECT_THAT(parameters->GetKemId(), Eq(tc.kem_id));
  EXPECT_THAT(parameters->GetKdfId(), Eq(tc.kdf_id));
  EXPECT_THAT(parameters->GetAeadId(), Eq(tc.aead_id));

  absl::StatusOr<HpkeParamsTP> params = HpkeParamsToProto(*parameters);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT(params->kem(), Eq(tc.kem));
  EXPECT_THAT(params->kdf(), Eq(tc.kdf));
  EXPECT_THAT(params->aead(), Eq(tc.aead));
  EXPECT_THAT(HpkeVariantToOutputPrefixType(parameters->GetVariant()),
              IsOkAndHolds(Eq(tc.output_prefix_type)));
}

INSTANTIATE_TEST_SUITE_P(
    HpkeProtoStructsRoundTripTest, HpkeProtoStructsRoundTripTest,
    Values(
        RoundTripCase{OutputPrefixTypeTP::kTink, HpkeKemTP::kXWing,
                      HpkeKdfTP::kHkdfSha256, HpkeAeadTP::kAes128Gcm,
                      HpkeParameters::Variant::kTink,
                      HpkeParameters::KemId::kXWing,
                      HpkeParameters::KdfId::kHkdfSha256,
                      HpkeParameters::AeadId::kAesGcm128},
        RoundTripCase{OutputPrefixTypeTP::kCrunchy,
                      HpkeKemTP::kDhkemX25519HkdfSha256, HpkeKdfTP::kHkdfSha384,
                      HpkeAeadTP::kAes256Gcm, HpkeParameters::Variant::kCrunchy,
                      HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                      HpkeParameters::KdfId::kHkdfSha384,
                      HpkeParameters::AeadId::kAesGcm256},
        RoundTripCase{OutputPrefixTypeTP::kRaw, HpkeKemTP::kDhkemP256HkdfSha256,
                      HpkeKdfTP::kHkdfSha512, HpkeAeadTP::kChacha20Poly1305,
                      HpkeParameters::Variant::kNoPrefix,
                      HpkeParameters::KemId::kDhkemP256HkdfSha256,
                      HpkeParameters::KdfId::kHkdfSha512,
                      HpkeParameters::AeadId::kChaCha20Poly1305},
        RoundTripCase{OutputPrefixTypeTP::kTink,
                      HpkeKemTP::kDhkemP384HkdfSha384, HpkeKdfTP::kHkdfSha384,
                      HpkeAeadTP::kAes256Gcm, HpkeParameters::Variant::kTink,
                      HpkeParameters::KemId::kDhkemP384HkdfSha384,
                      HpkeParameters::KdfId::kHkdfSha384,
                      HpkeParameters::AeadId::kAesGcm256},
        RoundTripCase{OutputPrefixTypeTP::kTink,
                      HpkeKemTP::kDhkemP521HkdfSha512, HpkeKdfTP::kHkdfSha512,
                      HpkeAeadTP::kAes256Gcm, HpkeParameters::Variant::kTink,
                      HpkeParameters::KemId::kDhkemP521HkdfSha512,
                      HpkeParameters::KdfId::kHkdfSha512,
                      HpkeParameters::AeadId::kAesGcm256},
        RoundTripCase{OutputPrefixTypeTP::kTink, HpkeKemTP::kMlKem768,
                      HpkeKdfTP::kHkdfSha256, HpkeAeadTP::kAes128Gcm,
                      HpkeParameters::Variant::kTink,
                      HpkeParameters::KemId::kMlKem768,
                      HpkeParameters::KdfId::kHkdfSha256,
                      HpkeParameters::AeadId::kAesGcm128},
        RoundTripCase{OutputPrefixTypeTP::kTink, HpkeKemTP::kMlKem1024,
                      HpkeKdfTP::kHkdfSha256, HpkeAeadTP::kAes256Gcm,
                      HpkeParameters::Variant::kTink,
                      HpkeParameters::KemId::kMlKem1024,
                      HpkeParameters::KdfId::kHkdfSha256,
                      HpkeParameters::AeadId::kAesGcm256}));

TEST(HpkeProtoStructsTest, LegacyParsesAsCrunchy) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParametersFromProto(OutputPrefixTypeTP::kLegacy,
                              Params(HpkeKemTP::kXWing, HpkeKdfTP::kHkdfSha256,
                                     HpkeAeadTP::kAes128Gcm));
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetVariant(), Eq(HpkeParameters::Variant::kCrunchy));
}

TEST(HpkeProtoStructsTest, RejectsUnknownValues) {
  EXPECT_THAT(
      HpkeParametersFromProto(OutputPrefixTypeTP::kUnknownPrefix,
                              Params(HpkeKemTP::kXWing, HpkeKdfTP::kHkdfSha256,
                                     HpkeAeadTP::kAes128Gcm))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(HpkeParametersFromProto(
                  OutputPrefixTypeTP::kTink,
                  Params(HpkeKemTP::kKemUnknown, HpkeKdfTP::kHkdfSha256,
                         HpkeAeadTP::kAes128Gcm))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      HpkeParametersFromProto(OutputPrefixTypeTP::kTink,
                              Params(HpkeKemTP::kXWing, HpkeKdfTP::kKdfUnknown,
                                     HpkeAeadTP::kAes128Gcm))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      HpkeParametersFromProto(OutputPrefixTypeTP::kTink,
                              Params(HpkeKemTP::kXWing, HpkeKdfTP::kHkdfSha256,
                                     HpkeAeadTP::kAeadUnknown))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
