// Copyright 2024 Google LLC
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

#include "tink/internal/testing/ec_test_vectors.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/ec_util.h"
#include "tink/subtle/common_enums.h"

namespace crypto::tink::internal {
namespace {

using ::testing::Eq;
using ::testing::IsFalse;

TEST(EcTestVectorsTest, GetEcKeyP256) {
  const EcKey& key = GetEcKey(subtle::EllipticCurveType::NIST_P256);
  EXPECT_THAT(key.curve, Eq(subtle::EllipticCurveType::NIST_P256));
  EXPECT_THAT(key.pub_x.empty(), IsFalse());
  EXPECT_THAT(key.pub_y.empty(), IsFalse());
  EXPECT_THAT(key.priv.empty(), IsFalse());
}

TEST(EcTestVectorsTest, GetEcKeyP384) {
  const EcKey& key = GetEcKey(subtle::EllipticCurveType::NIST_P384);
  EXPECT_THAT(key.curve, Eq(subtle::EllipticCurveType::NIST_P384));
  EXPECT_THAT(key.pub_x.empty(), IsFalse());
  EXPECT_THAT(key.pub_y.empty(), IsFalse());
  EXPECT_THAT(key.priv.empty(), IsFalse());
}

TEST(EcTestVectorsTest, GetEcKeyP521) {
  const EcKey& key = GetEcKey(subtle::EllipticCurveType::NIST_P521);
  EXPECT_THAT(key.curve, Eq(subtle::EllipticCurveType::NIST_P521));
  EXPECT_THAT(key.pub_x.empty(), IsFalse());
  EXPECT_THAT(key.pub_y.empty(), IsFalse());
  EXPECT_THAT(key.priv.empty(), IsFalse());
}

TEST(EcTestVectorsTest, GetEcKeyCurve25519) {
  const EcKey& key = GetEcKey(subtle::EllipticCurveType::CURVE25519);
  EXPECT_THAT(key.curve, Eq(subtle::EllipticCurveType::CURVE25519));
  EXPECT_THAT(key.pub_x.empty(), IsFalse());
  EXPECT_THAT(key.priv.empty(), IsFalse());
}

TEST(EcTestVectorsTest, PointsAndSecrets) {
  EXPECT_THAT(P256Point().GetX().GetValue().empty(), IsFalse());
  EXPECT_THAT(P384Point().GetX().GetValue().empty(), IsFalse());
  EXPECT_THAT(P521Point().GetX().GetValue().empty(), IsFalse());
  EXPECT_THAT(X25519PublicValue().empty(), IsFalse());
}

}  // namespace
}  // namespace crypto::tink::internal
