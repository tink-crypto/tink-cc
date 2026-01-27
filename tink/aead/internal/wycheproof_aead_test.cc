// Copyright 2024 Google LLC
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
#include "tink/aead/internal/wycheproof_aead.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_util.h"

namespace {

using ::crypto::tink::internal::ReadWycheproofTestVectors;
using ::crypto::tink::internal::WycheproofTestVector;
using ::crypto::tink::test::HexDecodeOrDie;
using ::testing::Eq;

TEST(WycheproofAeadTest, ReadWycheproofTestVectors) {
  std::vector<WycheproofTestVector> test_vectors =
      ReadWycheproofTestVectors("aes_gcm_test.json");
  EXPECT_THAT(test_vectors.size(), 316);

  WycheproofTestVector entry = test_vectors.at(0);

  EXPECT_THAT(entry.comment, Eq(""));
  EXPECT_THAT(entry.key,
              Eq(HexDecodeOrDie("5b9604fe14eadba931b0ccf34843dab9")));
  EXPECT_THAT(entry.nonce, Eq(HexDecodeOrDie("028318abc1824029138141a2")));
  EXPECT_THAT(entry.msg,
              Eq(HexDecodeOrDie("001d0c231287c1182784554ca3a21908")));
  EXPECT_THAT(entry.ct, Eq(HexDecodeOrDie("26073cc1d851beff176384dc9896d5ff")));
  EXPECT_THAT(entry.aad, Eq(""));
  EXPECT_THAT(entry.tag,
              Eq(HexDecodeOrDie("0a3ea7a5487cb5f7d70fb6c58d038554")));
  EXPECT_THAT(entry.id, Eq("1"));
  EXPECT_THAT(entry.expected, Eq("valid"));
}
}  // namespace
