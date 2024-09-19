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

#include "tink/internal/proto_parser_state.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/types/span.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {
using testing::Eq;

TEST(ParsingState, ConstructAndRemainingData) {
  std::string data = "data";
  ParsingState state = ParsingState(data);
  EXPECT_THAT(state.RemainingData(), Eq(data));
}

TEST(ParsingState, Peek) {
  std::string data = "data";
  ParsingState state = ParsingState(data);
  EXPECT_THAT(state.PeekByte(), Eq('d'));
}

TEST(ParsingState, Advance) {
  std::string data = "data";
  ParsingState state = ParsingState(data);
  state.Advance(2);
  EXPECT_THAT(state.PeekByte(), Eq('t'));
  EXPECT_THAT(state.RemainingData(), Eq("ta"));
}

TEST(ParsingState, AdvanceGetCrc) {
  std::string data = "data";
  ParsingState state = ParsingState(data);
  util::SecretValue<absl::crc32c_t> crc = state.AdvanceAndGetCrc(2);
  EXPECT_THAT(state.PeekByte(), Eq('t'));
  EXPECT_THAT(state.RemainingData(), Eq("ta"));
  EXPECT_THAT(crc.value(), Eq(absl::ComputeCrc32c("da")));
}

TEST(ParsingState, RemovePrefix) {
  std::string data = "data";
  ParsingState state = ParsingState(data);
  state.Advance(2);
  EXPECT_THAT(state.PeekByte(), Eq('t'));
  EXPECT_THAT(state.RemainingData(), Eq("ta"));
}

TEST(ParsingState, ParsingDone) {
  std::string data = "data";
  ParsingState state = ParsingState(data);
  EXPECT_THAT(state.ParsingDone(), Eq(false));
  state.Advance(2);
  EXPECT_THAT(state.ParsingDone(), Eq(false));
  state.Advance(2);
  EXPECT_THAT(state.ParsingDone(), Eq(true));
}

TEST(ParsingStateWithCrc, ConstructAndRemainingData) {
  std::string data = "data";
  absl::crc32c_t crc{};
  ParsingState state = ParsingState(data, &crc);
  EXPECT_THAT(state.RemainingData(), Eq(data));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c("")));
}

TEST(ParsingStateWithCrc, Advance) {
  std::string data = "data";
  absl::crc32c_t crc{};
  ParsingState state = ParsingState(data, &crc);
  state.Advance(2);
  EXPECT_THAT(state.PeekByte(), Eq('t'));
  EXPECT_THAT(state.RemainingData(), Eq("ta"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c("da")));
}

TEST(ParsingStateWithCrc, AdvanceGetCrc) {
  std::string data = "much data";
  absl::crc32c_t crc{};
  ParsingState state = ParsingState(data, &crc);
  state.Advance(5);  // Skip "much ".
  util::SecretValue<absl::crc32c_t> returned_crc = state.AdvanceAndGetCrc(2);
  EXPECT_THAT(state.PeekByte(), Eq('t'));
  EXPECT_THAT(state.RemainingData(), Eq("ta"));
  EXPECT_THAT(returned_crc.value(), Eq(absl::ComputeCrc32c("da")));
  state.Advance(2);  // Skip "ta".
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(data)));
}


TEST(SerializationState, ConstructAndBuffer) {
  std::string data = "data";
  SerializationState state = SerializationState(absl::MakeSpan(data));
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(data)));
}

TEST(SerializationState, Advance) {
  std::string data = "data";
  SerializationState state = SerializationState(absl::MakeSpan(data));
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(data)));
  state.Advance(2);
  std::string new_data = "ta";
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(new_data)));
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
