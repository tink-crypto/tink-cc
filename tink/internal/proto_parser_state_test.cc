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

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {
using testing::Eq;
using testing::IsFalse;
using testing::IsTrue;

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
  absl::crc32c_t crc = state.AdvanceAndGetCrc(2);
  EXPECT_THAT(state.PeekByte(), Eq('t'));
  EXPECT_THAT(state.RemainingData(), Eq("ta"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c("da")));
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
  absl::crc32c_t returned_crc = state.AdvanceAndGetCrc(2);
  EXPECT_THAT(state.PeekByte(), Eq('t'));
  EXPECT_THAT(state.RemainingData(), Eq("ta"));
  EXPECT_THAT(returned_crc, Eq(absl::ComputeCrc32c("da")));
  state.Advance(2);  // Skip "ta".
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(data)));
}

TEST(ParsingState, HasCrc) {
  std::string data = "data";
  absl::crc32c_t crc{};
  EXPECT_THAT(ParsingState(data).HasCrc(), IsFalse());
  EXPECT_THAT(ParsingState(data, &crc).HasCrc(), IsTrue());
}

TEST(ParsingState, SplitOffSubmessageState) {
  std::string data = "data 1234 remainder";
  ParsingState state = ParsingState(data);
  EXPECT_THAT(state.RemainingData(), Eq("data 1234 remainder"));
  ParsingState submessage_state = state.SplitOffSubmessageState(9);
  EXPECT_THAT(submessage_state.RemainingData(), Eq("data 1234"));
  EXPECT_THAT(state.RemainingData(), Eq(" remainder"));
}

TEST(ParsingState, SplitOffSubmessageStateCrc) {
  std::string data = "data 1234 rem";
  absl::crc32c_t crc{};
  ParsingState state = ParsingState(data, &crc);
  EXPECT_THAT(state.RemainingData(), Eq("data 1234 rem"));
  ParsingState submessage_state = state.SplitOffSubmessageState(9);
  EXPECT_THAT(submessage_state.RemainingData(), Eq("data 1234"));
  EXPECT_THAT(state.RemainingData(), Eq(" rem"));

  // No data was processed yet.
  EXPECT_THAT(crc, Eq(absl::crc32c_t{}));
  submessage_state.Advance(5);  // Process "data "

  EXPECT_THAT(submessage_state.RemainingData(), Eq("1234"));
  EXPECT_THAT(state.RemainingData(), Eq(" rem"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c("data ")));

  submessage_state.Advance(4);  // Process "1234"
  state.Advance(4);             // Process "rem "
  EXPECT_THAT(submessage_state.RemainingData(), Eq(""));
  EXPECT_THAT(state.RemainingData(), Eq(""));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c("data 1234 rem")));
}

TEST(ParsingState, SplitOffSubmessageStateCrcWrongOrder) {
  std::string data = "onetwo";
  absl::crc32c_t crc{};
  ParsingState state = ParsingState(data, &crc);
  ParsingState submessage_state = state.SplitOffSubmessageState(3);
  EXPECT_THAT(submessage_state.RemainingData(), Eq("one"));
  EXPECT_THAT(state.RemainingData(), Eq("two"));
  state.Advance(3);
  submessage_state.Advance(3);
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c("twoone")));
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

TEST(SerializationState, AdvanceWithCrc) {
  std::string data = "data";
  SerializationState state = SerializationState(absl::MakeSpan(data));
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(data)));
  // The passed in CRC is ignored, but calling the method still works.
  state.AdvanceWithCrc(2, absl::crc32c_t{0x12345678});
  std::string new_data = "ta";
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(new_data)));
}

TEST(SerializationStateWithCrc, Advance) {
  std::string data = "data";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(data), &crc);
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(data)));
  state.Advance(2);
  std::string new_data = "ta";
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(new_data)));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c("da")));
}

TEST(SerializationStateWithCrc, AdvanceWithCrc) {
  std::string data = "data";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(data), &crc);
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(data)));
  // If we advance with a given value, the actual CRC is ignored.
  state.AdvanceWithCrc(2, absl::crc32c_t{0x12345678});
  std::string new_data = "ta";
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(new_data)));
  EXPECT_THAT(crc, Eq(absl::crc32c_t{0x12345678}));
}

TEST(SerializationState, HasCrc) {
  std::string data = "data";
  absl::crc32c_t crc{};
  EXPECT_THAT(SerializationState(absl::MakeSpan(data)).HasCrc(), IsFalse());
  EXPECT_THAT(SerializationState(absl::MakeSpan(data), &crc).HasCrc(),
              IsTrue());
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
