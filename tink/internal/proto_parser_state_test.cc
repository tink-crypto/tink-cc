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

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
