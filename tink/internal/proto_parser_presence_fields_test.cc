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

#include "tink/internal/proto_parser_presence_fields.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Optional;
using ::testing::Test;

TEST(OptionalUint32Field, FieldNumberReturnsCorrectValue) {
  OptionalUint32Field field(1);
  EXPECT_THAT(field.FieldNumber(), Eq(1));
}

TEST(OptionalUint32Field, GetWireTypeReturnsCorrectValue) {
  OptionalUint32Field field(1);
  EXPECT_THAT(field.GetWireType(), Eq(WireType::kVarint));
}

TEST(OptionalUint32Field, Clear) {
  OptionalUint32Field field(1);
  field.set_value(123);
  field.Clear();
  EXPECT_THAT(field.value(), Eq(absl::nullopt));
}

TEST(OptionalUint32Field, ConsumeIntoMemberSuccessCases) {
  OptionalUint32Field field(1);
  field.set_value(123);
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Optional(128));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(OptionalUint32Field, ConsumeIntoMemberFailureCases) {
  OptionalUint32Field field(1);

  for (std::string test_case :
       {"", "faab",
        /* valid uint_64 encoding: */ "ffffffffffffffffffff01"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  }
}

TEST(OptionalUint32Field, GetSerializedSize) {
  OptionalUint32Field field(1);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  field.set_value(1);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  field.set_value(128);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(3));
}

TEST(OptionalUint32Field, SerializeWithNoValue) {
  OptionalUint32Field field(1);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsTrue());
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
}

TEST(OptionalUint32Field, SerializeWithZero) {
  OptionalUint32Field field(1);
  field.set_value(0);
  std::string expected_serialization = HexDecodeOrDie("0800");
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
              Eq(expected_serialization.size()));
  std::string buffer;
  buffer.resize(expected_serialization.size());
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsTrue());
  EXPECT_THAT(buffer, Eq(expected_serialization));
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
}

TEST(OptionalUint32Field, SerializeWithValue) {
  OptionalUint32Field field(1);
  field.set_value(128);
  std::string expected_serialization = HexDecodeOrDie("088001");
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
              Eq(expected_serialization.size()));
  std::string buffer;
  buffer.resize(expected_serialization.size());
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsTrue());
  EXPECT_THAT(buffer, Eq(expected_serialization));
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
}

TEST(OptionalUint32Field, SerializeWithValueTooSmallBuffer) {
  OptionalUint32Field field(1);
  field.set_value(128);
  std::string expected_serialization = HexDecodeOrDie("088001");
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
              Eq(expected_serialization.size()));
  std::string buffer;
  buffer.resize(expected_serialization.size() - 1);
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsFalse());
}

TEST(OptionalUint32Field, CopyConstructorWithValue) {
  OptionalUint32Field field(1);
  field.set_value(123);

  OptionalUint32Field copied_field(field);

  EXPECT_THAT(copied_field.value(), Optional(123));
}

TEST(OptionalUint32Field, CopyConstructorWithNoValue) {
  OptionalUint32Field field(1);

  OptionalUint32Field copied_field(field);

  EXPECT_THAT(copied_field.value(), Eq(absl::nullopt));
}

TEST(OptionalUint32Field, MoveConstructorWithValue) {
  OptionalUint32Field field(1);
  field.set_value(123);

  OptionalUint32Field moved_field(std::move(field));

  EXPECT_THAT(moved_field.value(), Optional(123));
}

TEST(OptionalUint32Field, MoveConstructorWithNoValue) {
  OptionalUint32Field field(1);

  OptionalUint32Field moved_field(std::move(field));

  EXPECT_THAT(moved_field.value(), Eq(absl::nullopt));
}

TEST(OptionalUint32Field, CopyAssignmentWithValue) {
  OptionalUint32Field field(1);
  field.set_value(123);

  OptionalUint32Field copied_field(2);
  copied_field = field;

  EXPECT_THAT(copied_field.value(), Optional(123));
}

TEST(OptionalUint32Field, CopyAssignmentWithNoValue) {
  OptionalUint32Field field(1);

  OptionalUint32Field copied_field(2);
  copied_field.set_value(123);
  copied_field = field;

  EXPECT_THAT(copied_field.value(), Eq(absl::nullopt));
}

TEST(OptionalUint32Field, MoveAssignmentWithValue) {
  OptionalUint32Field field(1);
  field.set_value(123);

  OptionalUint32Field moved_field(2);
  moved_field = std::move(field);

  EXPECT_THAT(moved_field.value(), Optional(123));
}

TEST(OptionalUint32Field, MoveAssignmentWithNoValue) {
  OptionalUint32Field field(1);

  OptionalUint32Field moved_field(2);
  moved_field.set_value(123);
  moved_field = std::move(field);

  EXPECT_THAT(moved_field.value(), Eq(absl::nullopt));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
