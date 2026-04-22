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

#include "tink/internal/legacy_annotations.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Pair;
using ::testing::UnorderedElementsAre;

TEST(LegacyAnnotationsTest, CreateAndGet) {
  absl::flat_hash_map<std::string, std::string> map;
  map["key1"] = "value1";
  map["key2"] = "value2";

  LegacyAnnotations annotations(map);

  EXPECT_THAT(
      annotations.GetMap(),
      UnorderedElementsAre(Pair("key1", "value1"), Pair("key2", "value2")));
}

TEST(LegacyAnnotationsTest, CopyConstructor) {
  absl::flat_hash_map<std::string, std::string> map;
  map["key1"] = "value1";
  map["key2"] = "value2";
  LegacyAnnotations annotations(map);

  LegacyAnnotations annotations2(annotations);

  EXPECT_THAT(
      annotations2.GetMap(),
      UnorderedElementsAre(Pair("key1", "value1"), Pair("key2", "value2")));
}

TEST(LegacyAnnotationsTest, CopyAssignment) {
  absl::flat_hash_map<std::string, std::string> map;
  map["key1"] = "value1";
  map["key2"] = "value2";
  LegacyAnnotations annotations(map);
  LegacyAnnotations annotations2({});

  annotations2 = annotations;

  EXPECT_THAT(
      annotations2.GetMap(),
      UnorderedElementsAre(Pair("key1", "value1"), Pair("key2", "value2")));
}

TEST(LegacyAnnotationsTest, MoveConstructor) {
  absl::flat_hash_map<std::string, std::string> map;
  map["key1"] = "value1";
  map["key2"] = "value2";
  LegacyAnnotations annotations(map);

  LegacyAnnotations annotations2(std::move(annotations));

  EXPECT_THAT(
      annotations2.GetMap(),
      UnorderedElementsAre(Pair("key1", "value1"), Pair("key2", "value2")));
}

TEST(LegacyAnnotationsTest, MoveAssignment) {
  absl::flat_hash_map<std::string, std::string> map;
  map["key1"] = "value1";
  map["key2"] = "value2";
  LegacyAnnotations annotations(map);
  LegacyAnnotations annotations2({});

  annotations2 = std::move(annotations);

  EXPECT_THAT(
      annotations2.GetMap(),
      UnorderedElementsAre(Pair("key1", "value1"), Pair("key2", "value2")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
