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
///////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/prf/streaming_prf_wrapper.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/primitive_set.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;

class DummyStreamingPrf : public StreamingPrf {
 public:
  explicit DummyStreamingPrf(absl::string_view name) : name_(name) {}
  std::unique_ptr<InputStream> ComputePrf(
      absl::string_view input) const override {
    return absl::make_unique<crypto::tink::util::IstreamInputStream>(
        absl::make_unique<std::stringstream>(
            absl::StrCat(name_.length(), ":", name_, input)));
  }

 private:
  std::string name_;
};

TEST(AeadSetWrapperTest, WrapNullptr) {
  StreamingPrfWrapper wrapper;
  EXPECT_THAT(
      wrapper.Wrap(nullptr).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-NULL")));
}

TEST(KeysetDeriverWrapperTest, WrapEmpty) {
  EXPECT_THAT(StreamingPrfWrapper()
                  .Wrap(absl::make_unique<PrimitiveSet<StreamingPrf>>())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("exactly one key")));
}

TEST(KeysetDeriverWrapperTest, WrapSingle) {
  PrimitiveSet<StreamingPrf>::Builder prf_set_builder;
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::RAW);

  prf_set_builder.AddPrimaryPrimitive(
      absl::make_unique<DummyStreamingPrf>("single_key"), key_info);

  absl::StatusOr<PrimitiveSet<StreamingPrf>> prf_set =
      std::move(prf_set_builder).Build();

  ASSERT_THAT(prf_set, IsOk());

  auto wrapped_prf = StreamingPrfWrapper().Wrap(
      std::make_unique<PrimitiveSet<StreamingPrf>>(*std::move(prf_set)));

  ASSERT_THAT(wrapped_prf, IsOk());

  auto prf_output = ReadBytesFromStream(
      23, wrapped_prf.value()->ComputePrf("input_text").get());
  ASSERT_THAT(prf_output, IsOk());
  EXPECT_THAT(prf_output.value(), Eq("10:single_keyinput_text"));
}

TEST(KeysetDeriverWrapperTest, WrapNonRaw) {
  PrimitiveSet<StreamingPrf>::Builder prf_set_builder;
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);

  prf_set_builder.AddPrimaryPrimitive(
      absl::make_unique<DummyStreamingPrf>("single_key"), key_info);
  absl::StatusOr<PrimitiveSet<StreamingPrf>> prf_set =
      std::move(prf_set_builder).Build();
  ASSERT_THAT(prf_set, IsOk());

  EXPECT_THAT(StreamingPrfWrapper()
                  .Wrap(std::make_unique<PrimitiveSet<StreamingPrf>>(
                      *std::move(prf_set)))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("output_prefix_type")));
}

TEST(KeysetDeriverWrapperTest, WrapMultiple) {
  PrimitiveSet<StreamingPrf>::Builder prf_set_builder;
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::RAW);

  prf_set_builder.AddPrimaryPrimitive(
      absl::make_unique<DummyStreamingPrf>("single_key"), key_info);
  key_info.set_key_id(2345);
  prf_set_builder.AddPrimitive(
      absl::make_unique<DummyStreamingPrf>("second_key"), key_info);
  absl::StatusOr<PrimitiveSet<StreamingPrf>> prf_set =
      std::move(prf_set_builder).Build();
  ASSERT_THAT(prf_set, IsOk());
  EXPECT_THAT(StreamingPrfWrapper()
                  .Wrap(std::make_unique<PrimitiveSet<StreamingPrf>>(
                      *std::move(prf_set)))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("given set has 2 keys")));
}


}  // namespace
}  // namespace tink
}  // namespace crypto
