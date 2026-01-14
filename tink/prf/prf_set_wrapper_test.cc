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
#include "tink/prf/prf_set_wrapper.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_client_mocks.h"
#include "tink/internal/registry_impl.h"
#include "tink/prf/prf_set.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Key;
using ::testing::NiceMock;
using ::testing::Not;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::Test;
using ::testing::UnorderedElementsAre;

KeysetInfo::KeyInfo MakeKey(uint32_t id) {
  KeysetInfo::KeyInfo key;
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  key.set_key_id(id);
  key.set_status(KeyStatusType::ENABLED);
  return key;
}

class FakePrf : public Prf {
 public:
  explicit FakePrf(const std::string& output) : output_(output) {}
  absl::StatusOr<std::string> Compute(absl::string_view input,
                                      size_t output_length) const override {
    return output_;
  }

 private:
  std::string output_;
};

class PrfSetWrapperTest : public ::testing::Test {};

TEST_F(PrfSetWrapperTest, NullPrfSet) {
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(nullptr), Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, EmptyPrfSet) {
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(absl::make_unique<PrimitiveSet<Prf>>()).status(),
              Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, NonRawKeyType) {
  KeysetInfo::KeyInfo key_info = MakeKey(1);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  PrimitiveSet<Prf>::Builder prf_set_builder;
  prf_set_builder.AddPrimaryPrimitive(absl::make_unique<FakePrf>("output"),
                                      key_info);
  absl::StatusOr<PrimitiveSet<Prf>> prf_set =
      std::move(prf_set_builder).Build();
  ASSERT_THAT(prf_set, IsOk());
  PrfSetWrapper wrapper;
  EXPECT_THAT(
      wrapper.Wrap(std::make_unique<PrimitiveSet<Prf>>(*std::move(prf_set))),
      Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, WrapOkay) {
  PrimitiveSet<Prf>::Builder prf_set_builder;
  prf_set_builder.AddPrimaryPrimitive(absl::make_unique<FakePrf>("output"),
                                      MakeKey(1));
  absl::StatusOr<PrimitiveSet<Prf>> prf_set =
      std::move(prf_set_builder).Build();
  ASSERT_THAT(prf_set, IsOk());
  PrfSetWrapper wrapper;
  auto wrapped =
      wrapper.Wrap(std::make_unique<PrimitiveSet<Prf>>(*std::move(prf_set)));
  ASSERT_THAT(wrapped, IsOk());
  EXPECT_THAT(wrapped.value()->ComputePrimary("input", 6),
              IsOkAndHolds(StrEq("output")));
}

TEST_F(PrfSetWrapperTest, WrapTwo) {
  std::string primary_output("output");
  std::string secondary_output("different");
  PrimitiveSet<Prf>::Builder prf_set_builder;
  prf_set_builder.AddPrimaryPrimitive(
      absl::make_unique<FakePrf>(primary_output), MakeKey(1));
  prf_set_builder.AddPrimitive(absl::make_unique<FakePrf>(primary_output),
                               MakeKey(1));
  prf_set_builder.AddPrimitive(absl::make_unique<FakePrf>(secondary_output),
                               MakeKey(2));
  absl::StatusOr<PrimitiveSet<Prf>> prf_set =
      std::move(prf_set_builder).Build();
  ASSERT_THAT(prf_set, IsOk());

  PrfSetWrapper wrapper;
  auto wrapped_or =
      wrapper.Wrap(std::make_unique<PrimitiveSet<Prf>>(*std::move(prf_set)));
  ASSERT_THAT(wrapped_or, IsOk());
  auto wrapped = std::move(wrapped_or.value());
  EXPECT_THAT(wrapped->ComputePrimary("input", 6),
              IsOkAndHolds(StrEq("output")));
  const auto& prf_map = wrapped->GetPrfs();
  ASSERT_THAT(prf_map, UnorderedElementsAre(Key(1), Key(2)));
  EXPECT_THAT(prf_map.find(1)->second->Compute("input", 6),
              IsOkAndHolds(StrEq("output")));
  EXPECT_THAT(prf_map.find(2)->second->Compute("input", 6),
              IsOkAndHolds(StrEq("different")));
}

// Tests for the monitoring behavior.
class PrfSetWrapperWithMonitoringTest : public Test {
 protected:
  // Reset the global registry.
  void SetUp() override {
    Registry::Reset();
    // Setup mocks for catching Monitoring calls.
    auto monitoring_client_factory =
        absl::make_unique<internal::MockMonitoringClientFactory>();
    auto monitoring_client =
        absl::make_unique<NiceMock<internal::MockMonitoringClient>>();
    monitoring_client_ref_ = monitoring_client.get();
    // Monitoring tests expect that the client factory will create the
    // corresponding internal::MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(Return(
            ByMove(absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>(
                std::move(monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(testing::IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  ~PrfSetWrapperWithMonitoringTest() override { Registry::Reset(); }

  NiceMock<internal::MockMonitoringClient>* monitoring_client_ref_;
};

class AlwaysFailingPrf : public Prf {
 public:
  AlwaysFailingPrf() = default;

  absl::StatusOr<std::string> Compute(absl::string_view input,
                                      size_t output_length) const override {
    return absl::Status(absl::StatusCode::kOutOfRange, "AlwaysFailingPrf");
  }
};

TEST_F(PrfSetWrapperWithMonitoringTest, WrapKeysetWithMonitoringFailure) {
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  PrimitiveSet<Prf>::Builder prf_set_builder;
  prf_set_builder.AddAnnotations(annotations);
  prf_set_builder.AddPrimaryPrimitive(absl::make_unique<AlwaysFailingPrf>(),
                                      MakeKey(/*id=*/1));
  prf_set_builder.AddPrimitive(absl::make_unique<FakePrf>("output"),
                               MakeKey(/*id=*/1));
  absl::StatusOr<PrimitiveSet<Prf>> primitive_set =
      std::move(prf_set_builder).Build();
  ASSERT_THAT(primitive_set, IsOk());

  absl::StatusOr<std::unique_ptr<PrfSet>> prf_set = PrfSetWrapper().Wrap(
      std::make_unique<PrimitiveSet<Prf>>(*std::move(primitive_set)));
  ASSERT_THAT(prf_set, IsOk());
  EXPECT_CALL(*monitoring_client_ref_, LogFailure());
  EXPECT_THAT((*prf_set)->ComputePrimary("input", /*output_length=*/16),
              Not(IsOk()));
}

TEST_F(PrfSetWrapperWithMonitoringTest, WrapKeysetWithMonitoringVerifySuccess) {
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  PrimitiveSet<Prf>::Builder prf_set_builder;
  prf_set_builder.AddAnnotations(annotations);

  prf_set_builder.AddPrimaryPrimitive(absl::make_unique<FakePrf>("output"),
                                      MakeKey(/*id=*/1));
  prf_set_builder.AddPrimitive(absl::make_unique<FakePrf>("output"),
                               MakeKey(/*id=*/1));
  absl::StatusOr<PrimitiveSet<Prf>> primitive_set =
      std::move(prf_set_builder).Build();
  ASSERT_THAT(primitive_set, IsOk());

  absl::StatusOr<std::unique_ptr<PrfSet>> prf_set = PrfSetWrapper().Wrap(
      std::make_unique<PrimitiveSet<Prf>>(*std::move(primitive_set)));
  ASSERT_THAT(prf_set, IsOk());
  std::map<uint32_t, Prf*> prf_map = (*prf_set)->GetPrfs();
  std::string input = "input";
  for (const auto& entry : prf_map) {
    EXPECT_CALL(*monitoring_client_ref_, Log(entry.first, input.size()));
    EXPECT_THAT((entry.second)->Compute(input, /*output_length=*/16).status(),
                IsOk());
  }
  input = "hello_world";
  EXPECT_CALL(*monitoring_client_ref_,
              Log((*prf_set)->GetPrimaryId(), input.size()));
  EXPECT_THAT((*prf_set)->ComputePrimary(input, /*output_length=*/16), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
