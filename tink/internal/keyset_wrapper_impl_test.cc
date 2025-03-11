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
#include "tink/internal/keyset_wrapper_impl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/ssl_util.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/restricted_data.h"
#include "tink/subtle/xchacha20_poly1305_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::AddKeyData;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::Keyset;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::Pair;
using ::testing::Pointee;
using ::testing::UnorderedElementsAre;

using InputPrimitive = std::string;
using OutputPrimitive = std::vector<std::pair<int, std::string>>;

// This "Wrapper" wraps primitives of type std::string into primitives of type
// std::vector<int, std::string> simply by returning pairs {key_id, string}.
// It appends " (primary)" to the string for the primary id.
class Wrapper : public PrimitiveWrapper<InputPrimitive, OutputPrimitive> {
 public:
  absl::StatusOr<std::unique_ptr<OutputPrimitive>> Wrap(
      std::unique_ptr<PrimitiveSet<InputPrimitive>> primitive_set)
      const override {
    auto result = absl::make_unique<OutputPrimitive>();
    for (const auto* entry : primitive_set->get_all()) {
      (*result).push_back(
          std::make_pair(entry->get_key_id(), entry->get_primitive()));
      if (entry->get_key_id() == primitive_set->get_primary()->get_key_id()) {
        result->back().second.append(" (primary)");
      }
    }
    return std::move(result);
  }
};

absl::StatusOr<std::unique_ptr<InputPrimitive>> CreateIn(
    const google::crypto::tink::KeyData& key_data) {
  if (absl::StartsWith(key_data.type_url(), "error:")) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        key_data.type_url());
  } else {
    return absl::make_unique<InputPrimitive>(key_data.type_url());
  }
}

absl::StatusOr<std::unique_ptr<InputPrimitive>> CreateInFromKey(
    const Key& key) {
  return absl::make_unique<InputPrimitive>("input primitive from key");
}

absl::StatusOr<std::unique_ptr<InputPrimitive>> CreateInFromKeyFailing(
    const Key& key) {
  return absl::Status(absl::StatusCode::kNotFound, "Not found.");
}

// Creates an XChaCha20Poly1305Key from the given parameters.
absl::StatusOr<std::unique_ptr<XChaCha20Poly1305Key>>
CreateXChaCha20Poly1305Key(const XChaCha20Poly1305Parameters& params,
                           absl::optional<int> id_requirement) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      params.GetVariant(), secret, id_requirement, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<XChaCha20Poly1305Key>(*key);
}

absl::StatusOr<std::unique_ptr<Aead>> GetPrimitiveFromXChaCha20Poly1305KeyData(
    const google::crypto::tink::KeyData& key_data) {
  google::crypto::tink::XChaCha20Poly1305Key key;
  if (!key.ParseFromString(key_data.value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse XChaCha20Poly1305Key proto");
  }
  return subtle::XChacha20Poly1305BoringSsl::New(
      util::SecretDataFromStringView(key.key_value()));
}

absl::StatusOr<std::unique_ptr<Aead>> GetPrimitiveFromXChaCha20Poly1305Key(
    const Key& key) {
  XChaCha20Poly1305Key xchacha_key =
      dynamic_cast<const XChaCha20Poly1305Key&>(key);
  return subtle::XChacha20Poly1305BoringSsl::New(
      (xchacha_key.GetKeyBytes(GetPartialKeyAccess())
           .Get(InsecureSecretKeyAccess::Get())));
}

google::crypto::tink::KeyData OnlyTypeUrlKeyData(absl::string_view type_url) {
  google::crypto::tink::KeyData result;
  result.set_type_url(std::string(type_url));
  return result;
}

google::crypto::tink::Keyset CreateKeyset(
    const std::vector<std::pair<int, std::string>>& keydata) {
  google::crypto::tink::Keyset keyset;
  for (const auto& pair : keydata) {
    AddKeyData(OnlyTypeUrlKeyData(pair.second), pair.first,
               google::crypto::tink::OutputPrefixType::TINK,
               google::crypto::tink::KeyStatusType::ENABLED, &keyset);
  }
  return keyset;
}

TEST(KeysetWrapperImplTest, Basic) {
  Wrapper wrapper;
  auto wrapper_impl =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn, &CreateInFromKeyFailing);
  std::vector<std::pair<int, std::string>> keydata = {
      {111, "one"}, {222, "two"}, {333, "three"}};
  google::crypto::tink::Keyset keyset = CreateKeyset(keydata);
  keyset.set_primary_key_id(222);

  absl::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_impl->Wrap(keyset, /*annotations=*/{});

  ASSERT_THAT(wrapped, IsOk());
  ASSERT_THAT(*wrapped.value(),
              UnorderedElementsAre(Pair(111, "one"), Pair(222, "two (primary)"),
                                   Pair(333, "three")));
}

using KeysetWrapperImplTest =
    testing::TestWithParam<XChaCha20Poly1305Parameters::Variant>;

INSTANTIATE_TEST_SUITE_P(
    KeysetWrapperImplTestSuite, KeysetWrapperImplTest,
    testing::Values(XChaCha20Poly1305Parameters::Variant::kTink,
                    XChaCha20Poly1305Parameters::Variant::kNoPrefix));

TEST_P(KeysetWrapperImplTest, BasicFromKey) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  XChaCha20Poly1305Parameters::Variant variant = GetParam();
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(variant);

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_gen_config),
              IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled,
          /*is_primary=*/true, /*id=*/111);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled, /*is_primary=*/false, /*id=*/222);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle.status(), IsOk());

  Wrapper wrapper;
  auto wrapper_impl =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn, &CreateInFromKey);

  absl::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped = wrapper_impl->Wrap(
      TestKeysetHandle::GetKeyset(*handle), /*annotations=*/{});
  ASSERT_THAT(wrapped, IsOk());
  ASSERT_THAT(
      *wrapped.value(),
      UnorderedElementsAre(Pair(111, "input primitive from key (primary)"),
                           Pair(222, "input primitive from key")));
}

TEST_P(KeysetWrapperImplTest, AeadEncryptDecryptWorks) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "XChaCha20-Poly1305 is not supported when OpenSSL is used";
  }
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  XChaCha20Poly1305Parameters::Variant variant = GetParam();
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(variant);

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_gen_config),
              IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled,
          /*is_primary=*/true, /*id=*/111);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled, /*is_primary=*/false, /*id=*/222);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle.status(), IsOk());

  AeadWrapper wrapper;
  auto wrapper_impl = absl::make_unique<KeysetWrapperImpl<Aead, Aead>>(
      &wrapper, &GetPrimitiveFromXChaCha20Poly1305KeyData,
      &GetPrimitiveFromXChaCha20Poly1305Key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = wrapper_impl->Wrap(
      TestKeysetHandle::GetKeyset(*handle), /*annotations=*/{});
  ASSERT_THAT(aead, IsOk());

  // Check that encrypt/decrypt works.
  const std::string plaintext = "plaintext";
  const std::string associated_data = "associated_data";
  absl::StatusOr<std::string> encryption =
      (*aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(encryption, IsOk());
  absl::StatusOr<std::string> decryption =
      (*aead)->Decrypt(*encryption, associated_data);
  ASSERT_THAT(decryption, IsOk());
  EXPECT_THAT(*decryption, Eq(plaintext));
}

TEST_P(KeysetWrapperImplTest,
       AeadEncryptDecryptFailingPrimitiveGetterFromKeyFallsBackToKeyData) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "XChaCha20-Poly1305 is not supported when OpenSSL is used";
  }
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  XChaCha20Poly1305Parameters::Variant variant = GetParam();
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(variant);

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_gen_config),
              IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled,
          /*is_primary=*/true, /*id=*/111);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled, /*is_primary=*/false, /*id=*/222);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle.status(), IsOk());

  auto aead_primitive_getter_failing =
      [](const Key& key) -> absl::StatusOr<std::unique_ptr<Aead>> {
    return absl::Status(absl::StatusCode::kNotFound, "Not implemented.");
  };
  AeadWrapper wrapper;
  auto wrapper_impl = absl::make_unique<KeysetWrapperImpl<Aead, Aead>>(
      &wrapper, &GetPrimitiveFromXChaCha20Poly1305KeyData,
      aead_primitive_getter_failing);
  absl::StatusOr<std::unique_ptr<Aead>> aead = wrapper_impl->Wrap(
      TestKeysetHandle::GetKeyset(*handle), /*annotations=*/{});
  ASSERT_THAT(aead, IsOk());

  // Check that encrypt/decrypt works.
  const std::string plaintext = "plaintext";
  const std::string associated_data = "associated_data";
  absl::StatusOr<std::string> encryption =
      (*aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(encryption, IsOk());
  absl::StatusOr<std::string> decryption =
      (*aead)->Decrypt(*encryption, associated_data);
  ASSERT_THAT(decryption, IsOk());
  EXPECT_THAT(*decryption, Eq(plaintext));
}

// Test values are taken from the test vector tcId 2 of the
// Wycheproof tests:
// https://github.com/google/wycheproof/blob/master/testvectors/xchacha20_poly1305_test.json#L33
TEST(KeysetWrapperImpl2Test, AeadEncryptDecryptFixedValuesWorks) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "XChaCha20-Poly1305 is not supported when OpenSSL is used";
  }
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kTink,
      RestrictedData(test::HexDecodeOrDie("ab1562faea9f47af3ae1c3d6d030e3af23"
                                          "0255dff3df583ced6fbbcbf9d606a9"),
                     InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(*key,
                                                        KeyStatus::kEnabled,
                                                        /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry0)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  AeadWrapper wrapper;
  auto wrapper_impl = absl::make_unique<KeysetWrapperImpl<Aead, Aead>>(
      &wrapper, &GetPrimitiveFromXChaCha20Poly1305KeyData,
      &GetPrimitiveFromXChaCha20Poly1305Key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = wrapper_impl->Wrap(
      TestKeysetHandle::GetKeyset(*handle), /*annotations=*/{});
  ASSERT_THAT(aead, IsOk());

  // Check that encrypt/decrypt works.
  absl::StatusOr<std::string> encryption =
      (*aead)->Encrypt(/*plaintext=*/"", /*associated_data=*/"");
  ASSERT_THAT(encryption, IsOk());
  EXPECT_THAT(encryption->size(), Eq(key->GetOutputPrefix().size() +
                                     /*tag_size=*/16 + /*nonce_size=*/24));
  absl::StatusOr<std::string> decryption =
      (*aead)->Decrypt(*encryption, /*associated_data=*/"");
  EXPECT_THAT(encryption->substr(0, key->GetOutputPrefix().size()),
              Eq(key->GetOutputPrefix()));
  ASSERT_THAT(decryption, IsOk());
  EXPECT_THAT(*decryption, Eq(""));

  // Check decryption with the fixed ciphertext.
  std::string fixed_ct = test::HexDecodeOrDie(
      absl::StrCat(/*tink_prefix*/ "01",
                   /*key_id*/ "02030405",
                   /*iv*/ "6a5e0c4617e07091b605a4de2c02dde117de2ebd53b23497",
                   /*ct*/ "", /*tag*/ "e2697ea6877aba39d9555a00e14db041"));
  absl::StatusOr<std::string> fixed_ct_decryption =
      (*aead)->Decrypt(fixed_ct, /*associated_data=*/"");
  ASSERT_THAT(fixed_ct_decryption, IsOk());
  EXPECT_THAT(*fixed_ct_decryption, Eq(""));
}

TEST(KeysetWrapperImplTest, FailingGetPrimitive) {
  Wrapper wrapper;
  auto wrapper_impl =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn, &CreateInFromKeyFailing);
  std::vector<std::pair<int, std::string>> keydata = {{1, "ok:one"},
                                                      {2, "error:two"}};
  google::crypto::tink::Keyset keyset = CreateKeyset(keydata);
  keyset.set_primary_key_id(1);

  absl::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_impl->Wrap(keyset, /*annotations=*/{});

  ASSERT_THAT(wrapped, Not(IsOk()));
  ASSERT_THAT(std::string(wrapped.status().message()), HasSubstr("error:two"));
}

// This test checks that validate keyset is called. We simply pass an empty
// keyset.
TEST(KeysetWrapperImplTest, ValidatesKeyset) {
  Wrapper wrapper;
  auto wrapper_impl =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn, &CreateInFromKey);
  absl::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_impl->Wrap(google::crypto::tink::Keyset(), /*annotations=*/{});

  ASSERT_THAT(wrapped, Not(IsOk()));
}

// This test checks that only enabled keys are used to create the primitive set.
TEST(KeysetWrapperImplTest, OnlyEnabled) {
  Wrapper wrapper;
  auto wrapper_impl =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn, &CreateInFromKey);
  std::vector<std::pair<int, std::string>> keydata = {
      {111, "one"}, {222, "two"}, {333, "three"}, {444, "four"}};
  google::crypto::tink::Keyset keyset = CreateKeyset(keydata);
  keyset.set_primary_key_id(222);
  // KeyId 333 is index 2.
  keyset.mutable_key(2)->set_status(google::crypto::tink::DISABLED);
  absl::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_impl->Wrap(keyset, /*annotations=*/{});

  ASSERT_THAT(wrapped, IsOk());
  // Parsing failed, so fell back to the legacy way.
  ASSERT_THAT(*wrapped.value(),
              UnorderedElementsAre(Pair(111, "one"), Pair(222, "two (primary)"),
                                   Pair(444, "four")));
}

// Mock PrimitiveWrapper with input primitive I and output primitive O.
template <class I, class O>
class MockWrapper : public PrimitiveWrapper<I, O> {
 public:
  MOCK_METHOD(absl::StatusOr<std::unique_ptr<O>>, Wrap,
              (std::unique_ptr<PrimitiveSet<I>> primitive_set),
              (const, override));
};

// Returns a valid output primitive.
std::unique_ptr<OutputPrimitive> GetOutputPrimitiveForTesting() {
  auto output_primitive = absl::make_unique<OutputPrimitive>();
  output_primitive->push_back({111, "one"});
  output_primitive->push_back({222, "two (primary)"});
  output_primitive->push_back({333, "three"});
  output_primitive->push_back({444, "four"});
  return output_primitive;
}

// Tests that annotations are correctly passed on to the generated PrimitiveSet.
TEST(KeysetWrapperImplTest, WrapWithAnnotationCorrectlyWrittenToPrimitiveSet) {
  MockWrapper<InputPrimitive, OutputPrimitive> wrapper;
  auto keyset_wrapper =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, CreateIn, CreateInFromKeyFailing);
  Keyset keyset = CreateKeyset(
      /*keydata=*/{{111, "one"}, {222, "two"}, {333, "three"}, {444, "four"}});
  keyset.set_primary_key_id(222);
  const absl::flat_hash_map<std::string, std::string> kExpectedAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};

  absl::flat_hash_map<std::string, std::string> generated_annotations;
  EXPECT_CALL(wrapper, Wrap(testing::_))
      .WillOnce(
          [&generated_annotations](std::unique_ptr<PrimitiveSet<InputPrimitive>>
                                       generated_primitive_set) {
            // We are interested to check if the annotations are what we
            // expected, so we copy them to `generated_annotations`.
            generated_annotations = generated_primitive_set->get_annotations();
            // Return a valid output primitive.
            return GetOutputPrimitiveForTesting();
          });

  absl::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped_primitive =
      keyset_wrapper->Wrap(keyset, kExpectedAnnotations);

  EXPECT_EQ(generated_annotations, kExpectedAnnotations);
  EXPECT_THAT(wrapped_primitive,
              IsOkAndHolds(Pointee(UnorderedElementsAre(
                  Pair(111, "one"), Pair(222, "two (primary)"),
                  Pair(333, "three"), Pair(444, "four")))));
}

}  // namespace

}  // namespace internal
}  // namespace tink
}  // namespace crypto
