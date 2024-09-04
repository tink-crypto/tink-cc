tink_module(internal::testing)

tink_cc_library(
  NAME equals_proto_key_serialization
  SRCS
    equals_proto_key_serialization.h
  DEPS
    gmock
    absl::strings
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::util::test_util
)

tink_cc_test(
  NAME equals_proto_key_serialization_test
  SRCS
    equals_proto_key_serialization_test.cc
  DEPS
    tink::internal::testing::equals_proto_key_serialization
    gmock
    absl::string_view
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::internal::proto_key_serialization
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME field_with_number
  SRCS
    field_with_number.cc
    field_with_number.h
  DEPS
    absl::check
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    absl::span
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::internal::proto_key_serialization
    tink::internal::proto_parsing_helpers
)

tink_cc_test(
  NAME field_with_number_test
  SRCS
    field_with_number_test.cc
  DEPS
    tink::internal::testing::equals_proto_key_serialization
    tink::internal::testing::field_with_number
    gmock
    absl::strings
    absl::string_view
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::internal::proto_key_serialization
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)
