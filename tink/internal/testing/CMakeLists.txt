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
    tink::internal::tink_proto_structs
    tink::util::test_util
)

tink_cc_test(
  NAME equals_proto_key_serialization_test
  SRCS
    equals_proto_key_serialization_test.cc
  DEPS
    tink::internal::testing::equals_proto_key_serialization
    gmock
    absl::statusor
    absl::string_view
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::internal::proto_key_serialization
    tink::internal::tink_proto_structs
    tink::util::test_matchers
)

tink_cc_library(
  NAME field_with_number
  SRCS
    field_with_number.cc
    field_with_number.h
  DEPS
    absl::absl_check
    absl::check
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    absl::span
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::internal::proto_key_serialization
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    tink::internal::tink_proto_structs
)

tink_cc_test(
  NAME field_with_number_test
  SRCS
    field_with_number_test.cc
  DEPS
    tink::internal::testing::equals_proto_key_serialization
    tink::internal::testing::field_with_number
    gmock
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::internal::proto_key_serialization
    tink::internal::tink_proto_structs
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME wycheproof_util
  SRCS
    wycheproof_util.cc
    wycheproof_util.h
  DEPS
    protobuf::libprotobuf
    absl::log
    absl::status
    absl::strings
    absl::string_view
    tink::internal::test_file_util
    tink::subtle::common_enums
    tink::util::status
    tink::util::statusor
  TESTONLY
)

tink_cc_test(
  NAME wycheproof_util_test
  SRCS
    wycheproof_util_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::internal::testing::wycheproof_util
    gmock
    tink::subtle::common_enums
    tink::util::test_matchers
)
