tink_module(json::internal)

tink_cc_library(
  NAME tink_type_resolver
  SRCS
    tink_type_resolver.cc
    tink_type_resolver.h
  DEPS
    protobuf::libprotobuf
    absl::absl_check
    absl::strings
    absl::string_view
)

tink_cc_test(
  NAME tink_type_resolver_test
  SRCS
    tink_type_resolver_test.cc
  DEPS
    tink::json::internal::tink_type_resolver
    gmock
    protobuf::libprotobuf
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)
