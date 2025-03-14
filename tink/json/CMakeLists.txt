tink_module(json)

add_subdirectory(internal)

tink_cc_library(
  NAME json_keyset_reader
  SRCS
    json_keyset_reader.cc
    json_keyset_reader.h
  DEPS
    absl::memory
    absl::status
    absl::string_view
    protobuf::libprotobuf
    tink::core::keyset_reader
    tink::json::internal::tink_type_resolver
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME json_keyset_writer
  SRCS
    json_keyset_writer.cc
    json_keyset_writer.h
  DEPS
    absl::status
    absl::string_view
    protobuf::libprotobuf
    tink::core::keyset_writer
    tink::json::internal::tink_type_resolver
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME json_keyset_reader_test
  SRCS
    json_keyset_reader_test.cc
  DEPS
    tink::json::json_keyset_reader
    gmock
    absl::status
    absl::statusor
    absl::strings
    tink::core::keyset_reader
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME json_keyset_writer_test
  SRCS
    json_keyset_writer_test.cc
  DEPS
    tink::json::json_keyset_reader
    tink::json::json_keyset_writer
    gmock
    absl::status
    absl::strings
    tink::core::binary_keyset_reader
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    tink::core::keyset_reader
    tink::core::keyset_writer
    tink::util::status
    tink::util::statusor
    tink::util::test_keyset_handle
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_gcm_siv_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
)
