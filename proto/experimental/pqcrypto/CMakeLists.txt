tink_cc_proto(
  NAME cecpq2_aead_hkdf_cc_proto
  SRCS cecpq2_aead_hkdf.proto
  DEPS
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_proto(
  NAME ml_dsa_cc_proto
  SRCS ml_dsa.proto
  DEPS
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_proto(
  NAME ml_kem_cc_proto
  SRCS ml_kem.proto
  DEPS
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)
