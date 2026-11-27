#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# Checks that all TINK_INTERNAL_RTTI_SET_TYPE_ID and
# TINK_INTERNAL_RTTI_COMPUTE_TYPE_ID usages in <source_dir> specify unique
# decimal integer literals in [1, 32767] and match the expected "<id> <file>"
# registry list.

# Generated with openssl rand -hex 10
echo "========================================================================="
echo "Tink Script ID: 9c4e17a83b05d2f641e9 (quickly find the script from logs)"
echo "========================================================================="

set -euo pipefail

# We currently hard code the list of files with IDs here -- this might or might
# not be useful. If it is annoying, please delete this part of the test.

DEFAULT_EXPECTED_IDS="$(cat <<'EOF'
1 //third_party/tink/cc/parameters.h
2 //third_party/tink/cc/key.h
3 //third_party/tink/cc/private_key.h
4 //third_party/tink/cc/internal/serialization.h
5 //third_party/tink/cc/internal/proto_key_serialization.h
6 //third_party/tink/cc/internal/proto_parameters_serialization.h
7 //third_party/tink/cc/internal/legacy_proto_key.h
8 //third_party/tink/cc/internal/legacy_proto_key.h
9 //third_party/tink/cc/internal/legacy_proto_parameters.h
50 //third_party/tink/cc/aead.h
51 //third_party/tink/cc/chunked_mac.h
52 //third_party/tink/cc/deterministic_aead.h
53 //third_party/tink/cc/hybrid_decrypt.h
54 //third_party/tink/cc/hybrid_encrypt.h
55 //third_party/tink/cc/mac.h
56 //third_party/tink/cc/public_key_sign.h
57 //third_party/tink/cc/public_key_verify.h
58 //third_party/tink/cc/streaming_aead.h
59 //third_party/tink/cc/streaming_mac.h
61 //third_party/tink/cc/prf/prf_set.h
62 //third_party/tink/cc/prf/prf_set.h
63 //third_party/tink/cc/keyderivation/keyset_deriver.h
67 //third_party/tink/cc/kem/kem_decapsulate.h
68 //third_party/tink/cc/kem/kem_encapsulate.h
69 //third_party/tink/cc/signature/prehash.h
70 //third_party/tink/cc/signature/sign_prehash.h
71 //third_party/tink/cc/signature/chunked_prehash.h
77 //third_party/tink/cc/subtle/prf/streaming_prf.h
101 //third_party/tink/cc/mac/mac_parameters.h
102 //third_party/tink/cc/mac/mac_key.h
103 //third_party/tink/cc/mac/hmac_parameters.h
104 //third_party/tink/cc/mac/hmac_key.h
105 //third_party/tink/cc/mac/aes_cmac_parameters.h
106 //third_party/tink/cc/mac/aes_cmac_key.h
201 //third_party/tink/cc/aead/aead_parameters.h
202 //third_party/tink/cc/aead/aead_key.h
203 //third_party/tink/cc/aead/aes_ctr_hmac_aead_parameters.h
204 //third_party/tink/cc/aead/aes_ctr_hmac_aead_key.h
205 //third_party/tink/cc/aead/aes_eax_parameters.h
206 //third_party/tink/cc/aead/aes_eax_key.h
207 //third_party/tink/cc/aead/aes_gcm_parameters.h
208 //third_party/tink/cc/aead/aes_gcm_key.h
209 //third_party/tink/cc/aead/aes_gcm_siv_parameters.h
210 //third_party/tink/cc/aead/aes_gcm_siv_key.h
211 //third_party/tink/cc/aead/chacha20_poly1305_parameters.h
212 //third_party/tink/cc/aead/chacha20_poly1305_key.h
213 //third_party/tink/cc/aead/legacy_kms_aead_parameters.h
214 //third_party/tink/cc/aead/legacy_kms_aead_key.h
215 //third_party/tink/cc/aead/legacy_kms_envelope_aead_parameters.h
216 //third_party/tink/cc/aead/legacy_kms_envelope_aead_key.h
217 //third_party/tink/cc/aead/x_aes_gcm_parameters.h
218 //third_party/tink/cc/aead/x_aes_gcm_key.h
219 //third_party/tink/cc/aead/xchacha20_poly1305_parameters.h
220 //third_party/tink/cc/aead/xchacha20_poly1305_key.h
301 //third_party/tink/cc/prf/prf_parameters.h
302 //third_party/tink/cc/prf/prf_key.h
303 //third_party/tink/cc/prf/aes_cmac_prf_parameters.h
304 //third_party/tink/cc/prf/aes_cmac_prf_key.h
305 //third_party/tink/cc/prf/hkdf_prf_parameters.h
306 //third_party/tink/cc/prf/hkdf_prf_key.h
307 //third_party/tink/cc/prf/hmac_prf_parameters.h
308 //third_party/tink/cc/prf/hmac_prf_key.h
401 //third_party/tink/cc/daead/deterministic_aead_parameters.h
402 //third_party/tink/cc/daead/deterministic_aead_key.h
403 //third_party/tink/cc/daead/aes_siv_parameters.h
404 //third_party/tink/cc/daead/aes_siv_key.h
501 //third_party/tink/cc/keyderivation/key_derivation_parameters.h
502 //third_party/tink/cc/keyderivation/key_derivation_key.h
503 //third_party/tink/cc/keyderivation/prf_based_key_derivation_parameters.h
504 //third_party/tink/cc/keyderivation/prf_based_key_derivation_key.h
601 //third_party/tink/cc/streamingaead/streaming_aead_parameters.h
602 //third_party/tink/cc/streamingaead/streaming_aead_key.h
603 //third_party/tink/cc/streamingaead/aes_ctr_hmac_streaming_parameters.h
604 //third_party/tink/cc/streamingaead/aes_ctr_hmac_streaming_key.h
605 //third_party/tink/cc/streamingaead/aes_gcm_hkdf_streaming_parameters.h
606 //third_party/tink/cc/streamingaead/aes_gcm_hkdf_streaming_key.h
701 //third_party/tink/cc/experimental/kem/kem_parameters.h
702 //third_party/tink/cc/experimental/kem/kem_public_key.h
703 //third_party/tink/cc/experimental/kem/kem_private_key.h
704 //third_party/tink/cc/experimental/pqcrypto/kem/ml_kem_parameters.h
705 //third_party/tink/cc/experimental/pqcrypto/kem/ml_kem_public_key.h
706 //third_party/tink/cc/experimental/pqcrypto/kem/ml_kem_private_key.h
801 //third_party/tink/cc/signature/signature_parameters.h
802 //third_party/tink/cc/signature/signature_public_key.h
803 //third_party/tink/cc/signature/signature_private_key.h
804 //third_party/tink/cc/signature/ecdsa_parameters.h
805 //third_party/tink/cc/signature/ecdsa_public_key.h
806 //third_party/tink/cc/signature/ecdsa_private_key.h
807 //third_party/tink/cc/signature/ed25519_parameters.h
808 //third_party/tink/cc/signature/ed25519_public_key.h
809 //third_party/tink/cc/signature/ed25519_private_key.h
810 //third_party/tink/cc/signature/rsa_ssa_pkcs1_parameters.h
811 //third_party/tink/cc/signature/rsa_ssa_pkcs1_public_key.h
812 //third_party/tink/cc/signature/rsa_ssa_pkcs1_private_key.h
813 //third_party/tink/cc/signature/rsa_ssa_pss_parameters.h
814 //third_party/tink/cc/signature/rsa_ssa_pss_public_key.h
815 //third_party/tink/cc/signature/rsa_ssa_pss_private_key.h
816 //third_party/tink/cc/signature/ml_dsa_parameters.h
817 //third_party/tink/cc/signature/ml_dsa_public_key.h
818 //third_party/tink/cc/signature/ml_dsa_private_key.h
819 //third_party/tink/cc/signature/slh_dsa_parameters.h
820 //third_party/tink/cc/signature/slh_dsa_public_key.h
821 //third_party/tink/cc/signature/slh_dsa_private_key.h
822 //third_party/tink/cc/signature/composite_ml_dsa_parameters.h
823 //third_party/tink/cc/signature/composite_ml_dsa_public_key.h
824 //third_party/tink/cc/signature/composite_ml_dsa_private_key.h
901 //third_party/tink/cc/hybrid/hybrid_parameters.h
902 //third_party/tink/cc/hybrid/hybrid_public_key.h
903 //third_party/tink/cc/hybrid/hybrid_private_key.h
904 //third_party/tink/cc/hybrid/ecies_parameters.h
905 //third_party/tink/cc/hybrid/ecies_public_key.h
906 //third_party/tink/cc/hybrid/ecies_private_key.h
907 //third_party/tink/cc/hybrid/hpke_parameters.h
908 //third_party/tink/cc/hybrid/hpke_public_key.h
909 //third_party/tink/cc/hybrid/hpke_private_key.h
1001 //third_party/tink/cc/jwt/jwt_mac_parameters.h
1002 //third_party/tink/cc/jwt/jwt_mac_key.h
1003 //third_party/tink/cc/jwt/jwt_hmac_parameters.h
1004 //third_party/tink/cc/jwt/jwt_hmac_key.h
1005 //third_party/tink/cc/jwt/jwt_signature_parameters.h
1006 //third_party/tink/cc/jwt/jwt_signature_public_key.h
1007 //third_party/tink/cc/jwt/jwt_signature_private_key.h
1008 //third_party/tink/cc/jwt/jwt_ecdsa_parameters.h
1009 //third_party/tink/cc/jwt/jwt_ecdsa_public_key.h
1010 //third_party/tink/cc/jwt/jwt_ecdsa_private_key.h
1011 //third_party/tink/cc/jwt/jwt_ml_dsa_parameters.h
1012 //third_party/tink/cc/jwt/jwt_ml_dsa_public_key.h
1013 //third_party/tink/cc/jwt/jwt_ml_dsa_private_key.h
1014 //third_party/tink/cc/jwt/jwt_rsa_ssa_pkcs1_parameters.h
1015 //third_party/tink/cc/jwt/jwt_rsa_ssa_pkcs1_public_key.h
1016 //third_party/tink/cc/jwt/jwt_rsa_ssa_pkcs1_private_key.h
1017 //third_party/tink/cc/jwt/jwt_rsa_ssa_pss_parameters.h
1018 //third_party/tink/cc/jwt/jwt_rsa_ssa_pss_public_key.h
1019 //third_party/tink/cc/jwt/jwt_rsa_ssa_pss_private_key.h
30001 //third_party/tink/cc/internal/util_test.cc
30002 //third_party/tink/cc/internal/util_test.cc
30003 //third_party/tink/cc/internal/util_test.cc
30004 //third_party/tink/cc/internal/util_test.cc
30005 //third_party/tink/cc/internal/util_test.cc
30006 //third_party/tink/cc/mac/aes_cmac_parameters_test.cc
30007 //third_party/tink/cc/mac/aes_cmac_key_test.cc
30008 //third_party/tink/cc/mac/hmac_parameters_test.cc
30009 //third_party/tink/cc/mac/hmac_key_test.cc
30010 //third_party/tink/cc/internal/serialization_test_util.h
30011 //third_party/tink/cc/internal/serialization_test_util.h
30012 //third_party/tink/cc/internal/serialization_test_util.h
30013 //third_party/tink/cc/internal/serialization_test_util.h
30014 //third_party/tink/cc/internal/serialization_test_util.h
30015 //third_party/tink/cc/internal/serialization_test_util.h
30016 //third_party/tink/cc/internal/serialization_test_util.h
30017 //third_party/tink/cc/internal/serialization_test_util.h
30018 //third_party/tink/cc/internal/parser_index_test.cc
30019 //third_party/tink/cc/internal/parser_index_test.cc
EOF
)"
readonly DEFAULT_EXPECTED_IDS

if (( $# < 1 || $# > 2 )) || [[ ! -d "$1" ]]; then
  echo "Usage: $0 <source_dir> [expected_ids_file]" >&2
  exit 1
fi
readonly TARGET_DIR="${1%/}"
if (( $# == 2 )); then
  EXPECTED_IDS="$(cat "$2")"
else
  EXPECTED_IDS="${DEFAULT_EXPECTED_IDS}"
fi
readonly EXPECTED_IDS

LINES="$(grep -rnE --include='*.h' --include='*.cc' \
  'TINK_INTERNAL_RTTI_(SET|COMPUTE)_TYPE_ID' "${TARGET_DIR}" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#define|")' || true)"
readonly LINES

if [[ -z "${LINES}" ]]; then
  if [[ -n "${EXPECTED_IDS}" ]]; then
    echo "ERROR: Found 0 RTTI type IDs, but expected:" >&2
    echo "${EXPECTED_IDS}" >&2
    exit 1
  fi
  echo "Checked 0 unique RTTI type ID(s)."
  exit 0
fi

VALID_RE='^[^:]+:[0-9]+:[[:space:]]*TINK_INTERNAL_RTTI_(SET|COMPUTE)_TYPE_ID'
VALID_RE+='\([1-9][0-9]*[),]'
readonly VALID_RE

BAD_LINES="$(echo "${LINES}" | grep -vE "${VALID_RE}" || true)"
if [[ -n "${BAD_LINES}" ]]; then
  echo "ERROR: Malformed/non-literal TINK_INTERNAL_RTTI_*_TYPE_ID line(s):" >&2
  echo "${BAD_LINES}" >&2
  exit 1
fi

IDS="$(echo "${LINES}" \
  | sed -E 's/.*TINK_INTERNAL_RTTI_(SET|COMPUTE)_TYPE_ID\(([0-9]+).*/\2/' \
  | sort -n)"
readonly IDS

MAX_ID="$(echo "${IDS}" | tail -n 1)"
if (( MAX_ID > 32767 )); then
  echo "ERROR: RTTI type IDs in Tink must be <= 32767 (got ${MAX_ID}):" >&2
  echo "${LINES}" \
    | grep -E "TINK_INTERNAL_RTTI_(SET|COMPUTE)_TYPE_ID\(${MAX_ID}[),]" >&2
  exit 1
fi

DUPS="$(echo "${IDS}" | uniq -d)"
if [[ -n "${DUPS}" ]]; then
  echo "ERROR: Duplicate RTTI type IDs found:" >&2
  for id in ${DUPS}; do
    echo "${LINES}" \
      | grep -E "TINK_INTERNAL_RTTI_(SET|COMPUTE)_TYPE_ID\(${id}[),]" >&2
  done
  exit 1
fi

ACTUAL_IDS="$(echo "${LINES}" \
  | sed -E "s#^${TARGET_DIR}/([^:]+):[0-9]+:.*TINK_INTERNAL_RTTI_(SET|COMPUTE)_TYPE_ID\(([0-9]+).*#\3 //third_party/tink/cc/\1#" \
  | LC_ALL=C sort -n -k1,1 -k2,2)"
readonly ACTUAL_IDS

if [[ "${ACTUAL_IDS}" != "${EXPECTED_IDS}" ]]; then
  echo "ERROR: Actual RTTI type IDs do not match expected list." >&2
  echo "Actual:" >&2
  echo "${ACTUAL_IDS}" >&2
  echo
  echo "Diff (-expected +actual):" >&2
  diff -u <(echo "${EXPECTED_IDS}") <(echo "${ACTUAL_IDS}") >&2
  exit 1
fi

echo "Checked $(echo "${IDS}" | wc -l | tr -d ' ') unique RTTI type ID(s)."
