// Copyright 2024 Google LLC
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

#ifndef TINK_INTERNAL_TESTING_EC_TEST_VECTORS_H_
#define TINK_INTERNAL_TESTING_EC_TEST_VECTORS_H_

#include <string>

#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto::tink::internal {

// Returns P-256 public point from RFC 6979, Appendix A.2.5.
EcPoint P256Point();
std::string P256PointAsString();
// Returns P-256 private key from RFC 6979, Appendix A.2.5.
RestrictedData P256SecretValue();
// Returns P-384 public point from RFC 6979, Appendix A.2.6.
EcPoint P384Point();
std::string P384PointAsString();
// Returns P-384 private key from RFC 6979, Appendix A.2.6.
RestrictedData P384SecretValue();
// Returns P-521 public point from RFC 6979, Appendix A.2.7.
EcPoint P521Point();
std::string P521PointAsString();
// Returns P-521 private key from RFC 6979, Appendix A.2.7.
RestrictedData P521SecretValue();
// Returns X25519 public and private key from RFC 9180, Appendix A.3.1.
std::string X25519PublicValue();
RestrictedData X25519SecretValue();

// Returns a valid static EC key for the given curve type from RFC 6979.
const internal::EcKey& GetEcKey(subtle::EllipticCurveType curve_type);

}  // namespace crypto::tink::internal

#endif  // TINK_INTERNAL_TESTING_EC_TEST_VECTORS_H_
