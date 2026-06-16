// Copyright 2026 Google LLC
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

#ifndef TINK_JWT_INTERNAL_TESTING_JWT_RSA_SSA_TEST_VECTORS_H_
#define TINK_JWT_INTERNAL_TESTING_JWT_RSA_SSA_TEST_VECTORS_H_

#include <string>

namespace crypto {
namespace tink {
namespace jwt_internal {

struct RsaSsaTestVector {
  std::string n;
  std::string e;
  std::string d;
  std::string p;
  std::string q;
  std::string dp;
  std::string dq;
  std::string q_inv;
};

// Returns RSA key values from RFC 7517 Appendix C.1.
const RsaSsaTestVector& GetRsa2048BitVector1();

// Returns RSA key values from RFC 7515 Appendix A.2.
const RsaSsaTestVector& GetRsa2048BitVector2();

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_TESTING_JWT_RSA_SSA_TEST_VECTORS_H_
