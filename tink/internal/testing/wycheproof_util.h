// Copyright 2024 Google Inc.
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

#ifndef TINK_INTERNAL_TESTING_WYCHEPROOF_UTIL_H_
#define TINK_INTERNAL_TESTING_WYCHEPROOF_UTIL_H_

#include <string>

#include "google/protobuf/struct.pb.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace wycheproof_testing {

// Reads test vector from a file.
// The filename is relative to the directory with the test vectors.
util::StatusOr<google::protobuf::Struct> ReadTestVectors(
    const std::string &filename);

std::string GetBytesFromHexValue(const google::protobuf::Value &val);

// Integers in Wycheproof are represented as signed big-endian hexadecimal
// strings in two's complement representation.
// Integers in EcKey are unsigned and are represented as an array of bytes
// using big-endian order.
// GetIntegerFromHexValue can assume that val is always 0 or a positive integer,
// since they are values from the key: a convention in Wycheproof is that
// parameters in the test group are valid, only values in the test vector itself
// may be invalid.
std::string GetIntegerFromHexValue(const google::protobuf::Value &val);

crypto::tink::subtle::HashType GetHashTypeFromValue(
    const google::protobuf::Value &val);

crypto::tink::subtle::EllipticCurveType GetEllipticCurveTypeFromValue(
    const google::protobuf::Value &val);

}  // namespace wycheproof_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TESTING_WYCHEPROOF_UTIL_H_
